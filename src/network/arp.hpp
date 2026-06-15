#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>
#include <vector>

#include <rte_arp.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

// =====================================================================
// ArpEntry
// state: 0=empty, 1=pending, 2=resolved
// Таблица принадлежит одному lcore; state/mac читаются снаружи через
// atomic load (acquire), чтобы видеть обновлённый MAC после resolved.
// =====================================================================
enum ArpEntryState : uint8_t {
    ARP_EMPTY    = 0,
    ARP_PENDING  = 1,
    ARP_RESOLVED = 2,
};

struct ArpEntry {
    uint32_t           ip;              // host order
    std::atomic<uint8_t> state{ARP_EMPTY};
    uint8_t            mac[RTE_ETHER_ADDR_LEN];
    uint64_t           request_sent_tsc;
    uint32_t           retries;
};

// =====================================================================
// ArpTable — открытая хеш-таблица с линейным пробированием.
// Размер — степень двойки; управляется одним lcore.
// =====================================================================
class ArpTable {
private:
    ArpEntry* entries_  = nullptr;
    uint32_t  capacity_ = 0;

    static uint32_t hash_ip(uint32_t ip) {
        return ip * 2654435761u;
    }

public:
    bool init(uint32_t capacity_pow2, int socket_id) {
        capacity_ = capacity_pow2;
        entries_  = static_cast<ArpEntry*>(
            rte_zmalloc_socket("arp-table",
                               capacity_ * sizeof(ArpEntry),
                               RTE_CACHE_LINE_SIZE,
                               socket_id));
        return entries_ != nullptr;
    }

    // Найти или создать слот. nullptr → таблица полна.
    ArpEntry* find_or_create(uint32_t ip) {
        uint32_t mask = capacity_ - 1;
        uint32_t idx  = hash_ip(ip) & mask;
        for (uint32_t p = 0; p < capacity_; ++p) {
            ArpEntry& e  = entries_[idx];
            uint8_t   st = e.state.load(std::memory_order_relaxed);
            if (st == ARP_EMPTY) {
                e.ip      = ip;
                e.retries = 0;
                e.request_sent_tsc = 0;
                // state оставляем ARP_EMPTY — caller выставит PENDING
                return &e;
            }
            if (e.ip == ip) return &e;
            idx = (idx + 1) & mask;
        }
        return nullptr;
    }

    ArpEntry* find(uint32_t ip) {
        uint32_t mask = capacity_ - 1;
        uint32_t idx  = hash_ip(ip) & mask;
        for (uint32_t p = 0; p < capacity_; ++p) {
            ArpEntry& e  = entries_[idx];
            uint8_t   st = e.state.load(std::memory_order_relaxed);
            if (st == ARP_EMPTY) return nullptr;
            if (e.ip == ip) return &e;
            idx = (idx + 1) & mask;
        }
        return nullptr;
    }

    void destroy() {
        if (entries_) { rte_free(entries_); entries_ = nullptr; }
    }
};

// =====================================================================
// ArpManager — инкапсулирует responder + requester для одного lcore.
// =====================================================================
class ArpManager {
private:
    ArpTable       table_;
    rte_ether_addr local_mac_;
    uint16_t       port_id_  = 0;

    struct LocalIpRange { uint32_t start; uint32_t end; };
    std::vector<LocalIpRange> local_ranges_;

    // Retry: 100 тиков × 10ms = ~1s между попытками
    static constexpr uint64_t ARP_RETRY_TICKS = 100;
    static constexpr uint32_t ARP_MAX_RETRIES = 5;

public:
    bool init(uint16_t port_id,
              const rte_ether_addr& mac,
              uint32_t table_capacity_pow2,
              int socket_id) {
        port_id_   = port_id;
        local_mac_ = mac;
        return table_.init(table_capacity_pow2, socket_id);
    }

    void add_local_range(uint32_t ip_start, uint32_t ip_end) {
        local_ranges_.push_back({ip_start, ip_end});
    }

    bool is_local_ip(uint32_t ip) const {
        for (auto& r : local_ranges_)
            if (ip >= r.start && ip <= r.end) return true;
        return false;
    }

    // ------------------------------------------------------------------
    // handle_arp_packet — вызывается для фреймов с ether_type == ARP.
    // Возвращает true если tx_mbuf заполнен reply'ем (RESPOND case).
    // tx_mbuf должен быть пустым mbufs из pool.
    // ------------------------------------------------------------------
    bool handle_arp_packet(rte_mbuf* rx, rte_mbuf* tx_mbuf, uint64_t now_tsc) {
        auto* eth_in = rte_pktmbuf_mtod(rx, rte_ether_hdr*);

        // Поддерживаем VLAN (если тег присутствует)
        uint16_t ether_type = rte_be_to_cpu_16(eth_in->ether_type);
        size_t   arp_offset = sizeof(rte_ether_hdr);
        if (ether_type == RTE_ETHER_TYPE_VLAN) {
            auto* vlan = reinterpret_cast<rte_vlan_hdr*>(eth_in + 1);
            ether_type = rte_be_to_cpu_16(vlan->eth_proto);
            arp_offset += sizeof(rte_vlan_hdr);
        }
        if (ether_type != RTE_ETHER_TYPE_ARP)
            return false;

        auto* arp_in = reinterpret_cast<rte_arp_hdr*>(
            reinterpret_cast<uint8_t*>(eth_in) + arp_offset);

        uint16_t op  = rte_be_to_cpu_16(arp_in->arp_opcode);
        uint32_t spa = rte_be_to_cpu_32(arp_in->arp_data.arp_sip);
        uint32_t tpa = rte_be_to_cpu_32(arp_in->arp_data.arp_tip);

        if (op == RTE_ARP_OP_REQUEST) {
            if (!is_local_ip(tpa)) return false;
            build_arp_reply(arp_in, eth_in, tx_mbuf, tpa, spa);
            return true;
        }

        if (op == RTE_ARP_OP_REPLY) {
            // Обновляем таблицу
            ArpEntry* entry = table_.find(spa);
            if (!entry) {
                // Кто-то ответил, но мы не спрашивали — учим всё равно
                entry = table_.find_or_create(spa);
            }
            if (entry) {
                std::memcpy(entry->mac,
                            arp_in->arp_data.arp_sha.addr_bytes,
                            RTE_ETHER_ADDR_LEN);
                entry->state.store(ARP_RESOLVED, std::memory_order_release);
            }
        }
        return false;
    }

    // ------------------------------------------------------------------
    // request_resolve — инициирует ARP-запрос для target_ip.
    // tx_mbuf — пустой mbuf для ARP-request.
    // Возвращает nullptr при переполнении таблицы.
    // ------------------------------------------------------------------
    ArpEntry* request_resolve(uint32_t source_ip,
                              uint32_t target_ip,
                              rte_mbuf* tx_mbuf,
                              uint64_t  now_tsc) {
        ArpEntry* entry = table_.find_or_create(target_ip);
        if (!entry) return nullptr;

        uint8_t st = entry->state.load(std::memory_order_relaxed);
        if (st == ARP_RESOLVED) return entry;

        if (st == ARP_PENDING) {
            // Ещё рано для ретрая
            if ((now_tsc - entry->request_sent_tsc) < ARP_RETRY_TICKS)
                return entry;
            // Лимит исчерпан — возвращаем как "unresolved", caller решит
            if (entry->retries >= ARP_MAX_RETRIES)
                return entry;
        }

        build_arp_request(source_ip, target_ip, tx_mbuf);
        entry->state.store(ARP_PENDING, std::memory_order_relaxed);
        entry->request_sent_tsc = now_tsc;
        entry->retries++;
        return entry;
    }

    bool lookup_mac(uint32_t ip, uint8_t* out_mac) {
        ArpEntry* entry = table_.find(ip);
        if (!entry) return false;
        if (entry->state.load(std::memory_order_acquire) != ARP_RESOLVED)
            return false;
        std::memcpy(out_mac, entry->mac, RTE_ETHER_ADDR_LEN);
        return true;
    }

    ArpEntry* get_entry(uint32_t ip) { return table_.find(ip); }

    void destroy() { table_.destroy(); }

private:
    void build_arp_reply(const rte_arp_hdr*   arp_in,
                         const rte_ether_hdr* eth_in,
                         rte_mbuf*            tx,
                         uint32_t             my_ip,
                         uint32_t             their_ip) {
        auto* eth_out = reinterpret_cast<rte_ether_hdr*>(
            rte_pktmbuf_append(tx, sizeof(rte_ether_hdr)));
        auto* arp_out = reinterpret_cast<rte_arp_hdr*>(
            rte_pktmbuf_append(tx, sizeof(rte_arp_hdr)));

        rte_ether_addr_copy(&local_mac_,         &eth_out->src_addr);
        rte_ether_addr_copy(&eth_in->src_addr,   &eth_out->dst_addr);
        eth_out->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

        arp_out->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
        arp_out->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
        arp_out->arp_hlen     = RTE_ETHER_ADDR_LEN;
        arp_out->arp_plen     = sizeof(uint32_t);
        arp_out->arp_opcode   = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

        rte_ether_addr_copy(&local_mac_,            &arp_out->arp_data.arp_sha);
        arp_out->arp_data.arp_sip = rte_cpu_to_be_32(my_ip);
        rte_ether_addr_copy(&arp_in->arp_data.arp_sha, &arp_out->arp_data.arp_tha);
        arp_out->arp_data.arp_tip = rte_cpu_to_be_32(their_ip);
    }

    void build_arp_request(uint32_t  source_ip,
                           uint32_t  target_ip,
                           rte_mbuf* tx) {
        auto* eth_out = reinterpret_cast<rte_ether_hdr*>(
            rte_pktmbuf_append(tx, sizeof(rte_ether_hdr)));
        auto* arp_out = reinterpret_cast<rte_arp_hdr*>(
            rte_pktmbuf_append(tx, sizeof(rte_arp_hdr)));

        rte_ether_addr_copy(&local_mac_, &eth_out->src_addr);
        std::memset(&eth_out->dst_addr, 0xFF, RTE_ETHER_ADDR_LEN);
        eth_out->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

        arp_out->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
        arp_out->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
        arp_out->arp_hlen     = RTE_ETHER_ADDR_LEN;
        arp_out->arp_plen     = sizeof(uint32_t);
        arp_out->arp_opcode   = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);

        rte_ether_addr_copy(&local_mac_, &arp_out->arp_data.arp_sha);
        arp_out->arp_data.arp_sip = rte_cpu_to_be_32(source_ip);
        std::memset(&arp_out->arp_data.arp_tha, 0x00, RTE_ETHER_ADDR_LEN);
        arp_out->arp_data.arp_tip = rte_cpu_to_be_32(target_ip);
    }
};