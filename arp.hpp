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
// ArpEntry - одна запись ARP-таблицы.
// state: 0 = empty, 1 = pending (запрос отправлен, ждём ответ),
//        2 = resolved.
// Таблица читается/пишется ТОЛЬКО своим lcore в datapath -
// никакой синхронизации не требуется для собственных операций.
// Доступ снаружи (например main при сборе ArpResolveResponse)
// идёт через atomic load полей state/mac.
// =====================================================================
struct ArpEntry {
  uint32_t ip;  // host order
  std::atomic<uint8_t> state{0};
  uint8_t mac[RTE_ETHER_ADDR_LEN];
  uint64_t request_sent_tsc;  // когда был отправлен последний запрос
  uint32_t retries;
};

enum ArpEntryState : uint8_t {
  ARP_EMPTY = 0,
  ARP_PENDING = 1,
  ARP_RESOLVED = 2,
};

// =====================================================================
// ArpTable - простая открытая хеш-таблица фиксированного размера
// (linear probing), под управлением одного lcore.
// Размер задаётся при создании = max количество уникальных gateway/
// destination IP, которые этому lcore может потребоваться резолвить
// (обычно мало - десятки/сотни записей, можно сделать фиксированным).
// =====================================================================
class ArpTable {
 private:
  ArpEntry* entries_;
  uint32_t capacity_;  // степень двойки

  static uint32_t hash_ip(uint32_t ip) {
    // простой Fibonacci hashing
    return (ip * 2654435761u);
  }

 public:
  bool init(uint32_t capacity_pow2, int socket_id) {
    capacity_ = capacity_pow2;
    entries_ = static_cast<ArpEntry*>(
        rte_zmalloc_socket("arp-table", capacity_ * sizeof(ArpEntry),
                           RTE_CACHE_LINE_SIZE, socket_id));
    return entries_ != nullptr;
  }

  // Найти или создать слот для ip. Возвращает nullptr если таблица полна.
  ArpEntry* find_or_create(uint32_t ip) {
    uint32_t mask = capacity_ - 1;
    uint32_t idx = hash_ip(ip) & mask;

    for (uint32_t probe = 0; probe < capacity_; ++probe) {
      ArpEntry& e = entries_[idx];
      uint8_t st = e.state.load(std::memory_order_relaxed);

      if (st == ARP_EMPTY) {
        e.ip = ip;
        return &e;
      }
      if (e.ip == ip)
        return &e;

      idx = (idx + 1) & mask;
    }
    return nullptr;  // таблица переполнена
  }

  // Только поиск (не создаёт). Используется responder-ом для
  // проверки "не наш ли это ответ" и main при сборе ArpResolveResponse.
  ArpEntry* find(uint32_t ip) {
    uint32_t mask = capacity_ - 1;
    uint32_t idx = hash_ip(ip) & mask;

    for (uint32_t probe = 0; probe < capacity_; ++probe) {
      ArpEntry& e = entries_[idx];
      uint8_t st = e.state.load(std::memory_order_relaxed);
      if (st == ARP_EMPTY)
        return nullptr;
      if (e.ip == ip)
        return &e;
      idx = (idx + 1) & mask;
    }
    return nullptr;
  }

  void destroy() {
    if (entries_ != nullptr)
      rte_free(entries_);
  }
};

// =====================================================================
// ArpManager - инкапсулирует responder + requester логику для одного
// lcore. Содержит ArpTable, собственный MAC и IP-список (для каких IP
// этот lcore отвечает на ARP-запросы - source_ip range streams).
// =====================================================================
class ArpManager {
 private:
  ArpTable table_;
  rte_ether_addr local_mac_;
  uint16_t port_id_;

  // Локальные IP, на которые этот lcore должен отвечать ARP-replies.
  // Заполняется при инициализации из StreamConfig (source_ip range).
  // Для простоты - диапазон [start, end], проверка через сравнение.
  struct LocalIpRange {
    uint32_t start;
    uint32_t end;
  };
  std::vector<LocalIpRange> local_ranges_;

  static constexpr uint64_t ARP_RETRY_TICKS = 100;  // ~1s при тике 10ms
  static constexpr uint32_t ARP_MAX_RETRIES = 3;

 public:
  bool init(uint16_t port_id,
            const rte_ether_addr& mac,
            uint32_t table_capacity_pow2,
            int socket_id) {
    port_id_ = port_id;
    local_mac_ = mac;
    return table_.init(table_capacity_pow2, socket_id);
  }

  void add_local_range(uint32_t ip_start, uint32_t ip_end) {
    local_ranges_.push_back({ip_start, ip_end});
  }

  bool is_local_ip(uint32_t ip) const {
    for (auto& r : local_ranges_) {
      if (ip >= r.start && ip <= r.end)
        return true;
    }
    return false;
  }

  // -----------------------------------------------------------------
  // handle_arp_packet - вызывается из основного rx-цикла lcore для
  // фреймов с ether_type == ARP.
  //
  // Возвращает true, если в tx_mbuf сформирован ARP-reply (responder
  // case), false если пакет был ARP-reply на наш запрос (обработан,
  // таблица обновлена) или невалидный ARP - в обоих случаях tx не нужен.
  // -----------------------------------------------------------------
  bool handle_arp_packet(rte_mbuf* rx, rte_mbuf* tx_mbuf) {
    rte_ether_hdr* eth_in = rte_pktmbuf_mtod(rx, rte_ether_hdr*);
    rte_arp_hdr* arp_in = reinterpret_cast<rte_arp_hdr*>(eth_in + 1);

    uint16_t op = rte_be_to_cpu_16(arp_in->arp_opcode);
    uint32_t spa = rte_be_to_cpu_32(arp_in->arp_data.arp_sip);
    uint32_t tpa = rte_be_to_cpu_32(arp_in->arp_data.arp_tip);

    if (op == RTE_ARP_OP_REQUEST) {
      // ---- Responder: отвечаем, если tpa - один из наших IP ----
      if (!is_local_ip(tpa))
        return false;

      build_arp_reply(arp_in, eth_in, tx_mbuf, tpa, spa);
      return true;
    }

    if (op == RTE_ARP_OP_REPLY) {
      // ---- Requester: обновляем таблицу по ответу ----
      ArpEntry* entry = table_.find(spa);
      if (entry == nullptr)
        return false;  // ответ не на наш запрос (или таблица не заполнена)

      std::memcpy(entry->mac, arp_in->arp_data.arp_sha.addr_bytes,
                  RTE_ETHER_ADDR_LEN);
      entry->state.store(ARP_RESOLVED, std::memory_order_release);
      return false;
    }

    return false;
  }

  // -----------------------------------------------------------------
  // build_arp_reply - формирует ARP-reply в tx_mbuf (новый, через append)
  // -----------------------------------------------------------------
  void build_arp_reply(const rte_arp_hdr* arp_in,
                       const rte_ether_hdr* eth_in,
                       rte_mbuf* tx_mbuf,
                       uint32_t my_ip,
                       uint32_t their_ip) {
    rte_ether_hdr* eth_out = reinterpret_cast<rte_ether_hdr*>(
        rte_pktmbuf_append(tx_mbuf, sizeof(rte_ether_hdr)));
    rte_arp_hdr* arp_out = reinterpret_cast<rte_arp_hdr*>(
        rte_pktmbuf_append(tx_mbuf, sizeof(rte_arp_hdr)));

    // ETH
    rte_ether_addr_copy(&local_mac_, &eth_out->src_addr);
    rte_ether_addr_copy(&eth_in->src_addr, &eth_out->dst_addr);
    eth_out->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    // ARP
    arp_out->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp_out->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp_out->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp_out->arp_plen = sizeof(uint32_t);
    arp_out->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

    rte_ether_addr_copy(&local_mac_, &arp_out->arp_data.arp_sha);
    arp_out->arp_data.arp_sip = rte_cpu_to_be_32(my_ip);
    rte_ether_addr_copy(&arp_in->arp_data.arp_sha, &arp_out->arp_data.arp_tha);
    arp_out->arp_data.arp_tip = rte_cpu_to_be_32(their_ip);
  }

  // -----------------------------------------------------------------
  // request_resolve - инициирует резолв target_ip с source_ip.
  // Если запись уже resolved/pending - не дублирует запрос.
  // Возвращает указатель на ArpEntry для последующего polling.
  // -----------------------------------------------------------------
  ArpEntry* request_resolve(uint32_t source_ip,
                            uint32_t target_ip,
                            rte_mbuf* tx_mbuf,
                            uint64_t now_tsc) {
    ArpEntry* entry = table_.find_or_create(target_ip);
    if (entry == nullptr)
      return nullptr;  // таблица переполнена

    uint8_t st = entry->state.load(std::memory_order_relaxed);
    if (st == ARP_RESOLVED)
      return entry;

    if (st == ARP_PENDING &&
        (now_tsc - entry->request_sent_tsc) < ARP_RETRY_TICKS)
      return entry;  // запрос уже в полёте, рано повторять

    if (st == ARP_PENDING && entry->retries >= ARP_MAX_RETRIES)
      return entry;  // лимит попыток, отдаём как unresolved

    // ---- Формируем ARP-request ----
    build_arp_request(source_ip, target_ip, tx_mbuf);

    entry->state.store(ARP_PENDING, std::memory_order_relaxed);
    entry->request_sent_tsc = now_tsc;
    entry->retries++;

    return entry;
  }

  void build_arp_request(uint32_t source_ip,
                         uint32_t target_ip,
                         rte_mbuf* tx_mbuf) {
    rte_ether_hdr* eth_out = reinterpret_cast<rte_ether_hdr*>(
        rte_pktmbuf_append(tx_mbuf, sizeof(rte_ether_hdr)));
    rte_arp_hdr* arp_out = reinterpret_cast<rte_arp_hdr*>(
        rte_pktmbuf_append(tx_mbuf, sizeof(rte_arp_hdr)));

    // ETH - broadcast
    rte_ether_addr_copy(&local_mac_, &eth_out->src_addr);
    std::memset(&eth_out->dst_addr, 0xFF, RTE_ETHER_ADDR_LEN);
    eth_out->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    // ARP
    arp_out->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp_out->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp_out->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp_out->arp_plen = sizeof(uint32_t);
    arp_out->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);

    rte_ether_addr_copy(&local_mac_, &arp_out->arp_data.arp_sha);
    arp_out->arp_data.arp_sip = rte_cpu_to_be_32(source_ip);
    std::memset(&arp_out->arp_data.arp_tha, 0x00, RTE_ETHER_ADDR_LEN);
    arp_out->arp_data.arp_tip = rte_cpu_to_be_32(target_ip);
  }

  // -----------------------------------------------------------------
  // lookup_mac - получить MAC для уже резолвленного IP.
  // Возвращает true и копирует mac, если есть resolved-запись.
  // -----------------------------------------------------------------
  bool lookup_mac(uint32_t ip, uint8_t* out_mac) {
    ArpEntry* entry = table_.find(ip);
    if (entry == nullptr)
      return false;
    if (entry->state.load(std::memory_order_acquire) != ARP_RESOLVED)
      return false;
    std::memcpy(out_mac, entry->mac, RTE_ETHER_ADDR_LEN);
    return true;
  }

  ArpEntry* get_entry(uint32_t ip) { return table_.find(ip); }

  void destroy() { table_.destroy(); }
};