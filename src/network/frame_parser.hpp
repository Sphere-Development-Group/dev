#pragma once

#include <cstdint>
#include <vector>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "tcp_stack.hpp"
#include "../core/test_instance.hpp"

// =====================================================================
// ParsedFrame — результат разбора входящего mbuf.
// Все указатели (eth/ip/tcp/udp) — внутрь оригинального mbuf,
// освобождать их отдельно НЕ нужно.
// =====================================================================
struct ParsedFrame {
  bool is_arp = false;
  bool is_ipv4_tcp = false;
  bool is_ipv4_udp = false;

  rte_ether_hdr* eth = nullptr;
  rte_ipv4_hdr* ip = nullptr;
  rte_tcp_hdr* tcp = nullptr;
  rte_udp_hdr* udp = nullptr;

  uint8_t* payload = nullptr;
  uint16_t payload_len = 0;

  // SessionKey уже в host order, с инверсией src/dst:
  //   key.src_ip/port = наш локальный адрес (то, куда пришло)
  //   key.dst_ip/port = адрес отправителя
  // Таким образом key совпадает с SessionKey открытого соединения.
  SessionKey key{};

  int32_t stream_idx = -1;  // заполняется в classify_stream()
};

// =====================================================================
// parse_frame — разбор L2/L3/L4 без классификации по stream.
// =====================================================================
inline ParsedFrame parse_frame(rte_mbuf* m) {
  ParsedFrame pf;
  uint32_t pkt_len = rte_pktmbuf_pkt_len(m);

  if (unlikely(pkt_len < sizeof(rte_ether_hdr)))
    return pf;

  pf.eth = rte_pktmbuf_mtod(m, rte_ether_hdr*);
  uint16_t ether_type = rte_be_to_cpu_16(pf.eth->ether_type);

  // Поддержка одного VLAN-тега 802.1Q
  size_t l2_len = sizeof(rte_ether_hdr);
  if (ether_type == RTE_ETHER_TYPE_VLAN) {
    if (unlikely(pkt_len < l2_len + sizeof(rte_vlan_hdr)))
      return pf;
    auto* vlan = reinterpret_cast<rte_vlan_hdr*>(
        reinterpret_cast<uint8_t*>(pf.eth) + sizeof(rte_ether_hdr));
    ether_type = rte_be_to_cpu_16(vlan->eth_proto);
    l2_len += sizeof(rte_vlan_hdr);
  }

  if (ether_type == RTE_ETHER_TYPE_ARP) {
    pf.is_arp = true;
    return pf;
  }

  if (ether_type != RTE_ETHER_TYPE_IPV4)
    return pf;

  if (unlikely(pkt_len < l2_len + sizeof(rte_ipv4_hdr)))
    return pf;

  pf.ip = reinterpret_cast<rte_ipv4_hdr*>(reinterpret_cast<uint8_t*>(pf.eth) +
                                          l2_len);

  uint8_t ip_hlen = (pf.ip->version_ihl & 0x0F) * 4;
  uint16_t total_len = rte_be_to_cpu_16(pf.ip->total_length);

  if (pf.ip->next_proto_id == IPPROTO_TCP) {
    if (unlikely(pkt_len < l2_len + ip_hlen + sizeof(rte_tcp_hdr)))
      return pf;

    pf.tcp = reinterpret_cast<rte_tcp_hdr*>(reinterpret_cast<uint8_t*>(pf.ip) +
                                            ip_hlen);

    uint8_t tcp_hlen = (pf.tcp->data_off >> 4) * 4;
    int32_t pl = static_cast<int32_t>(total_len) - ip_hlen - tcp_hlen;
    pf.payload_len = (pl > 0) ? static_cast<uint16_t>(pl) : 0;
    if (pf.payload_len > 0)
      pf.payload = reinterpret_cast<uint8_t*>(pf.tcp) + tcp_hlen;

    pf.is_ipv4_tcp = true;
    // Инвертируем src/dst: входящий dst = наш адрес = SessionKey.src
    pf.key.src_ip = rte_be_to_cpu_32(pf.ip->dst_addr);
    pf.key.dst_ip = rte_be_to_cpu_32(pf.ip->src_addr);
    pf.key.src_port = rte_be_to_cpu_16(pf.tcp->dst_port);
    pf.key.dst_port = rte_be_to_cpu_16(pf.tcp->src_port);

    // Сохраняем l2/l3 длины в mbuf для ol_flags TX
    m->l2_len = static_cast<uint64_t>(l2_len);
    m->l3_len = ip_hlen;

  } else if (pf.ip->next_proto_id == IPPROTO_UDP) {
    if (unlikely(pkt_len < l2_len + ip_hlen + sizeof(rte_udp_hdr)))
      return pf;

    pf.udp = reinterpret_cast<rte_udp_hdr*>(reinterpret_cast<uint8_t*>(pf.ip) +
                                            ip_hlen);

    uint16_t udp_len = rte_be_to_cpu_16(pf.udp->dgram_len);
    int32_t pl = static_cast<int32_t>(udp_len) - sizeof(rte_udp_hdr);
    pf.payload_len = (pl > 0) ? static_cast<uint16_t>(pl) : 0;
    if (pf.payload_len > 0)
      pf.payload = reinterpret_cast<uint8_t*>(pf.udp) + sizeof(rte_udp_hdr);

    pf.is_ipv4_udp = true;
    pf.key.src_ip = rte_be_to_cpu_32(pf.ip->dst_addr);
    pf.key.dst_ip = rte_be_to_cpu_32(pf.ip->src_addr);
    pf.key.src_port = rte_be_to_cpu_16(pf.udp->dst_port);
    pf.key.dst_port = rte_be_to_cpu_16(pf.udp->src_port);

    m->l2_len = static_cast<uint64_t>(l2_len);
    m->l3_len = ip_hlen;
  }

  return pf;
}

// =====================================================================
// classify_stream — находит индекс stream в списке по:
//   - протоколу (TCP/UDP)
//   - диапазону src_ip (наш локальный адрес)
//   - диапазону src_port (наш локальный порт)
//
// Для RESPOND/BOTH — входящий dst совпадает с нашим src диапазоном.
// Возвращает -1 если stream не найден.
// =====================================================================
inline int32_t classify_stream(const ParsedFrame& pf,
                               const std::vector<StreamConfig>& streams) {
  for (size_t i = 0; i < streams.size(); ++i) {
    const StreamConfig& s = streams[i];

    // Проверяем протокол
    bool proto_ok = (pf.is_ipv4_tcp && s.protocol == 0) ||
                    (pf.is_ipv4_udp && s.protocol == 1);
    if (!proto_ok)
      continue;

    // key.src_ip/port = наш локальный адрес (инверсия из parse_frame)
    if (pf.key.src_ip < s.src_ip_start || pf.key.src_ip > s.src_ip_end)
      continue;
    if (pf.key.src_port < s.src_port_start || pf.key.src_port > s.src_port_end)
      continue;

    return static_cast<int32_t>(i);
  }
  return -1;
}

// =====================================================================
// build_l2l3 — заполняет Ethernet + IPv4 заголовки в пустой mbuf.
// Используется при генерации исходящих пакетов (INIT/BOTH).
//
// dst_mac    — MAC назначения (из ARP-таблицы)
// src_mac    — наш MAC
// src_ip/dst_ip — в host order
// protocol   — IPPROTO_TCP или IPPROTO_UDP
// dscp       — DSCP (6 бит)
// vlan       — 0 = без тега, иначе VLAN ID
// payload_len — размер L4 + данных (для total_length)
// =====================================================================
inline void build_l2l3(rte_mbuf* mbuf,
                       const uint8_t* dst_mac,
                       const rte_ether_addr& src_mac,
                       uint32_t src_ip,
                       uint32_t dst_ip,
                       uint8_t protocol,
                       uint8_t dscp,
                       uint16_t vlan,
                       uint16_t l4_payload_len) {
  size_t l2_len = sizeof(rte_ether_hdr);

  auto* eth = reinterpret_cast<rte_ether_hdr*>(
      rte_pktmbuf_append(mbuf, sizeof(rte_ether_hdr)));
  rte_ether_addr_copy(&src_mac, &eth->src_addr);
  memcpy(&eth->dst_addr, dst_mac, RTE_ETHER_ADDR_LEN);

  if (vlan) {
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
    auto* vtag = reinterpret_cast<rte_vlan_hdr*>(
        rte_pktmbuf_append(mbuf, sizeof(rte_vlan_hdr)));
    vtag->vlan_tci = rte_cpu_to_be_16(vlan & 0x0FFF);
    vtag->eth_proto = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    l2_len += sizeof(rte_vlan_hdr);
  } else {
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
  }

  auto* ip = reinterpret_cast<rte_ipv4_hdr*>(
      rte_pktmbuf_append(mbuf, sizeof(rte_ipv4_hdr)));

  uint16_t l4_hdr_len = (protocol == IPPROTO_TCP)
                            ? static_cast<uint16_t>(sizeof(rte_tcp_hdr))
                            : static_cast<uint16_t>(sizeof(rte_udp_hdr));
  uint16_t total_len = sizeof(rte_ipv4_hdr) + l4_hdr_len + l4_payload_len;

  ip->version_ihl = 0x45;
  ip->type_of_service = static_cast<uint8_t>(dscp << 2);
  ip->total_length = rte_cpu_to_be_16(total_len);
  ip->packet_id = 0;
  ip->fragment_offset = 0;
  ip->time_to_live = 64;
  ip->next_proto_id = protocol;
  ip->hdr_checksum = 0;
  ip->src_addr = rte_cpu_to_be_32(src_ip);
  ip->dst_addr = rte_cpu_to_be_32(dst_ip);

  mbuf->l2_len = static_cast<uint64_t>(l2_len);
  mbuf->l3_len = sizeof(rte_ipv4_hdr);
  mbuf->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
}