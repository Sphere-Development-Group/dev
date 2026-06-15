#pragma once

#include <cstdint>
#include <vector>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "test_instance.hpp"
#include "tcp_stack.hpp"

// =====================================================================
// ParsedFrame - результат разбора входящего mbuf.
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

  SessionKey key{};       // в network byte order не нужен -
                           // заполняется в host order для SessionKey
  int32_t stream_idx = -1;
};

// =====================================================================
// parse_frame - базовый разбор L2/L3/L4. Не делает classify по stream -
// это отдельный шаг (classify_stream), т.к. требует доступа к
// конфигурации streams лcore.
// =====================================================================
inline ParsedFrame parse_frame(rte_mbuf* m) {
  ParsedFrame pf;

  if (unlikely(rte_pktmbuf_pkt_len(m) < sizeof(rte_ether_hdr)))
    return pf;

  pf.eth = rte_pktmbuf_mtod(m, rte_ether_hdr*);
  uint16_t ether_type = rte_be_to_cpu_16(pf.eth->ether_type);

  // VLAN unwrap (поддержка одного тега 802.1Q)
  size_t l2_len = sizeof(rte_ether_hdr);
  if (ether_type == RTE_ETHER_TYPE_VLAN) {
    rte_vlan_hdr* vlan =
        reinterpret_cast<rte_vlan_hdr*>(reinterpret_cast<uint8_t*>(pf.eth) +
                                         sizeof(rte_ether_hdr));
    ether_type = rte_be_to_cpu_16(vlan->eth_proto);
    l2_len += sizeof(rte_vlan_hdr);
  }

  if (ether_type == RTE_ETHER_TYPE_ARP) {
    pf.is_arp = true;
    return pf;
  }

  if (ether_type != RTE_ETHER_TYPE_IPV4)
    return pf;  // IPv6 / прочее - не поддерживается генератором

  pf.ip = reinterpret_cast<rte_ipv4_hdr*>(reinterpret_cast<uint8_t*>(pf.eth) +
                                           l2_len);
  uint8_t ip_hlen = (pf.ip->version_ihl & 0x0F) * 4;
  uint16_t total_len = rte_be_to_cpu_16(pf.ip->total_length);

  if (pf.ip->next_proto_id == IPPROTO_TCP) {
    pf.tcp = reinterpret_cast<rte_tcp_hdr*>(
        reinterpret_cast<uint8_t*>(pf.ip) + ip_hlen);
    uint8_t tcp_hlen = (pf.tcp->data_off >> 4) * 4;

    pf.payload_len =
        total_len - ip_hlen - tcp_hlen;  // может быть 0
    if (pf.payload_len > 0)
      pf.payload =
          reinterpret_cast<uint8_t*>(pf.tcp) + tcp_hlen;

    pf.is_ipv4_tcp = true;

    pf.key.src_ip = rte_be_to_cpu_32(pf.ip->dst_addr);  // dst для нас = src в SessionKey
    pf.key.dst_ip = rte_be_to_cpu_32(pf.ip->src_addr);
    pf.key.src_port = rte_be_to_cpu_16(pf.tcp->dst_port);
    pf.key.dst_port = rte_be_to_cpu_16(pf.tcp->src_port);

  } else if (pf.ip->next_proto_id == IPPROTO_UDP) {
    pf.udp = reinterpret_cast<rte_udp_hdr*>(
        reinterpret_cast<uint8_t*>(pf.ip) + ip_hlen);

    uint16_t udp_len = rte_be_to_cpu_16(pf.udp->dgram_len);
    pf.payload_len = udp_len > sizeof(rte_udp_hdr)
                         ? udp_len - sizeof(rte_udp_hdr)
                         : 0;
    if (pf.payload_len > 0)
      pf.payload = reinterpret_cast<uint8_t*>(pf.udp) + sizeof(rte_udp_hdr);

    pf.is_ipv4_udp = true;

    pf.key.src_ip = rte_be_to_cpu_32(pf.ip->dst_addr);
    pf.key.dst_ip = rte_be_to_cpu_32(pf.ip->src_addr);
    pf.key.src_port = rte_be_to_cpu_16(pf.udp->dst_port);
    pf.key.dst_port = rte_be_to_cpu_16(pf.udp->src_port);
  }

  return pf;
}

// =====================================================================
// classify_stream - находит индекс stream в ctx->streams, которому
// принадлежит фрейм, по диапазону destination-порта (тот порт, на
// который пришёл сегмент = наш слушающий/исходящий порт = key.src_port
// после инверсии в parse_frame).
//
// Возвращает -1 если не найден соответствующий stream (фрейм
// игнорируется / дропается).
// =====================================================================
inline int32_t classify_stream(const ParsedFrame& pf,
                                const std::vector<StreamConfig>& streams) {
  for (size_t i = 0; i < streams.size(); ++i) {
    const StreamConfig& s = streams[i];

    bool proto_match =
        (pf.is_ipv4_tcp && s.protocol == 0 /* TCP */) ||
        (pf.is_ipv4_udp && s.protocol == 1 /* UDP */);
    if (!proto_match)
      continue;

    // key.src_port - это наш локальный порт (после инверсии в parse_frame)
    if (pf.key.src_port < s.src_port_start || pf.key.src_port > s.src_port_end)
      continue;

    if (pf.key.src_ip < s.src_ip_start || pf.key.src_ip > s.src_ip_end)
      continue;

    return static_cast<int32_t>(i);
  }
  return -1;
}