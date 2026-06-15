#pragma once

#include <cstdint>
#include <cstring>

#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

#include "metrics.hpp"
#include "tcp_stack.hpp"  // for SessionKey

// =====================================================================
// UDP_Stack — stateless.
// generate_segment — формирует UDP-датаграмму (для INIT/BOTH).
// receive_segment  — обрабатывает входящую (для RESPOND/BOTH).
// =====================================================================
class UDP_Stack {
public:
    // ------------------------------------------------------------------
    // generate_segment — заполняет UDP-заголовок + payload в mbuf.
    // mbuf должен уже содержать L2/L3 (appended), здесь добавляем L4.
    // payload_len — сколько байт данных после UDP-заголовка.
    // ------------------------------------------------------------------
    static void generate_segment(rte_mbuf*        mbuf,
                                 const SessionKey* tx_key,
                                 uint16_t         payload_len) {
        auto* udp = reinterpret_cast<rte_udp_hdr*>(
            rte_pktmbuf_append(mbuf, sizeof(rte_udp_hdr)));

        udp->src_port   = rte_cpu_to_be_16(tx_key->src_port);
        udp->dst_port   = rte_cpu_to_be_16(tx_key->dst_port);
        udp->dgram_len  = rte_cpu_to_be_16(
                              static_cast<uint16_t>(sizeof(rte_udp_hdr) + payload_len));
        udp->dgram_cksum = 0;

        if (payload_len > 0) {
            auto* payload = reinterpret_cast<uint8_t*>(
                rte_pktmbuf_append(mbuf, payload_len));
            // Паттерн 0x00..0xFF для верификации на приёмнике
            for (uint16_t i = 0; i < payload_len; ++i)
                payload[i] = static_cast<uint8_t>(i & 0xFF);
        }

        mbuf->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM | RTE_MBUF_F_TX_IPV4;
        mbuf->l4_len    = sizeof(rte_udp_hdr);
    }

    // ------------------------------------------------------------------
    // receive_segment — обрабатывает входящую UDP датаграмму.
    // Возвращает true если tx_mbuf заполнен ответом.
    // should_respond=true для RESPOND/BOTH режима.
    // ------------------------------------------------------------------
    static bool receive_segment(const rte_udp_hdr* rx_udp,
                                const uint8_t*     rx_payload,
                                uint16_t           rx_payload_len,
                                const SessionKey*  tx_key,
                                bool               should_respond,
                                rte_mbuf*          tx_mbuf,
                                StreamMetrics&     sm) {
        uint16_t dgram_len = rte_be_to_cpu_16(rx_udp->dgram_len);

        sm.rx_packets.fetch_add(1, std::memory_order_relaxed);
        sm.rx_bytes  .fetch_add(dgram_len, std::memory_order_relaxed);

        if (!should_respond) return false;

        // Зеркальный ответ с той же полезной нагрузкой
        auto* udp_out = reinterpret_cast<rte_udp_hdr*>(
            rte_pktmbuf_append(tx_mbuf, sizeof(rte_udp_hdr)));

        udp_out->src_port    = rte_cpu_to_be_16(tx_key->src_port);
        udp_out->dst_port    = rte_cpu_to_be_16(tx_key->dst_port);
        udp_out->dgram_len   = rte_cpu_to_be_16(
            static_cast<uint16_t>(sizeof(rte_udp_hdr) + rx_payload_len));
        udp_out->dgram_cksum = 0;

        if (rx_payload_len > 0) {
            auto* out_payload = reinterpret_cast<uint8_t*>(
                rte_pktmbuf_append(tx_mbuf, rx_payload_len));
            rte_memcpy(out_payload, rx_payload, rx_payload_len);
        }

        tx_mbuf->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM | RTE_MBUF_F_TX_IPV4;
        tx_mbuf->l4_len    = sizeof(rte_udp_hdr);

        uint16_t out_len = rte_be_to_cpu_16(udp_out->dgram_len);
        sm.tx_packets.fetch_add(1, std::memory_order_relaxed);
        sm.tx_bytes  .fetch_add(out_len, std::memory_order_relaxed);

        return true;
    }
};