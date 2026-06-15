#pragma once

#include <cstdint>

#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

#include "metrics.hpp"

#include "tcp_stack.hpp"

// =====================================================================
// UDP_Stack - stateless. Никаких таблиц сессий, никакого timer wheel.
//
// generate_segment - формирует UDP-заголовок + payload в новом mbuf
//                     (через append), используется для INIT/BOTH
//                     режимов (port_mode), когда генератор сам
//                     инициирует трафик.
//
// receive_segment  - обрабатывает входящий UDP-сегмент: для RESPOND/BOTH
//                     может сформировать ответ (зеркалирование payload
//                     либо отдельный сценарий), для чисто INIT - просто
//                     считает метрики и дропает.
// =====================================================================
class UDP_Stack {
 public:
  // -------------------------------------------------------------
  // generate_segment - формирует новый UDP-сегмент в tx_mbuf.
  //
  // is_new_mbuf: всегда true для stateless UDP (нет понятия
  // "шаблон с established", но параметр сохранён для единообразия
  // интерфейса с TCP_Stack::fillTcpSegment - на случай если в
  // будущем понадобится копирование шаблона payload по IMIX).
  //
  // payload_len - сколько байт payload добавить после заголовка
  // (заполняется нулями/паттерном - генератор payload не специфицирует
  // здесь, это делает caller через дополнительный append перед вызовом
  // либо передачей готового шаблона).
  // -------------------------------------------------------------
  static void generate_segment(rte_mbuf* mbuf,
                               const SessionKey* tx_key,
                               uint16_t payload_len) {
    rte_udp_hdr* udp = reinterpret_cast<rte_udp_hdr*>(
        rte_pktmbuf_append(mbuf, sizeof(rte_udp_hdr)));

    udp->src_port = rte_cpu_to_be_16(tx_key->src_port);
    udp->dst_port = rte_cpu_to_be_16(tx_key->dst_port);
    udp->dgram_len = rte_cpu_to_be_16(sizeof(rte_udp_hdr) + payload_len);
    udp->dgram_cksum = 0;

    if (payload_len > 0) {
      uint8_t* payload =
          reinterpret_cast<uint8_t*>(rte_pktmbuf_append(mbuf, payload_len));
      // Простой инкрементальный паттерн для возможности проверки
      // целостности на приёмнике (не обязателен, но полезен для теста).
      for (uint16_t i = 0; i < payload_len; ++i)
        payload[i] = static_cast<uint8_t>(i & 0xFF);
    }

    mbuf->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM | RTE_MBUF_F_TX_IPV4;
  }

  // -------------------------------------------------------------
  // receive_segment - обрабатывает входящий UDP datagram.
  // Возвращает true, если в tx_mbuf сформирован ответ (для RESPOND/
  // BOTH режима - зеркальный ответ с тем же payload).
  //
  // sm - метрики stream (запись только из своего lcore).
  // -------------------------------------------------------------
  static bool receive_segment(const rte_udp_hdr* rx_udp,
                              const uint8_t* rx_payload,
                              uint16_t rx_payload_len,
                              const SessionKey* tx_key,
                              bool should_respond,
                              rte_mbuf* tx_mbuf,
                              StreamMetrics& sm) {
    sm.rx_packets.fetch_add(1, std::memory_order_relaxed);
    sm.rx_bytes.fetch_add(rte_be_to_cpu_16(rx_udp->dgram_len),
                          std::memory_order_relaxed);

    if (!should_respond)
      return false;

    rte_udp_hdr* udp_out = reinterpret_cast<rte_udp_hdr*>(
        rte_pktmbuf_append(tx_mbuf, sizeof(rte_udp_hdr)));

    udp_out->src_port = rte_cpu_to_be_16(tx_key->src_port);
    udp_out->dst_port = rte_cpu_to_be_16(tx_key->dst_port);
    udp_out->dgram_len = rte_cpu_to_be_16(sizeof(rte_udp_hdr) + rx_payload_len);
    udp_out->dgram_cksum = 0;

    if (rx_payload_len > 0) {
      uint8_t* payload = reinterpret_cast<uint8_t*>(
          rte_pktmbuf_append(tx_mbuf, rx_payload_len));
      rte_memcpy(payload, rx_payload, rx_payload_len);
    }

    tx_mbuf->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM | RTE_MBUF_F_TX_IPV4;

    sm.tx_packets.fetch_add(1, std::memory_order_relaxed);
    sm.tx_bytes.fetch_add(rte_be_to_cpu_16(udp_out->dgram_len),
                          std::memory_order_relaxed);

    return true;
  }
};