#pragma once

#include <rte_branch_prediction.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "arp.hpp"
#include "frame_parser.hpp"
#include "imix.hpp"
#include "metrics.hpp"
#include "tcp_stack.hpp"
#include "test_instance.hpp"
#include "udp_stack.hpp"

// =====================================================================
// Константы datapath
// =====================================================================
static constexpr uint16_t RX_BURST = 32;
static constexpr uint16_t TX_BURST = 32;
static constexpr uint16_t MBUF_CACHE = 512;
static constexpr uint32_t MBUF_POOL_SZ = 65535;  // per lcore
static constexpr uint16_t MBUF_DATA_SZ = RTE_MBUF_DEFAULT_BUF_SIZE;

// Тик timer wheel = ~10ms
static inline uint64_t timer_tick_cycles() {
  return rte_get_tsc_hz() / 100;
}

// =====================================================================
// Вспомогательная функция: следующая пара (src_ip, src_port, dst_ip)
// для INIT/BOTH round-robin по диапазонам конфига.
// =====================================================================
static inline void advance_init_cursor(const StreamConfig& cfg,
                                       StreamRuntimeState& rs) {
  // Инкрементируем src_port, затем src_ip, затем dst_ip
  rs.cur_src_port++;
  if (rs.cur_src_port > cfg.src_port_end) {
    rs.cur_src_port = cfg.src_port_start;
    rs.cur_src_ip++;
    if (rs.cur_src_ip > cfg.src_ip_end) {
      rs.cur_src_ip = cfg.src_ip_start;
      rs.cur_dst_ip++;
      if (rs.cur_dst_ip > cfg.dst_ip_end)
        rs.cur_dst_ip = cfg.dst_ip_start;
    }
  }
}

// =====================================================================
// lcore_main — запускается через rte_eal_remote_launch(lcore_main, ctx, id)
// =====================================================================
static int lcore_main(void* arg) {
  LcoreContext* ctx = static_cast<LcoreContext*>(arg);
  uint16_t lcore = rte_lcore_id();
  uint16_t port_id = ctx->port_id;
  int socket = rte_socket_id();

  // ------------------------------------------------------------------
  // 1. Получаем MAC порта
  // ------------------------------------------------------------------
  rte_eth_macaddr_get(port_id, &ctx->local_mac);

  // ------------------------------------------------------------------
  // 2. Создаём mbuf pool для TX-буферов этого lcore
  // ------------------------------------------------------------------
  char pool_name[32];
  snprintf(pool_name, sizeof(pool_name), "mbuf-lcore-%u", lcore);
  rte_mempool* pool = rte_pktmbuf_pool_create(
      pool_name, MBUF_POOL_SZ, MBUF_CACHE, 0, MBUF_DATA_SZ, socket);

  if (unlikely(!pool)) {
    RTE_LOG(ERR, USER1, "lcore %u: failed to create mbuf pool\n", lcore);
    return -1;
  }

  // ------------------------------------------------------------------
  // 3. Создаём TCP_Stack (на NUMA этого lcore)
  // ------------------------------------------------------------------
  uint64_t total_sessions = 0;
  for (auto& s : ctx->streams) {
    uint64_t ips = (uint64_t)(s.src_ip_end - s.src_ip_start + 1);
    uint64_t ports = (uint64_t)(s.src_port_end - s.src_port_start + 1);
    total_sessions += ips * ports;
  }
  if (total_sessions == 0)
    total_sessions = 1024;

  TCP_Stack stack(lcore, port_id, total_sessions);
  if (!stack.mempool_create() || !stack.create_hash_table()) {
    RTE_LOG(ERR, USER1, "lcore %u: TCP_Stack init failed\n", lcore);
    rte_mempool_free(pool);
    return -1;
  }
  ctx->tcp_stack = &stack;

  // ------------------------------------------------------------------
  // 4. Создаём ARP-менеджер
  // ------------------------------------------------------------------
  ArpManager arp_mgr;
  // Размер таблицы: степень двойки >= кол-ва gateway + немного запаса
  uint32_t arp_cap = 256;  // достаточно для большинства конфигураций
  arp_mgr.init(port_id, ctx->local_mac, arp_cap, socket);

  // Регистрируем локальные IP-диапазоны (для ответа на ARP-запросы)
  for (auto& s : ctx->streams)
    arp_mgr.add_local_range(s.src_ip_start, s.src_ip_end);

  // ------------------------------------------------------------------
  // 5. Инициализируем runtime-состояние streams
  // ------------------------------------------------------------------
  ctx->stream_state.resize(ctx->streams.size());
  for (size_t i = 0; i < ctx->streams.size(); ++i) {
    auto& rs = ctx->stream_state[i];
    auto& cfg = ctx->streams[i];
    rs.cur_src_ip = cfg.src_ip_start;
    rs.cur_src_port = cfg.src_port_start;
    rs.cur_dst_ip = cfg.dst_ip_start;
    rs.cur_dst_port = cfg.dst_port_start;
    rs.imix_idx = 0;
    rs.gateway_resolved = false;
    rs.open_connections = 0;
  }

  // ------------------------------------------------------------------
  // 6. Публикуем метрики
  // ------------------------------------------------------------------
  size_t n_streams = ctx->streams.size();
  StreamMetrics* metrics = static_cast<StreamMetrics*>(
      rte_zmalloc_socket("lcore-metrics", n_streams * sizeof(StreamMetrics),
                         RTE_CACHE_LINE_SIZE, socket));
  if (unlikely(!metrics)) {
    RTE_LOG(ERR, USER1, "lcore %u: metrics alloc failed\n", lcore);
    rte_mempool_free(pool);
    return -1;
  }
  for (size_t i = 0; i < n_streams; ++i)
    new (&metrics[i]) StreamMetrics();
  ctx->metrics_count = n_streams;
  __atomic_store_n(&ctx->metrics, metrics, __ATOMIC_RELEASE);

  RTE_LOG(INFO, USER1,
          "lcore %u started: port=%u, streams=%zu, tcb_slots=%lu\n", lcore,
          port_id, n_streams, total_sessions);

  // ------------------------------------------------------------------
  // 7. Фаза ARP resolution: запрашиваем MAC gateway для каждого stream
  // ------------------------------------------------------------------
  {
    uint64_t arp_deadline = rte_get_tsc_cycles() + rte_get_tsc_hz() * 5;  // 5s
    bool all_done = false;

    while (!all_done && rte_get_tsc_cycles() < arp_deadline &&
           !ctx->shutdown_requested.load(std::memory_order_relaxed)) {
      // RX: обрабатываем ARP-ответы
      rte_mbuf* rx_burst_arr[RX_BURST];
      uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, rx_burst_arr, RX_BURST);

      rte_mbuf* tx_burst_arr[TX_BURST];
      uint16_t nb_tx = 0;

      for (uint16_t i = 0; i < nb_rx; ++i) {
        rte_mbuf* m = rx_burst_arr[i];
        ParsedFrame pf = parse_frame(m);
        if (pf.is_arp) {
          rte_mbuf* arp_reply = rte_pktmbuf_alloc(pool);
          if (arp_reply &&
              arp_mgr.handle_arp_packet(m, arp_reply, rte_get_tsc_cycles())) {
            tx_burst_arr[nb_tx++] = arp_reply;
          } else if (arp_reply) {
            rte_pktmbuf_free(arp_reply);
          }
        }
        rte_pktmbuf_free(m);
      }

      // TX: ARP-replies
      if (nb_tx > 0) {
        uint16_t sent = rte_eth_tx_burst(port_id, 0, tx_burst_arr, nb_tx);
        for (uint16_t i = sent; i < nb_tx; ++i)
          rte_pktmbuf_free(tx_burst_arr[i]);
        nb_tx = 0;
      }

      // TX: ARP requests для gateway каждого stream
      uint64_t now = rte_get_tsc_cycles();
      all_done = true;

      for (size_t si = 0; si < ctx->streams.size(); ++si) {
        auto& cfg = ctx->streams[si];
        auto& rs = ctx->stream_state[si];

        if (rs.gateway_resolved)
          continue;

        // Проверяем — может уже ответили?
        if (arp_mgr.lookup_mac(cfg.gateway, rs.gateway_mac)) {
          rs.gateway_resolved = true;
          RTE_LOG(INFO, USER1, "lcore %u: stream %zu gateway %08x resolved\n",
                  lcore, si, cfg.gateway);
          continue;
        }

        all_done = false;

        // Отправляем ARP-request
        rte_mbuf* arp_req = rte_pktmbuf_alloc(pool);
        if (arp_req) {
          ArpEntry* e = arp_mgr.request_resolve(cfg.src_ip_start, cfg.gateway,
                                                arp_req, now);
          if (e && rte_pktmbuf_pkt_len(arp_req) > 0) {
            tx_burst_arr[nb_tx++] = arp_req;
          } else {
            rte_pktmbuf_free(arp_req);
          }
        }
      }

      if (nb_tx > 0) {
        uint16_t sent = rte_eth_tx_burst(port_id, 0, tx_burst_arr, nb_tx);
        for (uint16_t i = sent; i < nb_tx; ++i)
          rte_pktmbuf_free(tx_burst_arr[i]);
      }

      // Небольшая пауза чтобы не молотить шину
      rte_delay_ms(1);
    }

    if (!all_done) {
      RTE_LOG(WARNING, USER1,
              "lcore %u: ARP timeout, some gateways unresolved\n", lcore);
    }
    ctx->arp_ready.store(true, std::memory_order_release);
  }

  // ------------------------------------------------------------------
  // 8. Ждём пока Manager установит running = true
  // ------------------------------------------------------------------
  while (!ctx->running.load(std::memory_order_relaxed) &&
         !ctx->shutdown_requested.load(std::memory_order_relaxed)) {
    rte_pause();
  }

  // ------------------------------------------------------------------
  // 9. Основной datapath цикл
  // ------------------------------------------------------------------
  rte_mbuf* rx_arr[RX_BURST];
  rte_mbuf* tx_arr[TX_BURST];

  uint64_t next_timer_tick = rte_get_tsc_cycles() + timer_tick_cycles();
  uint64_t tick_interval = timer_tick_cycles();

  while (likely(!ctx->shutdown_requested.load(std::memory_order_relaxed))) {
    // ---- Pause / state check ----
    if (unlikely(!ctx->running.load(std::memory_order_relaxed))) {
      rte_pause();
      continue;
    }

    uint16_t nb_tx = 0;
    uint64_t now = rte_get_tsc_cycles();

    // ================================================================
    // RX path
    // ================================================================
    uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, rx_arr, RX_BURST);

    for (uint16_t i = 0; i < nb_rx; ++i) {
      rte_mbuf* m = rx_arr[i];
      ParsedFrame pf = parse_frame(m);

      // ---- ARP ----
      if (unlikely(pf.is_arp)) {
        rte_mbuf* reply = rte_pktmbuf_alloc(pool);
        if (reply && arp_mgr.handle_arp_packet(m, reply, now)) {
          tx_arr[nb_tx++] = reply;
        } else if (reply) {
          rte_pktmbuf_free(reply);
        }
        // Обновляем gateway_resolved для всех streams
        for (size_t si = 0; si < ctx->streams.size(); ++si) {
          auto& cfg = ctx->streams[si];
          auto& rs = ctx->stream_state[si];
          if (!rs.gateway_resolved &&
              arp_mgr.lookup_mac(cfg.gateway, rs.gateway_mac)) {
            rs.gateway_resolved = true;
          }
        }
        rte_pktmbuf_free(m);
        if (nb_tx >= TX_BURST) {
          rte_eth_tx_burst(port_id, 0, tx_arr, nb_tx);
          nb_tx = 0;
        }
        continue;
      }

      // ---- Классификация пакета по stream ----
      int32_t si = classify_stream(pf, ctx->streams);
      if (unlikely(si < 0)) {
        rte_pktmbuf_free(m);
        continue;
      }

      StreamMetrics& sm = metrics[si];
      const StreamConfig& cfg = ctx->streams[si];

      sm.rx_packets.fetch_add(1, std::memory_order_relaxed);
      sm.rx_bytes.fetch_add(rte_pktmbuf_pkt_len(m), std::memory_order_relaxed);

      // ---- TCP ----
      if (pf.is_ipv4_tcp) {
        // Только RESPOND и BOTH принимают входящие TCP
        if (cfg.port_mode == 0 /* INIT only */) {
          // В INIT-режиме мы инициаторы: входящий пакет —
          // ответ на наш SYN или данные. Передаём в TCP_Stack.
        }

        rte_mbuf* tx_mbuf = rte_pktmbuf_alloc(pool);
        if (unlikely(!tx_mbuf)) {
          sm.rx_dropped.fetch_add(1, std::memory_order_relaxed);
          rte_pktmbuf_free(m);
          continue;
        }

        rte_mbuf* reply = nullptr;
        bool ok = stack.receive_message(&pf.key, tx_mbuf, nullptr, pf.tcp,
                                        pf.payload_len, &reply, &sm,
                                        static_cast<uint32_t>(si), now);

        if (ok && reply) {
          // Добавляем L2/L3 к ответу (reply = tx_mbuf пустой или tpl)
          // Для ответов нам нужен gateway MAC
          auto& rs = ctx->stream_state[si];
          uint8_t* dst_mac_ptr = rs.gateway_resolved ? rs.gateway_mac : nullptr;

          if (likely(dst_mac_ptr)) {
            // Строим L2/L3 перед L4. Но reply уже содержит
            // TCP-заголовок, appended через fill_tcp_segment.
            // Нужно prepend L2/L3.
            // Используем цепочку: prepend новый mbuf с L2/L3,
            // chain с reply.
            rte_mbuf* hdr_mbuf = rte_pktmbuf_alloc(pool);
            if (likely(hdr_mbuf)) {
              uint16_t l4_payload = 0;  // ACK без данных
              build_l2l3(hdr_mbuf, dst_mac_ptr, ctx->local_mac, pf.key.src_ip,
                         pf.key.dst_ip, IPPROTO_TCP, cfg.dscp, cfg.vlan,
                         l4_payload);
              // chain: hdr → reply (TCP hdr)
              hdr_mbuf->next = reply;
              hdr_mbuf->nb_segs = 2;
              hdr_mbuf->pkt_len = hdr_mbuf->data_len + reply->data_len;

              sm.tx_packets.fetch_add(1, std::memory_order_relaxed);
              sm.tx_bytes.fetch_add(hdr_mbuf->pkt_len,
                                    std::memory_order_relaxed);
              tx_arr[nb_tx++] = hdr_mbuf;
            } else {
              rte_pktmbuf_free(reply);
            }
          } else {
            rte_pktmbuf_free(reply);
          }
        } else if (!ok) {
          rte_pktmbuf_free(tx_mbuf);
        }
        rte_pktmbuf_free(m);

        // ---- UDP ----
      } else if (pf.is_ipv4_udp) {
        bool should_respond =
            (cfg.port_mode == 1 /* RESPOND */ || cfg.port_mode == 2 /* BOTH */);

        rte_mbuf* tx_mbuf = rte_pktmbuf_alloc(pool);
        if (unlikely(!tx_mbuf)) {
          sm.rx_dropped.fetch_add(1, std::memory_order_relaxed);
          rte_pktmbuf_free(m);
          continue;
        }

        // SessionKey для ответа
        SessionKey tx_key = pf.key.reversed();

        bool ok =
            UDP_Stack::receive_segment(pf.udp, pf.payload, pf.payload_len,
                                       &tx_key, should_respond, tx_mbuf, sm);

        if (ok) {
          auto& rs = ctx->stream_state[si];
          if (rs.gateway_resolved) {
            rte_mbuf* hdr = rte_pktmbuf_alloc(pool);
            if (hdr) {
              build_l2l3(hdr, rs.gateway_mac, ctx->local_mac, pf.key.src_ip,
                         pf.key.dst_ip, IPPROTO_UDP, cfg.dscp, cfg.vlan,
                         pf.payload_len);
              hdr->next = tx_mbuf;
              hdr->nb_segs = 2;
              hdr->pkt_len = hdr->data_len + tx_mbuf->data_len;
              tx_arr[nb_tx++] = hdr;
            } else {
              rte_pktmbuf_free(tx_mbuf);
            }
          } else {
            rte_pktmbuf_free(tx_mbuf);
          }
        } else {
          rte_pktmbuf_free(tx_mbuf);
        }
        rte_pktmbuf_free(m);

      } else {
        rte_pktmbuf_free(m);
      }

      if (nb_tx >= TX_BURST) {
        uint16_t sent = rte_eth_tx_burst(port_id, 0, tx_arr, nb_tx);
        for (uint16_t k = sent; k < nb_tx; ++k)
          rte_pktmbuf_free(tx_arr[k]);
        nb_tx = 0;
      }
    }  // for nb_rx

    // ================================================================
    // TX generation path — INIT / BOTH
    // ================================================================
    int32_t rate = ctx->rate_percent.load(std::memory_order_relaxed);

    for (size_t si = 0; si < ctx->streams.size() && nb_tx < TX_BURST; ++si) {
      const StreamConfig& cfg = ctx->streams[si];
      StreamRuntimeState& rs = ctx->stream_state[si];
      StreamMetrics& sm = metrics[si];

      // Только INIT(0) и BOTH(2) генерируют трафик сами
      if (cfg.port_mode == 1 /* RESPOND */)
        continue;
      if (!rs.gateway_resolved)
        continue;

      // Простой rate limiter: пропускаем некоторые итерации
      // При rate=100 генерируем каждую итерацию,
      // при rate=50 — каждую вторую и т.д.
      // Используем TSC-дробление: генерируем, если
      // (now % 100) < rate.
      uint64_t phase = (now / tick_interval) % 100;
      if ((uint64_t)rate < 100 && phase >= (uint64_t)rate)
        continue;

      if (cfg.protocol == 0 /* TCP */) {
        // Открываем новое соединение (SYN)
        SessionKey key;
        key.src_ip = rs.cur_src_ip;
        key.src_port = rs.cur_src_port;
        key.dst_ip = rs.cur_dst_ip;
        key.dst_port = cfg.dst_port_start;

        // Проверяем: нет ли уже активного TCB с таким ключом
        if (!stack.lookup_tcb(&key)) {
          rte_mbuf* syn_l4 = rte_pktmbuf_alloc(pool);
          if (syn_l4) {
            TCB* tcb = stack.open_connection(&key, syn_l4,
                                             cfg.tcp_initial_window, &sm, now);

            if (tcb) {
              // Prepend L2/L3
              rte_mbuf* hdr = rte_pktmbuf_alloc(pool);
              if (hdr) {
                // Payload = 0 для SYN
                build_l2l3(hdr, rs.gateway_mac, ctx->local_mac, key.src_ip,
                           key.dst_ip, IPPROTO_TCP, cfg.dscp, cfg.vlan, 0);
                hdr->next = syn_l4;
                hdr->nb_segs = 2;
                hdr->pkt_len = hdr->data_len + syn_l4->data_len;
                tx_arr[nb_tx++] = hdr;

                sm.tx_packets.fetch_add(1, std::memory_order_relaxed);
                sm.tx_bytes.fetch_add(hdr->pkt_len, std::memory_order_relaxed);
              } else {
                rte_pktmbuf_free(syn_l4);
              }
            } else {
              rte_pktmbuf_free(syn_l4);
            }
          }
        }
        advance_init_cursor(cfg, rs);

      } else /* UDP */ {
        // Генерируем UDP датаграмму
        uint16_t frame_sz;
        if (cfg.frame_mode == 1 /* IMIX */)
          frame_sz = imix_frame_size(rs.imix_idx);
        else
          frame_sz = cfg.frame_size;

        bool has_vlan = (cfg.vlan != 0);
        uint16_t payload_len = udp_payload_from_frame(frame_sz, has_vlan);

        SessionKey key;
        key.src_ip = rs.cur_src_ip;
        key.src_port = rs.cur_src_port;
        key.dst_ip = rs.cur_dst_ip;
        key.dst_port = cfg.dst_port_start;

        rte_mbuf* hdr = rte_pktmbuf_alloc(pool);
        if (hdr) {
          build_l2l3(hdr, rs.gateway_mac, ctx->local_mac, key.src_ip,
                     key.dst_ip, IPPROTO_UDP, cfg.dscp, cfg.vlan, payload_len);

          rte_mbuf* udp_mbuf = rte_pktmbuf_alloc(pool);
          if (udp_mbuf) {
            UDP_Stack::generate_segment(udp_mbuf, &key, payload_len);
            hdr->next = udp_mbuf;
            hdr->nb_segs = 2;
            hdr->pkt_len = hdr->data_len + udp_mbuf->data_len;

            sm.tx_packets.fetch_add(1, std::memory_order_relaxed);
            sm.tx_bytes.fetch_add(hdr->pkt_len, std::memory_order_relaxed);
            tx_arr[nb_tx++] = hdr;
          } else {
            rte_pktmbuf_free(hdr);
          }
        }
        advance_init_cursor(cfg, rs);
      }

      if (nb_tx >= TX_BURST)
        break;
    }

    // ================================================================
    // Timer wheel tick
    // ================================================================
    if (unlikely(now >= next_timer_tick)) {
      stack.process_timers(metrics, [&](TCB* tcb) {
        // Ретрансмит: пересобираем последний сегмент
        size_t si = tcb->stream_index;
        if (si >= ctx->streams.size())
          return;

        const StreamConfig& cfg = ctx->streams[si];
        StreamRuntimeState& rs = ctx->stream_state[si];
        StreamMetrics& sm = metrics[si];

        if (!rs.gateway_resolved)
          return;

        rte_mbuf* ret_l4 = rte_pktmbuf_alloc(pool);
        if (!ret_l4)
          return;

        stack.fill_tcp_segment(tcb, true, ret_l4, &tcb->key,
                               tcb->last_tx_flags);

        rte_mbuf* hdr = rte_pktmbuf_alloc(pool);
        if (!hdr) {
          rte_pktmbuf_free(ret_l4);
          return;
        }

        build_l2l3(hdr, rs.gateway_mac, ctx->local_mac, tcb->key.src_ip,
                   tcb->key.dst_ip, IPPROTO_TCP, cfg.dscp, cfg.vlan, 0);

        hdr->next = ret_l4;
        hdr->nb_segs = 2;
        hdr->pkt_len = hdr->data_len + ret_l4->data_len;

        // Немедленная отправка (не ждём batch)
        if (rte_eth_tx_burst(port_id, 0, &hdr, 1) == 0) {
          rte_pktmbuf_free(hdr);
        }
        sm.tx_packets.fetch_add(1, std::memory_order_relaxed);
        sm.tx_bytes.fetch_add(hdr ? hdr->pkt_len : 0,
                              std::memory_order_relaxed);
      });
      next_timer_tick = now + tick_interval;
    }

    // ================================================================
    // TX burst flush
    // ================================================================
    if (nb_tx > 0) {
      uint16_t sent = rte_eth_tx_burst(port_id, 0, tx_arr, nb_tx);
      for (uint16_t k = sent; k < nb_tx; ++k)
        rte_pktmbuf_free(tx_arr[k]);
    }

  }  // main loop

  RTE_LOG(INFO, USER1, "lcore %u: shutting down\n", lcore);
  rte_mempool_free(pool);
  return 0;
}