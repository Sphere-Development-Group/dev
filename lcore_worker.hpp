#pragma once

#include <rte_branch_prediction.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include "test_instance.hpp"
#include "tcp_stack.hpp"

// Период тика timer wheel в TSC-циклах. Пример: 10ms.
static inline uint64_t timer_tick_interval_cycles() {
  return rte_get_tsc_hz() / 100;  // 10ms
}

// =====================================================================
// lcore_main - запускается через rte_eal_remote_launch(lcore_main, ctx, lcore_id)
//
// arg - указатель на LcoreContext*, уже размещённый в памяти NUMA-узла
// этого lcore (выделение происходит в манагере ДО запуска, см. manager.cpp)
// =====================================================================
static int lcore_main(void* arg) {
  LcoreContext* ctx = static_cast<LcoreContext*>(arg);
  uint16_t lcore_id = rte_lcore_id();

  // -------------------------------------------------------------
  // TCP_Stack создаётся ЗДЕСЬ, внутри потока lcore - его внутренние
  // структуры (mempool, hash table) будут на NUMA-узле этого core,
  // а не main. total_sessions берём по сумме TCB-лимитов streams,
  // назначенных этому lcore.
  // -------------------------------------------------------------
  uint64_t total_sessions = 0;
  for (auto& s : ctx->streams) {
    uint32_t ip_range =
        (s.src_ip_end - s.src_ip_start + 1);
    uint32_t port_range =
        (s.src_port_end - s.src_port_start + 1);
    total_sessions += static_cast<uint64_t>(ip_range) * port_range;
  }
  if (total_sessions == 0)
    total_sessions = 1;

  TCP_Stack stack(lcore_id, ctx->port_id, total_sessions);
  if (!stack.mempool_create() || !stack.create_hash_table()) {
    RTE_LOG(ERR, USER1, "lcore %u: failed to init TCP_Stack\n", lcore_id);
    return -1;
  }
  ctx->tcp_stack = &stack;

  // -------------------------------------------------------------
  // Метрики тоже выделяются здесь, на NUMA этого lcore.
  // ctx->metrics указатель публикуется ПОСЛЕ выделения - main
  // (collector) не должен читать его раньше времени, поэтому
  // публикация через atomic store с release.
  // -------------------------------------------------------------
  size_t n = ctx->streams.size();
  StreamMetrics* metrics = static_cast<StreamMetrics*>(
      rte_zmalloc_socket("lcore-metrics", n * sizeof(StreamMetrics),
                          RTE_CACHE_LINE_SIZE, rte_socket_id()));
  if (metrics == nullptr) {
    RTE_LOG(ERR, USER1, "lcore %u: failed to alloc metrics\n", lcore_id);
    return -1;
  }
  for (size_t i = 0; i < n; ++i) new (&metrics[i]) StreamMetrics();
  ctx->metrics_count = n;

  // Публикация указателя - release гарантирует, что collector,
  // прочитав не-null через acquire, увидит уже инициализированную память.
  __atomic_store_n(&ctx->metrics, metrics, __ATOMIC_RELEASE);

  RTE_LOG(INFO, USER1, "lcore %u started, %zu streams, %lu tcb slots\n",
          lcore_id, n, total_sessions);

  rte_mbuf* rx_burst[32];
  rte_mbuf* tx_burst[32];

  uint64_t next_timer_tick = rte_get_tsc_cycles() + timer_tick_interval_cycles();
  uint64_t tick_interval = timer_tick_interval_cycles();

  // -------------------------------------------------------------
  // Основной цикл
  // -------------------------------------------------------------
  while (likely(!ctx->shutdown_requested.load(std::memory_order_relaxed))) {
    if (unlikely(!ctx->running.load(std::memory_order_relaxed))) {
      // Тест на паузе/не стартован - не молотим впустую, но проверяем
      // флаг периодически. rte_pause снижает нагрузку на шину памяти
      // на HT-сосед.
      rte_pause();
      continue;
    }

    // ---- RX ----
    uint16_t nb_rx = rte_eth_rx_burst(ctx->port_id, 0, rx_burst, 32);

    for (uint16_t i = 0; i < nb_rx; ++i) {
      rte_mbuf* m = rx_burst[i];

      // Разбор L2/L3/L4, определение stream_index по конфигурации
      // (например по dst_port range -> индекс stream), формирование
      // SessionKey - детали парсинга опущены, это отдельный модуль.
      //
      // uint32_t stream_idx = classify_stream(m, ctx->streams);
      // SessionKey key = build_session_key(m);
      // rte_tcp_hdr* l4 = ...;
      //
      // rte_mbuf* tx_mbuf = rte_pktmbuf_alloc(...);
      // rte_mbuf* tpl_mbuf = nullptr; // или clone шаблона для ESTABLISHED
      // rte_mbuf* reply = nullptr;
      //
      // bool ok = stack.receiveMessage(&key, tx_mbuf, tpl_mbuf, l4, &reply);

      uint32_t stream_idx = 0;  // placeholder - результат classify_stream

      // ---- метрики rx, запись в "свою" память ----
      StreamMetrics& sm = metrics[stream_idx];
      sm.rx_packets.fetch_add(1, std::memory_order_relaxed);
      sm.rx_bytes.fetch_add(rte_pktmbuf_pkt_len(m), std::memory_order_relaxed);

      // if (!ok) {
      //   sm.rx_dropped.fetch_add(1, std::memory_order_relaxed);
      //   rte_pktmbuf_free(m);
      //   continue;
      // }

      // tx_burst[...] = reply; ... формирование burst на отправку

      rte_pktmbuf_free(m);
    }

    // ---- TX ----
    // uint16_t nb_tx = rte_eth_tx_burst(ctx->port_id, 0, tx_burst, nb_to_send);
    // for каждого отправленного - sm.tx_packets++, sm.tx_bytes += len

    // ---- Timer wheel tick ----
    uint64_t now = rte_get_tsc_cycles();
    if (unlikely(now >= next_timer_tick)) {
      stack.process_timers([&](TCB* tcb) {
        // retransmit callback: пересобрать последний сегмент и
        // отправить повторно. Здесь нужен доступ к stream_idx,
        // который должен храниться в самой TCB (расширить структуру
        // TCB полем stream_index при создании в receiveMessage).
        (void)tcb;
      });
      next_timer_tick = now + tick_interval;
    }
  }

  RTE_LOG(INFO, USER1, "lcore %u stopping\n", lcore_id);
  return 0;
}