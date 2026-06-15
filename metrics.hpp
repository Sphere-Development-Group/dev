#pragma once

#include <atomic>
#include <cstdint>
#include <rte_common.h>

// =====================================================================
// Метрики одного Stream на конкретном lcore.
// Выровнено по cache line, чтобы избежать false sharing между
// метриками соседних streams на одном lcore и между lcore.
//
// Поля - atomic с relaxed order: пишет только "свой" lcore,
// читает только collector. Это однонаправленный SPSC паттерн,
// полный memory order не нужен - нам достаточно гарантии видимости
// в разумные сроки (eventual visibility), что relaxed на x86
// обеспечивает де-факто как обычная запись + сериализация по тику.
// =====================================================================
struct __rte_cache_aligned StreamMetrics {
  std::atomic<uint64_t> tx_packets{0};
  std::atomic<uint64_t> tx_bytes{0};
  std::atomic<uint64_t> rx_packets{0};
  std::atomic<uint64_t> rx_bytes{0};

  std::atomic<uint64_t> tcp_connections_opened{0};
  std::atomic<uint64_t> tcp_connections_established{0};
  std::atomic<uint64_t> tcp_connections_closed{0};
  std::atomic<uint64_t> tcp_connections_reset{0};
  std::atomic<uint64_t> tcp_retransmits{0};

  std::atomic<uint64_t> tcb_alloc_failed{0};   // pool exhausted
  std::atomic<uint64_t> rx_dropped{0};         // дропы (no tcb, bad seq и т.п.)

  // RTT в наносекундах, скользящее значение последнего замера.
  // Для гистограммы/перцентилей нужна отдельная структура (см. ниже),
  // здесь только "последнее значение" для быстрого дешборда.
  std::atomic<uint64_t> last_rtt_ns{0};

  // padding до размера cache line делается автоматически благодаря
  // __rte_cache_aligned (выравнивание + паддинг компилятором структуры
  // целиком, см. rte_common.h: alignas(RTE_CACHE_LINE_SIZE))
};

// =====================================================================
// Снимок метрик для отдачи наружу (например, в gRPC/JSON ответ
// статистики теста). Обычные uint64_t, не atomic - заполняется
// collector-потоком после агрегации.
// =====================================================================
struct StreamMetricsSnapshot {
  uint64_t tx_packets;
  uint64_t tx_bytes;
  uint64_t rx_packets;
  uint64_t rx_bytes;

  uint64_t tcp_connections_opened;
  uint64_t tcp_connections_established;
  uint64_t tcp_connections_closed;
  uint64_t tcp_connections_reset;
  uint64_t tcp_retransmits;

  uint64_t tcb_alloc_failed;
  uint64_t rx_dropped;
  uint64_t last_rtt_ns;

  // производные поля, вычисляются collector-ом между двумя снимками
  double tx_pps;
  double rx_pps;
  double tx_bps;
  double rx_bps;
};