#pragma once

#include <atomic>
#include <cstdint>
#include <rte_common.h>

// =====================================================================
// StreamMetrics — атомарные счётчики одного Stream на одном lcore.
// Выровнено по cache line чтобы избежать false sharing.
// Пишет только "свой" lcore (relaxed), читает collector (relaxed).
// На x86 relaxed store/load == обычная запись в память, что достаточно
// для eventual visibility в рамках 1-секундного тика коллектора.
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
    std::atomic<uint64_t> tcb_alloc_failed{0};
    std::atomic<uint64_t> rx_dropped{0};

    // Последнее измеренное RTT (наносекунды). Для INIT-потоков:
    // время от отправки SYN до получения SYN+ACK.
    std::atomic<uint64_t> last_rtt_ns{0};
};

// =====================================================================
// StreamMetricsSnapshot — снимок для отдачи по сети / логирования.
// Обычные uint64_t, заполняет collector-поток.
// =====================================================================
struct StreamMetricsSnapshot {
    uint32_t stream_index{0};

    uint64_t tx_packets{0};
    uint64_t tx_bytes{0};
    uint64_t rx_packets{0};
    uint64_t rx_bytes{0};

    uint64_t tcp_connections_opened{0};
    uint64_t tcp_connections_established{0};
    uint64_t tcp_connections_closed{0};
    uint64_t tcp_connections_reset{0};
    uint64_t tcp_retransmits{0};
    uint64_t tcb_alloc_failed{0};
    uint64_t rx_dropped{0};
    uint64_t last_rtt_ns{0};

    // Производные (pps / bps) — вычисляет collector между двумя снимками
    double tx_pps{0.0};
    double rx_pps{0.0};
    double tx_bps{0.0};
    double rx_bps{0.0};
};