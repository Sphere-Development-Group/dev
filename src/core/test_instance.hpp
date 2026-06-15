#pragma once

#include <atomic>
#include <cstdint>
#include <vector>

#include <rte_ether.h>

#include "metrics.hpp"
#include "tcp_stack.hpp"

// =====================================================================
// StreamConfig — runtime-конфигурация одного Stream (без protobuf).
// =====================================================================
struct StreamConfig {
  int32_t port_id;
  uint8_t port_mode;    // 0=INIT, 1=RESPOND, 2=BOTH
  uint16_t vlan;        // 0 = без тега
  uint16_t frame_size;  // байт (при FIX mode)
  uint8_t frame_mode;   // 0=FIX, 1=IMIX

  uint32_t src_ip_start;
  uint32_t src_ip_end;
  uint32_t net_mask;
  uint32_t gateway;
  uint32_t dst_ip_start;
  uint32_t dst_ip_end;

  uint8_t dscp;
  uint8_t protocol;  // 0=TCP, 1=UDP

  uint16_t src_port_start;
  uint16_t src_port_end;
  uint16_t dst_port_start;
  uint16_t dst_port_end;

  uint16_t tcp_initial_window;

  // Глобальный индекс внутри Test (для метрик и идентификации)
  uint32_t stream_index;
};

// =====================================================================
// StreamRuntimeState — изменяемый курсор генерации для одного stream.
// Живёт на lcore, пишется/читается только им же.
// =====================================================================
struct StreamRuntimeState {
  // Round-robin курсоры для INIT/BOTH (новые соединения)
  uint32_t cur_src_ip = 0;
  uint16_t cur_src_port = 0;
  uint32_t cur_dst_ip = 0;
  uint16_t cur_dst_port = 0;

  // IMIX round-robin
  uint8_t imix_idx = 0;

  // ARP-резолюция gateway
  bool gateway_resolved = false;
  uint8_t gateway_mac[RTE_ETHER_ADDR_LEN] = {0};

  // Счётчик открытых соединений на ЭТОМ lcore для этого stream
  // (чтобы не превышать пул TCB)
  uint64_t open_connections = 0;
};

// =====================================================================
// LcoreContext — всё, что нужно одному worker lcore.
// Создаётся в памяти NUMA-узла lcore ДО rte_eal_remote_launch,
// указатель передаётся как аргумент.
// =====================================================================
struct LcoreContext {
  uint16_t lcore_id;
  uint16_t port_id;
  uint16_t queue_id = 0;
  rte_ether_addr local_mac;  // MAC порта — заполняется в init

  TCP_Stack* tcp_stack{nullptr};  // создаётся внутри lcore-функции

  std::vector<StreamConfig> streams;
  std::vector<StreamRuntimeState> stream_state;

  // Метрики: массив по [streams.size()].
  // Публикуется lcore после аллокации через atomic store с release.
  StreamMetrics* metrics{nullptr};
  size_t metrics_count{0};

  // Управляющие флаги (пишет Manager, читает lcore каждую итерацию)
  std::atomic<bool> running{false};
  std::atomic<bool> shutdown_requested{false};
  std::atomic<bool> arp_ready{false};  // ARP-резолюция завершена

  std::atomic<int32_t> test_state{0};      // TestState из protobuf
  std::atomic<int32_t> rate_percent{100};  // % от линейной скорости
};

// =====================================================================
// TestInstance — сущность теста на стороне Manager.
// =====================================================================
struct TestInstance {
  uint32_t test_id{0};
  int32_t rate{100};
  int32_t state{0};
  size_t total_streams{0};

  std::vector<LcoreContext*> lcore_contexts;
};