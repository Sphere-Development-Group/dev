#pragma once

#include <atomic>
#include <cstdint>
#include <vector>

#include <rte_ether.h>

#include "metrics.hpp"
#include "tcp_stack.hpp"

// =====================================================================
// Конфигурация одного Stream после разворачивания protobuf -
// удобный для воркера формат (без protobuf-зависимостей в datapath).
// =====================================================================
struct StreamConfig {
  int32_t  port_id;
  uint8_t  port_mode;       // PortMode
  uint16_t vlan;
  uint16_t frame_size;
  uint8_t  frame_mode;      // FrameMode

  uint32_t src_ip_start;
  uint32_t src_ip_end;
  uint32_t net_mask;
  uint32_t gateway;
  uint32_t dst_ip_start;
  uint32_t dst_ip_end;

  uint8_t  dscp;
  uint8_t  protocol;        // Protocol

  uint16_t src_port_start;
  uint16_t src_port_end;
  uint16_t dst_port_start;
  uint16_t dst_port_end;

  uint16_t tcp_initial_window;

  // глобальный индекс stream в рамках Test (для метрик/идентификации)
  uint32_t stream_index;
};

// =====================================================================
// StreamRuntimeState - изменяемое состояние генерации для одного
// stream на конкретном lcore. Живёт в памяти lcore (часть
// LcoreContext), пишется/читается только этим lcore.
// =====================================================================
struct StreamRuntimeState {
  uint32_t imix_idx = 0;       // индекс в цикле IMIX (12 элементов)

  // "Курсор" round-robin для генерации новых соединений по диапазонам
  // src_ip / src_port / dst_ip / dst_port (port_mode INIT/BOTH).
  uint32_t cur_src_ip = 0;
  uint16_t cur_src_port = 0;
  uint32_t cur_dst_ip = 0;
  uint16_t cur_dst_port = 0;

  // ARP resolution: разрешён ли gateway/destination перед стартом.
  std::atomic<bool> gateway_resolved{false};
  uint8_t gateway_mac[RTE_ETHER_ADDR_LEN] = {0};
};

// =====================================================================
// LcoreContext - всё, что нужно одному lcore-воркеру.
// Создаётся и инициализируется ДО запуска lcore (rte_eal_remote_launch),
// указатель передаётся как аргумент launch-функции.
//
// Память выделяется на NUMA-узле, соответствующем lcore
// (rte_malloc с socket_id = rte_lcore_to_socket_id(lcore_id)).
// =====================================================================
struct LcoreContext {
  uint16_t lcore_id;
  uint16_t port_id;       // основной порт, на котором развёрнут стек

  TCP_Stack* tcp_stack;   // создаётся внутри lcore-функции на своём стеке/NUMA

  rte_ether_addr local_mac;  // MAC порта, заполняется при старте lcore

  // Streams, назначенные этому lcore (один Test может шардироваться
  // по нескольким lcore по диапазонам портов/IP)
  std::vector<StreamConfig> streams;

  // Runtime-состояние генерации, по одному на stream (тот же индекс,
  // что и в streams).
  std::vector<StreamRuntimeState> stream_state;

  // Массив метрик, ОДИН per stream_index в рамках теста.
  // Память выделяется здесь (на NUMA lcore), используется только этим
  // lcore для записи. Collector хранит копии указателей у себя.
  StreamMetrics* metrics;   // metrics[streams.size()]
  size_t metrics_count;

  // Флаг управления потоком (start/stop/pause), читается lcore каждую
  // итерацию основного цикла. atomic, пишет main/manager.
  std::atomic<bool> running{false};
  std::atomic<bool> shutdown_requested{false};

  // Флаг "ARP resolution выполнен для всех streams" - устанавливается
  // lcore после того, как все gateway_resolved == true (или по timeout).
  // running переводится в true только после arp_ready (см. lcore_main).
  std::atomic<bool> arp_ready{false};

  // Текущее "состояние теста" - проекция Test.state из protobuf,
  // нужно для динамического старт/стоп без пересоздания контекста.
  std::atomic<int32_t> test_state{0};
};

// =====================================================================
// TestInstance - сущность одного запущенного теста на стороне main.
// Хранит указатели на LcoreContext каждого задействованного lcore
// (но НЕ владеет метриками - только читает через указатели).
// =====================================================================
struct TestInstance {
  uint32_t test_id;

  // Конфигурация (копия из protobuf, разворачивается при создании)
  int32_t rate;
  int32_t state;

  // Lcore-и, на которых выполняется тест, и соответствующие контексты.
  // Контексты живут в памяти каждого lcore (выделены через rte_malloc
  // с socket_id того lcore), main хранит только указатели на них.
  std::vector<LcoreContext*> lcore_contexts;

  // Для удобства - суммарное число streams во всём тесте (для
  // построения общего отчёта)
  size_t total_streams;
};