#pragma once

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include "lcore_worker.hpp"
#include "metrics.hpp"
#include "test_instance.hpp"
#include "test.pb.h"  // сгенерированный protobuf (Test, Stream, ...)

// =====================================================================
// Manager - главный объект, живущий на main lcore.
//
// Обязанности:
//  1. UNIX socket server: принимает Test (protobuf), запускает/останавливает
//     тесты.
//  2. Раскладка streams по lcore (sharding), выделение LcoreContext
//     на NUMA каждого core, rte_eal_remote_launch.
//  3. Metrics collector thread: периодически читает StreamMetrics
//     каждого lcore (через указатели в LcoreContext), агрегирует,
//     считает производные метрики (pps/bps), складывает в snapshot,
//     доступный по запросу через тот же UNIX socket.
// =====================================================================
class Manager {
 private:
  std::string sock_path_;
  int listen_fd_ = -1;

  std::vector<uint32_t> worker_lcores_;  // доступные lcore (без main)

  std::mutex tests_mutex_;
  std::unordered_map<uint32_t, TestInstance> tests_;
  uint32_t next_test_id_ = 1;

  std::thread collector_thread_;
  std::atomic<bool> collector_running_{false};

  // Снимки метрик для отдачи наружу, защищены отдельным mutex,
  // т.к. читаются из socket-потока, пишутся из collector-потока.
  std::mutex snapshot_mutex_;
  std::unordered_map<uint32_t, std::vector<StreamMetricsSnapshot>> snapshots_;

  // Предыдущие значения счётчиков - для расчёта pps/bps между тиками
  struct PrevCounters {
    uint64_t tx_packets, rx_packets, tx_bytes, rx_bytes;
    std::chrono::steady_clock::time_point ts;
  };
  std::unordered_map<uint64_t, PrevCounters> prev_;  // key = (test_id<<32)|stream_idx

 public:
  explicit Manager(std::string sock_path) : sock_path_(std::move(sock_path)) {
    // worker_lcores_ заполняется из rte_lcore_*, исключая main
    unsigned lcore_id;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
      worker_lcores_.push_back(lcore_id);
    }
  }

  // -------------------------------------------------------------
  // UNIX socket setup
  // -------------------------------------------------------------
  bool init_socket() {
    listen_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd_ < 0)
      return false;

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock_path_.c_str(), sizeof(addr.sun_path) - 1);
    unlink(sock_path_.c_str());

    if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
      return false;
    if (listen(listen_fd_, 8) < 0)
      return false;

    return true;
  }

  // -------------------------------------------------------------
  // Основной цикл приёма команд (вызывается на main lcore)
  // -------------------------------------------------------------
  void run() {
    start_collector();

    while (true) {
      int client_fd = accept(listen_fd_, nullptr, nullptr);
      if (client_fd < 0)
        continue;

      handle_client(client_fd);
      close(client_fd);
    }
  }

  // -------------------------------------------------------------
  // Обработка одного подключения: читаем длину + protobuf Test,
  // создаём/запускаем тест.
  // -------------------------------------------------------------
  void handle_client(int fd) {
    uint32_t msg_len = 0;
    if (read(fd, &msg_len, sizeof(msg_len)) != sizeof(msg_len))
      return;

    std::vector<uint8_t> buf(msg_len);
    size_t total_read = 0;
    while (total_read < msg_len) {
      ssize_t r = read(fd, buf.data() + total_read, msg_len - total_read);
      if (r <= 0)
        return;
      total_read += r;
    }

    test_proto::Test test_msg;
    if (!test_msg.ParseFromArray(buf.data(), buf.size())) {
      RTE_LOG(ERR, USER1, "failed to parse Test protobuf\n");
      return;
    }

    create_and_start_test(test_msg);

    // Ответ клиенту (test_id) - формат ответа опущен для краткости
  }

  // -------------------------------------------------------------
  // Создание TestInstance: шардирование streams по lcore,
  // выделение LcoreContext на NUMA каждого lcore, запуск.
  // -------------------------------------------------------------
  uint32_t create_and_start_test(const test_proto::Test& test_msg) {
    std::lock_guard<std::mutex> lock(tests_mutex_);

    uint32_t test_id = next_test_id_++;
    TestInstance instance;
    instance.test_id = test_id;
    instance.rate = test_msg.rate();
    instance.state = test_msg.state();
    instance.total_streams = test_msg.stream_size();

    // ---- Шардирование: распределяем streams round-robin по lcore ----
    // Более продвинутый вариант - шардировать по диапазону IP/портов
    // внутри одного stream, если он один, но большой. Здесь - простой
    // RR на уровне streams.
    size_t n_lcores = worker_lcores_.size();
    if (n_lcores == 0) {
      RTE_LOG(ERR, USER1, "no worker lcores available\n");
      return 0;
    }

    std::vector<std::vector<StreamConfig>> per_lcore_streams(n_lcores);

    for (int i = 0; i < test_msg.stream_size(); ++i) {
      const auto& s = test_msg.stream(i);
      StreamConfig cfg = convert_stream(s, static_cast<uint32_t>(i));
      per_lcore_streams[i % n_lcores].push_back(cfg);
    }

    // ---- Для каждого lcore: выделяем LcoreContext на его NUMA,
    //      запускаем lcore_main ----
    for (size_t li = 0; li < n_lcores; ++li) {
      if (per_lcore_streams[li].empty())
        continue;

      uint32_t lcore_id = worker_lcores_[li];
      int socket_id = rte_lcore_to_socket_id(lcore_id);

      LcoreContext* ctx = static_cast<LcoreContext*>(
          rte_malloc_socket("lcore-ctx", sizeof(LcoreContext),
                            RTE_CACHE_LINE_SIZE, socket_id));
      if (ctx == nullptr) {
        RTE_LOG(ERR, USER1, "failed to alloc LcoreContext for lcore %u\n",
                lcore_id);
        continue;
      }
      new (ctx) LcoreContext();

      ctx->lcore_id = lcore_id;
      ctx->port_id = static_cast<uint16_t>(per_lcore_streams[li][0].port_id);
      ctx->streams = std::move(per_lcore_streams[li]);
      ctx->metrics = nullptr;       // публикуется самим lcore после alloc
      ctx->metrics_count = 0;
      ctx->running.store(true, std::memory_order_relaxed);
      ctx->shutdown_requested.store(false, std::memory_order_relaxed);
      ctx->test_state.store(test_msg.state(), std::memory_order_relaxed);

      instance.lcore_contexts.push_back(ctx);

      // Снимки метрик для этого lcore - резервируем место
      {
        std::lock_guard<std::mutex> snap_lock(snapshot_mutex_);
        auto& vec = snapshots_[test_id];
        vec.resize(vec.size() + ctx->streams.size());
      }

      rte_eal_remote_launch(lcore_main, ctx, lcore_id);
    }

    tests_.emplace(test_id, std::move(instance));
    return test_id;
  }

  // -------------------------------------------------------------
  // Конвертация Stream (protobuf) -> StreamConfig (runtime)
  // -------------------------------------------------------------
  static StreamConfig convert_stream(const test_proto::Stream& s,
                                      uint32_t stream_index) {
    StreamConfig cfg{};
    cfg.port_id = s.port_id();
    cfg.port_mode = static_cast<uint8_t>(s.port_mode());
    cfg.vlan = static_cast<uint16_t>(s.vlan());
    cfg.frame_size = static_cast<uint16_t>(s.frame_size());
    cfg.frame_mode = static_cast<uint8_t>(s.frame_mode());

    cfg.src_ip_start = ip_to_u32(s.source_ip_start());
    cfg.src_ip_end = ip_to_u32(s.source_ip_end());
    cfg.net_mask = ip_to_u32(s.network_mask());
    cfg.gateway = ip_to_u32(s.default_gateway());
    cfg.dst_ip_start = ip_to_u32(s.destination_ip_start());
    cfg.dst_ip_end = ip_to_u32(s.destination_ip_end());

    cfg.dscp = static_cast<uint8_t>(s.dscp());
    cfg.protocol = static_cast<uint8_t>(s.protocol());

    cfg.src_port_start = static_cast<uint16_t>(s.source_port().start());
    cfg.src_port_end = static_cast<uint16_t>(s.source_port().end());
    cfg.dst_port_start = static_cast<uint16_t>(s.destination_port().start());
    cfg.dst_port_end = static_cast<uint16_t>(s.destination_port().end());

    cfg.tcp_initial_window = static_cast<uint16_t>(s.tcp_initial_window_size());
    cfg.stream_index = stream_index;

    return cfg;
  }

  static uint32_t ip_to_u32(const test_proto::IPAddress& ip) {
    return (static_cast<uint32_t>(ip.octet1()) << 24) |
           (static_cast<uint32_t>(ip.octet2()) << 16) |
           (static_cast<uint32_t>(ip.octet3()) << 8) |
           static_cast<uint32_t>(ip.octet4());
  }

  // -------------------------------------------------------------
  // Остановка теста: сигнал shutdown всем lcore, rte_eal_wait_lcore,
  // освобождение памяти.
  // -------------------------------------------------------------
  void stop_test(uint32_t test_id) {
    std::lock_guard<std::mutex> lock(tests_mutex_);
    auto it = tests_.find(test_id);
    if (it == tests_.end())
      return;

    for (auto* ctx : it->second.lcore_contexts) {
      ctx->shutdown_requested.store(true, std::memory_order_relaxed);
    }
    for (auto* ctx : it->second.lcore_contexts) {
      rte_eal_wait_lcore(ctx->lcore_id);
      if (ctx->metrics != nullptr)
        rte_free(ctx->metrics);
      ctx->~LcoreContext();
      rte_free(ctx);
    }

    {
      std::lock_guard<std::mutex> snap_lock(snapshot_mutex_);
      snapshots_.erase(test_id);
    }

    tests_.erase(it);
  }

  // =================================================================
  // Metrics collector - отдельный std::thread (НЕ lcore, не нужен
  // dataplane-приоритет; main core может позволить себе обычный
  // pthread с периодическим sleep).
  //
  // Читает StreamMetrics через указатели в LcoreContext (acquire-load
  // указателя ctx->metrics, затем relaxed-load atomic-полей).
  // Промахи кэша на чтении из памяти других NUMA-узлов здесь
  // допустимы - это не datapath.
  // =================================================================
  void start_collector() {
    collector_running_.store(true);
    collector_thread_ = std::thread([this]() {
      while (collector_running_.load()) {
        collect_once();
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
    });
  }

  void stop_collector() {
    collector_running_.store(false);
    if (collector_thread_.joinable())
      collector_thread_.join();
  }

  void collect_once() {
    std::lock_guard<std::mutex> lock(tests_mutex_);
    auto now = std::chrono::steady_clock::now();

    for (auto& [test_id, instance] : tests_) {
      std::vector<StreamMetricsSnapshot> result;
      result.reserve(instance.total_streams);

      for (auto* ctx : instance.lcore_contexts) {
        // acquire-load: гарантирует, что если указатель не null,
        // то memset/конструкторы StreamMetrics на lcore уже видны
        StreamMetrics* metrics =
            __atomic_load_n(&ctx->metrics, __ATOMIC_ACQUIRE);
        if (metrics == nullptr)
          continue;  // lcore ещё не успел опубликовать метрики

        for (size_t i = 0; i < ctx->streams.size(); ++i) {
          StreamMetricsSnapshot snap{};
          const StreamMetrics& sm = metrics[i];

          snap.tx_packets = sm.tx_packets.load(std::memory_order_relaxed);
          snap.tx_bytes = sm.tx_bytes.load(std::memory_order_relaxed);
          snap.rx_packets = sm.rx_packets.load(std::memory_order_relaxed);
          snap.rx_bytes = sm.rx_bytes.load(std::memory_order_relaxed);

          snap.tcp_connections_opened =
              sm.tcp_connections_opened.load(std::memory_order_relaxed);
          snap.tcp_connections_established =
              sm.tcp_connections_established.load(std::memory_order_relaxed);
          snap.tcp_connections_closed =
              sm.tcp_connections_closed.load(std::memory_order_relaxed);
          snap.tcp_connections_reset =
              sm.tcp_connections_reset.load(std::memory_order_relaxed);
          snap.tcp_retransmits =
              sm.tcp_retransmits.load(std::memory_order_relaxed);

          snap.tcb_alloc_failed =
              sm.tcb_alloc_failed.load(std::memory_order_relaxed);
          snap.rx_dropped = sm.rx_dropped.load(std::memory_order_relaxed);
          snap.last_rtt_ns = sm.last_rtt_ns.load(std::memory_order_relaxed);

          // ---- производные метрики (pps/bps) ----
          uint64_t global_idx =
              (static_cast<uint64_t>(test_id) << 32) |
              ctx->streams[i].stream_index;

          auto pit = prev_.find(global_idx);
          if (pit != prev_.end()) {
            double dt = std::chrono::duration<double>(now - pit->second.ts).count();
            if (dt > 0) {
              snap.tx_pps = (snap.tx_packets - pit->second.tx_packets) / dt;
              snap.rx_pps = (snap.rx_packets - pit->second.rx_packets) / dt;
              snap.tx_bps = (snap.tx_bytes - pit->second.tx_bytes) * 8.0 / dt;
              snap.rx_bps = (snap.rx_bytes - pit->second.rx_bytes) * 8.0 / dt;
            }
          }

          prev_[global_idx] = {snap.tx_packets, snap.rx_packets,
                                snap.tx_bytes, snap.rx_bytes, now};

          result.push_back(snap);
        }
      }

      std::lock_guard<std::mutex> snap_lock(snapshot_mutex_);
      snapshots_[test_id] = std::move(result);
    }
  }

  // -------------------------------------------------------------
  // Получение снимка метрик для ответа по UNIX socket
  // -------------------------------------------------------------
  std::vector<StreamMetricsSnapshot> get_snapshot(uint32_t test_id) {
    std::lock_guard<std::mutex> lock(snapshot_mutex_);
    auto it = snapshots_.find(test_id);
    if (it == snapshots_.end())
      return {};
    return it->second;
  }

  ~Manager() {
    stop_collector();
    if (listen_fd_ >= 0)
      close(listen_fd_);
    unlink(sock_path_.c_str());
  }
};