#pragma once

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include "../proto/protobuf.pb.h"
#include "lcore_worker.hpp"
#include "metrics.hpp"
#include "test_instance.hpp"

// =====================================================================
// Manager — главный управляющий объект на main lcore.
//
// Протокол UNIX socket: length-prefixed protobuf
//   Request:  [uint32_t len BE][Command proto]
//   Response: [uint32_t len BE][CommandResponse | StatsResponse |
//   TestListResponse]
//
// Все команды обрабатываются последовательно (один accept за раз).
// Для production рекомендуется использовать epoll + thread pool,
// но для тестера это излишне.
// =====================================================================
class Manager {
 private:
  std::string sock_path_;
  int listen_fd_ = -1;
  std::vector<uint32_t> worker_lcores_;

  std::mutex tests_mutex_;
  std::unordered_map<uint32_t, TestInstance> tests_;
  uint32_t next_test_id_ = 1;

  // Collector
  std::thread collector_thread_;
  std::atomic<bool> collector_running_{false};

  // Снимки метрик (пишет collector, читает socket-handler)
  std::mutex snapshot_mutex_;
  std::unordered_map<uint32_t, std::vector<StreamMetricsSnapshot>> snapshots_;

  struct PrevCounters {
    uint64_t tx_packets, rx_packets, tx_bytes, rx_bytes;
    std::chrono::steady_clock::time_point ts;
  };
  std::unordered_map<uint64_t, PrevCounters> prev_counters_;

 public:
  explicit Manager(std::string sock_path) : sock_path_(std::move(sock_path)) {
    unsigned id;
    RTE_LCORE_FOREACH_WORKER(id) {
      worker_lcores_.push_back(id);
    }
  }

  // ------------------------------------------------------------------
  // Инициализация UNIX socket
  // ------------------------------------------------------------------
  bool init_socket() {
    listen_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd_ < 0)
      return false;

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock_path_.c_str(), sizeof(addr.sun_path) - 1);
    ::unlink(sock_path_.c_str());

    if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
      return false;
    if (listen(listen_fd_, 16) < 0)
      return false;
    return true;
  }

  // ------------------------------------------------------------------
  // run() — основной цикл (main lcore)
  // ------------------------------------------------------------------
  void run() {
    start_collector();
    RTE_LOG(INFO, USER1, "Manager: listening on %s\n", sock_path_.c_str());

    while (true) {
      int client_fd = ::accept(listen_fd_, nullptr, nullptr);
      if (client_fd < 0) {
        if (errno == EINTR)
          continue;
        break;
      }
      handle_client(client_fd);
      ::close(client_fd);
    }
    stop_collector();
  }

  ~Manager() {
    stop_collector();
    if (listen_fd_ >= 0)
      ::close(listen_fd_);
    ::unlink(sock_path_.c_str());
  }

 private:
  // ------------------------------------------------------------------
  // Чтение/запись length-prefixed сообщений
  // ------------------------------------------------------------------
  static bool recv_msg(int fd, std::vector<uint8_t>& buf) {
    uint32_t len_be = 0;
    if (read_exact(fd, &len_be, 4) != 4)
      return false;
    uint32_t len = ntohl(len_be);
    if (len == 0 || len > 64 * 1024 * 1024)
      return false;
    buf.resize(len);
    return read_exact(fd, buf.data(), len) == static_cast<ssize_t>(len);
  }

  static bool send_msg(int fd, const std::string& data) {
    uint32_t len_be = htonl(static_cast<uint32_t>(data.size()));
    if (write(fd, &len_be, 4) != 4)
      return false;
    return write(fd, data.data(), data.size()) ==
           static_cast<ssize_t>(data.size());
  }

  static ssize_t read_exact(int fd, void* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
      ssize_t r = ::read(fd, static_cast<uint8_t*>(buf) + total, n - total);
      if (r <= 0)
        return r == 0 ? static_cast<ssize_t>(total) : -1;
      total += r;
    }
    return static_cast<ssize_t>(total);
  }

  // ------------------------------------------------------------------
  // handle_client — обработка одного подключения
  // ------------------------------------------------------------------
  void handle_client(int fd) {
    std::vector<uint8_t> buf;
    while (recv_msg(fd, buf)) {
      tester_proto::Command cmd;
      if (!cmd.ParseFromArray(buf.data(), static_cast<int>(buf.size()))) {
        send_error(fd, "failed to parse Command");
        continue;
      }

      switch (cmd.type()) {
        case tester_proto::CMD_START_TEST:
          handle_start_test(fd, cmd.test());
          break;
        case tester_proto::CMD_STOP_TEST:
          handle_stop_test(fd, cmd.test_id());
          break;
        case tester_proto::CMD_PAUSE_TEST:
          handle_pause_test(fd, cmd.test_id());
          break;
        case tester_proto::CMD_RESUME_TEST:
          handle_resume_test(fd, cmd.test_id());
          break;
        case tester_proto::CMD_GET_STATS:
          handle_get_stats(fd, cmd.test_id());
          break;
        case tester_proto::CMD_LIST_TESTS:
          handle_list_tests(fd);
          break;
        case tester_proto::CMD_SET_RATE:
          handle_set_rate(fd, cmd.set_rate());
          break;
        default:
          send_error(fd, "unknown command");
          break;
      }
    }
  }

  // ------------------------------------------------------------------
  // CMD_START_TEST
  // ------------------------------------------------------------------
  void handle_start_test(int fd, const tester_proto::Test& test_msg) {
    if (test_msg.stream_size() == 0) {
      send_error(fd, "test has no streams");
      return;
    }
    if (worker_lcores_.empty()) {
      send_error(fd, "no worker lcores available");
      return;
    }

    std::lock_guard<std::mutex> lock(tests_mutex_);
    uint32_t test_id = next_test_id_++;

    TestInstance inst;
    inst.test_id = test_id;
    inst.rate = test_msg.rate();
    inst.state = static_cast<int32_t>(test_msg.state());
    inst.total_streams = static_cast<size_t>(test_msg.stream_size());

    // ---- Шардирование streams round-robin по lcore ----
    size_t n_lc = worker_lcores_.size();
    std::vector<std::vector<StreamConfig>> per_lcore(n_lc);

    for (int i = 0; i < test_msg.stream_size(); ++i) {
      StreamConfig cfg =
          convert_stream(test_msg.stream(i), static_cast<uint32_t>(i));
      per_lcore[i % n_lc].push_back(cfg);
    }

    // ---- Запускаем каждый lcore ----
    for (size_t li = 0; li < n_lc; ++li) {
      if (per_lcore[li].empty())
        continue;

      uint32_t lc_id = worker_lcores_[li];
      int socket = rte_lcore_to_socket_id(lc_id);

      auto* ctx = static_cast<LcoreContext*>(rte_malloc_socket(
          "lcore-ctx", sizeof(LcoreContext), RTE_CACHE_LINE_SIZE, socket));
      if (!ctx) {
        RTE_LOG(ERR, USER1, "lcore %u: ctx alloc failed\n", lc_id);
        continue;
      }
      new (ctx) LcoreContext();

      ctx->lcore_id = static_cast<uint16_t>(lc_id);
      ctx->port_id = static_cast<uint16_t>(per_lcore[li][0].port_id);
      ctx->streams = std::move(per_lcore[li]);
      ctx->metrics = nullptr;
      ctx->metrics_count = 0;
      ctx->running.store(false, std::memory_order_relaxed);
      ctx->shutdown_requested.store(false, std::memory_order_relaxed);
      ctx->arp_ready.store(false, std::memory_order_relaxed);
      ctx->test_state.store(inst.state, std::memory_order_relaxed);
      ctx->rate_percent.store(inst.rate, std::memory_order_relaxed);

      inst.lcore_contexts.push_back(ctx);

      rte_eal_remote_launch(lcore_main, ctx, lc_id);
    }

    // Ждём ARP-ready со всех lcore (до 6 секунд)
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(6);
    for (auto* ctx : inst.lcore_contexts) {
      while (!ctx->arp_ready.load(std::memory_order_acquire)) {
        if (std::chrono::steady_clock::now() > deadline)
          break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
      }
    }

    // Устанавливаем running если state == RUNNING
    if (inst.state == static_cast<int32_t>(tester_proto::RUNNING)) {
      for (auto* ctx : inst.lcore_contexts)
        ctx->running.store(true, std::memory_order_relaxed);
    }

    tests_.emplace(test_id, std::move(inst));

    // Ответ
    tester_proto::CommandResponse resp;
    resp.set_ok(true);
    resp.set_test_id(test_id);
    send_proto(fd, resp);
  }

  // ------------------------------------------------------------------
  // CMD_STOP_TEST
  // ------------------------------------------------------------------
  void handle_stop_test(int fd, uint32_t test_id) {
    std::lock_guard<std::mutex> lock(tests_mutex_);
    auto it = tests_.find(test_id);
    if (it == tests_.end()) {
      send_error(fd, "test not found");
      return;
    }

    for (auto* ctx : it->second.lcore_contexts) {
      ctx->running.store(false, std::memory_order_relaxed);
      ctx->shutdown_requested.store(true, std::memory_order_relaxed);
    }
    for (auto* ctx : it->second.lcore_contexts) {
      rte_eal_wait_lcore(ctx->lcore_id);
      if (ctx->metrics)
        rte_free(ctx->metrics);
      ctx->~LcoreContext();
      rte_free(ctx);
    }

    {
      std::lock_guard<std::mutex> sl(snapshot_mutex_);
      snapshots_.erase(test_id);
    }
    tests_.erase(it);

    tester_proto::CommandResponse resp;
    resp.set_ok(true);
    send_proto(fd, resp);
  }

  // ------------------------------------------------------------------
  // CMD_PAUSE_TEST
  // ------------------------------------------------------------------
  void handle_pause_test(int fd, uint32_t test_id) {
    std::lock_guard<std::mutex> lock(tests_mutex_);
    auto it = tests_.find(test_id);
    if (it == tests_.end()) {
      send_error(fd, "test not found");
      return;
    }

    for (auto* ctx : it->second.lcore_contexts)
      ctx->running.store(false, std::memory_order_relaxed);
    it->second.state = static_cast<int32_t>(tester_proto::PAUSED);

    tester_proto::CommandResponse resp;
    resp.set_ok(true);
    send_proto(fd, resp);
  }

  // ------------------------------------------------------------------
  // CMD_RESUME_TEST
  // ------------------------------------------------------------------
  void handle_resume_test(int fd, uint32_t test_id) {
    std::lock_guard<std::mutex> lock(tests_mutex_);
    auto it = tests_.find(test_id);
    if (it == tests_.end()) {
      send_error(fd, "test not found");
      return;
    }

    for (auto* ctx : it->second.lcore_contexts)
      ctx->running.store(true, std::memory_order_relaxed);
    it->second.state = static_cast<int32_t>(tester_proto::RUNNING);

    tester_proto::CommandResponse resp;
    resp.set_ok(true);
    send_proto(fd, resp);
  }

  // ------------------------------------------------------------------
  // CMD_SET_RATE
  // ------------------------------------------------------------------
  void handle_set_rate(int fd, const tester_proto::SetRateRequest& req) {
    std::lock_guard<std::mutex> lock(tests_mutex_);
    auto it = tests_.find(req.test_id());
    if (it == tests_.end()) {
      send_error(fd, "test not found");
      return;
    }

    int32_t rate = std::max(1, std::min(100, req.rate()));
    it->second.rate = rate;
    for (auto* ctx : it->second.lcore_contexts)
      ctx->rate_percent.store(rate, std::memory_order_relaxed);

    tester_proto::CommandResponse resp;
    resp.set_ok(true);
    send_proto(fd, resp);
  }

  // ------------------------------------------------------------------
  // CMD_GET_STATS
  // ------------------------------------------------------------------
  void handle_get_stats(int fd, uint32_t test_id) {
    std::vector<StreamMetricsSnapshot> snap;
    int32_t state = 0;
    {
      std::lock_guard<std::mutex> sl(snapshot_mutex_);
      auto it = snapshots_.find(test_id);
      if (it != snapshots_.end())
        snap = it->second;
    }
    {
      std::lock_guard<std::mutex> lock(tests_mutex_);
      auto it = tests_.find(test_id);
      if (it != tests_.end())
        state = it->second.state;
    }

    tester_proto::StatsResponse resp;
    resp.set_test_id(test_id);
    resp.set_state(static_cast<tester_proto::TestState>(state));

    for (auto& s : snap) {
      auto* ss = resp.add_streams();
      ss->set_stream_index(s.stream_index);
      ss->set_tx_packets(s.tx_packets);
      ss->set_tx_bytes(s.tx_bytes);
      ss->set_rx_packets(s.rx_packets);
      ss->set_rx_bytes(s.rx_bytes);
      ss->set_tcp_connections_opened(s.tcp_connections_opened);
      ss->set_tcp_connections_established(s.tcp_connections_established);
      ss->set_tcp_connections_closed(s.tcp_connections_closed);
      ss->set_tcp_connections_reset(s.tcp_connections_reset);
      ss->set_tcp_retransmits(s.tcp_retransmits);
      ss->set_tcb_alloc_failed(s.tcb_alloc_failed);
      ss->set_rx_dropped(s.rx_dropped);
      ss->set_last_rtt_ns(s.last_rtt_ns);
      ss->set_tx_pps(s.tx_pps);
      ss->set_rx_pps(s.rx_pps);
      ss->set_tx_bps(s.tx_bps);
      ss->set_rx_bps(s.rx_bps);
    }

    send_proto(fd, resp);
  }

  // ------------------------------------------------------------------
  // CMD_LIST_TESTS
  // ------------------------------------------------------------------
  void handle_list_tests(int fd) {
    std::lock_guard<std::mutex> lock(tests_mutex_);
    tester_proto::TestListResponse resp;
    for (auto& [id, inst] : tests_) {
      auto* ti = resp.add_tests();
      ti->set_test_id(id);
      ti->set_state(static_cast<tester_proto::TestState>(inst.state));
      ti->set_rate(inst.rate);
      ti->set_num_streams(static_cast<int32_t>(inst.total_streams));
    }
    send_proto(fd, resp);
  }

  // ------------------------------------------------------------------
  // Metrics collector thread
  // ------------------------------------------------------------------
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

    for (auto& [test_id, inst] : tests_) {
      std::vector<StreamMetricsSnapshot> result;
      result.reserve(inst.total_streams);

      for (auto* ctx : inst.lcore_contexts) {
        StreamMetrics* mptr = __atomic_load_n(&ctx->metrics, __ATOMIC_ACQUIRE);
        if (!mptr)
          continue;

        for (size_t i = 0; i < ctx->streams.size(); ++i) {
          const StreamMetrics& sm = mptr[i];
          StreamMetricsSnapshot snap{};
          snap.stream_index = ctx->streams[i].stream_index;

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

          // Производные метрики
          uint64_t gidx =
              (static_cast<uint64_t>(test_id) << 32) | snap.stream_index;
          auto pit = prev_counters_.find(gidx);
          if (pit != prev_counters_.end()) {
            double dt =
                std::chrono::duration<double>(now - pit->second.ts).count();
            if (dt > 0.0) {
              snap.tx_pps = (snap.tx_packets - pit->second.tx_packets) / dt;
              snap.rx_pps = (snap.rx_packets - pit->second.rx_packets) / dt;
              snap.tx_bps = (snap.tx_bytes - pit->second.tx_bytes) * 8.0 / dt;
              snap.rx_bps = (snap.rx_bytes - pit->second.rx_bytes) * 8.0 / dt;
            }
          }
          prev_counters_[gidx] = {snap.tx_packets, snap.rx_packets,
                                  snap.tx_bytes, snap.rx_bytes, now};
          result.push_back(snap);
        }
      }

      std::lock_guard<std::mutex> sl(snapshot_mutex_);
      snapshots_[test_id] = std::move(result);
    }
  }

  // ------------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------------
  void send_error(int fd, const char* msg) {
    tester_proto::CommandResponse resp;
    resp.set_ok(false);
    resp.set_error(msg);
    send_proto(fd, resp);
  }

  template <typename T>
  void send_proto(int fd, const T& msg) {
    std::string data;
    msg.SerializeToString(&data);
    send_msg(fd, data);
  }

  static StreamConfig convert_stream(const tester_proto::Stream& s,
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

    // Гарантируем корректность диапазонов
    if (cfg.src_port_end < cfg.src_port_start)
      cfg.src_port_end = cfg.src_port_start;
    if (cfg.dst_port_end < cfg.dst_port_start)
      cfg.dst_port_end = cfg.dst_port_start;
    if (cfg.src_ip_end < cfg.src_ip_start)
      cfg.src_ip_end = cfg.src_ip_start;
    if (cfg.dst_ip_end < cfg.dst_ip_start)
      cfg.dst_ip_end = cfg.dst_ip_start;
    if (cfg.frame_size < 64)
      cfg.frame_size = 64;
    if (cfg.tcp_initial_window == 0)
      cfg.tcp_initial_window = 65535;

    return cfg;
  }

  static uint32_t ip_to_u32(const tester_proto::IPAddress& ip) {
    return (static_cast<uint32_t>(ip.octet1()) << 24) |
           (static_cast<uint32_t>(ip.octet2()) << 16) |
           (static_cast<uint32_t>(ip.octet3()) << 8) |
           static_cast<uint32_t>(ip.octet4());
  }
};