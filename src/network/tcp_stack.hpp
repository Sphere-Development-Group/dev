#pragma once

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_random.h>
#include <rte_tcp.h>

#include <string>
#include "../core/metrics.hpp"

// =====================================================================
// RFC 793 State machine
// =====================================================================
enum StateMachine : uint8_t {
  CLOSED = 0,
  LISTEN,
  SYN_SENT,
  SYN_RECEIVED,
  ESTABLISHED,
  FIN_WAIT_1,
  FIN_WAIT_2,
  CLOSE_WAIT,
  CLOSING,
  LAST_ACK,
  TIME_WAIT
};

// =====================================================================
// SessionKey — packed, иначе паддинг ломает хеш/сравнение
// =====================================================================
struct SessionKey {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;

  SessionKey reversed() const {
    SessionKey r;
    r.src_ip = dst_ip;
    r.dst_ip = src_ip;
    r.src_port = dst_port;
    r.dst_port = src_port;
    return r;
  }

  bool operator==(const SessionKey& o) const {
    return src_ip == o.src_ip && dst_ip == o.dst_ip && src_port == o.src_port &&
           dst_port == o.dst_port;
  }
};

// =====================================================================
// Timer Wheel — 4096 слотов, тик = период вызова process_timers
// =====================================================================
#define TW_SLOTS 4096u

struct TCB;  // forward

class TimerWheel {
 private:
  TCB* slots_[TW_SLOTS];
  uint32_t current_slot_{0};

 public:
  TimerWheel() {
    for (uint32_t i = 0; i < TW_SLOTS; ++i)
      slots_[i] = nullptr;
  }

  void add(TCB* tcb, uint32_t ticks_from_now);
  void remove(TCB* tcb);
  void rearm(TCB* tcb, uint32_t ticks_from_now);
  TCB* tick();  // возвращает голову просроченного списка
};

// =====================================================================
// TCB — TCP Control Block
// =====================================================================
struct TCB {
  // --- Send sequence ---
  uint32_t snd_una;
  uint32_t snd_nxt;
  uint32_t snd_wnd;
  uint32_t iss;

  // --- Receive sequence ---
  uint32_t rcv_nxt;
  uint32_t rcv_wnd;
  uint32_t irs;

  // --- State ---
  uint8_t session_state;

  // --- Для ретрансмита: последние флаги отправленного сегмента ---
  uint8_t last_tx_flags;

  // --- Принадлежность ---
  SessionKey key;
  uint32_t stream_index;

  // --- TSC момента отправки SYN (для расчёта RTT) ---
  uint64_t syn_sent_tsc;

  // --- Timer wheel ---
  TCB* prev_tcb;
  TCB* next_tcb;
  uint32_t tw_slot;
  uint8_t retransmission_count;

  // --- payload template mbuf (для ESTABLISHED data) ---
  rte_mbuf* payload_template;

  void reset() {
    snd_una = snd_nxt = snd_wnd = iss = 0;
    rcv_nxt = rcv_wnd = irs = 0;
    session_state = StateMachine::CLOSED;
    last_tx_flags = 0;
    prev_tcb = next_tcb = nullptr;
    tw_slot = UINT32_MAX;
    retransmission_count = 5;
    payload_template = nullptr;
    stream_index = 0;
    syn_sent_tsc = 0;
  }
};

// TimerWheel impl (defined after TCB)
inline void TimerWheel::add(TCB* tcb, uint32_t ticks_from_now) {
  uint32_t slot = (current_slot_ + ticks_from_now) % TW_SLOTS;
  tcb->tw_slot = slot;
  tcb->prev_tcb = nullptr;
  tcb->next_tcb = slots_[slot];
  if (slots_[slot])
    slots_[slot]->prev_tcb = tcb;
  slots_[slot] = tcb;
}

inline void TimerWheel::remove(TCB* tcb) {
  if (tcb->tw_slot == UINT32_MAX)
    return;
  if (tcb->prev_tcb)
    tcb->prev_tcb->next_tcb = tcb->next_tcb;
  else
    slots_[tcb->tw_slot] = tcb->next_tcb;
  if (tcb->next_tcb)
    tcb->next_tcb->prev_tcb = tcb->prev_tcb;
  tcb->prev_tcb = tcb->next_tcb = nullptr;
  tcb->tw_slot = UINT32_MAX;
}

inline void TimerWheel::rearm(TCB* tcb, uint32_t ticks_from_now) {
  remove(tcb);
  add(tcb, ticks_from_now);
}

inline TCB* TimerWheel::tick() {
  TCB* expired = slots_[current_slot_];
  slots_[current_slot_] = nullptr;
  current_slot_ = (current_slot_ + 1) % TW_SLOTS;
  return expired;
}

// =====================================================================
// TCP_Stack
// =====================================================================
class TCP_Stack {
 private:
  uint16_t core_id_ = 0;
  uint16_t port_id_ = 0;
  uint64_t total_sessions_ = 0;
  rte_mempool* mempool_ = nullptr;
  rte_hash* hash_table_ = nullptr;
  TimerWheel timer_wheel_;

  // Таймауты в тиках (1 тик = 10ms)
  static constexpr uint32_t TIMEOUT_SYN_SENT = 100;      // 1s ждём SYN+ACK
  static constexpr uint32_t TIMEOUT_SYN_RECEIVED = 100;  // 1s ждём ACK
  static constexpr uint32_t TIMEOUT_ESTABLISHED = 6000;  // 60s keepalive
  static constexpr uint32_t TIMEOUT_FIN_WAIT = 200;      // 2s
  static constexpr uint32_t TIMEOUT_TIME_WAIT = 400;     // 4s (2*MSL)
  static constexpr uint32_t TIMEOUT_RETRANSMIT = 30;     // 300ms

 public:
  TCP_Stack(uint16_t core_id, uint16_t port_id, uint64_t total_sessions)
      : core_id_(core_id), port_id_(port_id), total_sessions_(total_sessions) {}

  // ------------------------------------------------------------------
  // Инициализация
  // ------------------------------------------------------------------
  bool mempool_create() {
    std::string name = "tcb-pool-" + std::to_string(core_id_);
    mempool_ = rte_mempool_create(
        name.c_str(), static_cast<uint32_t>(total_sessions_), sizeof(TCB), 512,
        0, nullptr, nullptr, nullptr, nullptr, rte_socket_id(), 0);
    return mempool_ != nullptr;
  }

  bool create_hash_table() {
    rte_hash_parameters cfg = {};
    std::string name = "tcb-hash-" + std::to_string(core_id_);
    cfg.name = name.c_str();
    cfg.entries = static_cast<uint32_t>(total_sessions_ * 1.25 + 16);
    cfg.key_len = sizeof(SessionKey);
    cfg.socket_id = rte_socket_id();
    cfg.extra_flag = RTE_HASH_EXTRA_FLAGS_EXT_TABLE;
    cfg.hash_func_init_val = 0;
    hash_table_ = rte_hash_create(&cfg);
    return hash_table_ != nullptr;
  }

  // ------------------------------------------------------------------
  // TCB pool / hash helpers
  // ------------------------------------------------------------------
  TCB* lookup_tcb(const SessionKey* key) {
    void* tcb = nullptr;
    if (unlikely(rte_hash_lookup_data(hash_table_, key, &tcb) < 0))
      return nullptr;
    return static_cast<TCB*>(tcb);
  }

  TCB* create_tcb(const SessionKey* key) {
    void* raw = nullptr;
    if (unlikely(rte_mempool_get(mempool_, &raw) != 0))
      return nullptr;
    TCB* tcb = static_cast<TCB*>(raw);
    tcb->reset();
    tcb->key = *key;
    if (unlikely(rte_hash_add_key_data(hash_table_, key, tcb) != 0)) {
      rte_mempool_put(mempool_, tcb);
      return nullptr;
    }
    return tcb;
  }

  bool destroy_tcb(TCB* tcb) {
    if (unlikely(!tcb))
      return false;
    timer_wheel_.remove(tcb);
    if (unlikely(rte_hash_del_key(hash_table_, &tcb->key) < 0))
      return false;
    rte_mempool_put(mempool_, tcb);
    return true;
  }

  // ------------------------------------------------------------------
  // open_connection — активная сторона (INIT/BOTH).
  // Создаёт TCB в состоянии SYN_SENT, формирует SYN-сегмент в tx_mbuf.
  // Возвращает TCB* или nullptr при нехватке ресурсов.
  // ------------------------------------------------------------------
  TCB* open_connection(const SessionKey* key,
                       rte_mbuf* tx_mbuf,
                       uint16_t initial_window,
                       StreamMetrics* sm,
                       uint64_t now_tsc) {
    // Проверяем: вдруг уже есть
    TCB* tcb = lookup_tcb(key);
    if (tcb)
      return tcb;

    tcb = create_tcb(key);
    if (unlikely(!tcb)) {
      if (sm)
        sm->tcb_alloc_failed.fetch_add(1, std::memory_order_relaxed);
      return nullptr;
    }

    tcb->iss = static_cast<uint32_t>(rte_rand());
    tcb->snd_una = tcb->iss;
    tcb->snd_nxt = tcb->iss;
    tcb->rcv_wnd = initial_window ? initial_window : 65535u;
    tcb->session_state = StateMachine::SYN_SENT;
    tcb->syn_sent_tsc = now_tsc;

    // SYN не несёт данных, SYN bit занимает 1 sequence-number
    fill_tcp_segment(tcb, true, tx_mbuf, key, RTE_TCP_SYN_FLAG);
    tcb->snd_nxt++;  // SYN расходует 1 seq

    timer_wheel_.add(tcb, TIMEOUT_SYN_SENT);

    if (sm)
      sm->tcp_connections_opened.fetch_add(1, std::memory_order_relaxed);
    return tcb;
  }

  // ------------------------------------------------------------------
  // receive_message — точка входа для входящего сегмента.
  //   key        — SessionKey из rx (src=наш локальный, dst=peer),
  //                т.е. ПОСЛЕ инверсии в parse_frame.
  //   tx_mbuf    — новый пустой mbuf для ответа (ACK/SYN+ACK/FIN)
  //   tpl_mbuf   — клон шаблона с данными (для ESTABLISHED), или nullptr
  //   rx_l4      — TCP заголовок входящего пакета
  //   rx_payload_len — длина полезной нагрузки
  //   out_reply  — [out] mbuf для отправки (tx_mbuf или tpl_mbuf)
  //   sm         — метрики stream
  //   stream_idx — индекс stream для записи в TCB
  //   now_tsc    — текущее значение TSC (для RTT)
  //
  // Возвращает true если out_reply готов к отправке.
  // ------------------------------------------------------------------
  bool receive_message(const SessionKey* key,
                       rte_mbuf* tx_mbuf,
                       rte_mbuf* tpl_mbuf,
                       const rte_tcp_hdr* rx_l4,
                       uint16_t rx_payload_len,
                       rte_mbuf** out_reply,
                       StreamMetrics* sm,
                       uint32_t stream_idx,
                       uint64_t now_tsc) {
    TCB* tcb = lookup_tcb(key);
    bool is_new = false;
    uint8_t flags = rx_l4->tcp_flags;

    // ---- RST всегда обрабатываем мгновенно ----
    if (unlikely(flags & RTE_TCP_RST_FLAG)) {
      if (tcb) {
        if (sm) {
          sm->tcp_connections_reset.fetch_add(1, std::memory_order_relaxed);
          sm->tcp_connections_closed.fetch_add(1, std::memory_order_relaxed);
        }
        destroy_tcb(tcb);
      }
      if (sm)
        sm->rx_dropped.fetch_add(1, std::memory_order_relaxed);
      return false;
    }

    // ---- Нет TCB ----
    if (unlikely(!tcb)) {
      // Принимаем только SYN (passive open / RESPOND mode)
      if (!(flags & RTE_TCP_SYN_FLAG) || (flags & RTE_TCP_ACK_FLAG)) {
        if (sm)
          sm->rx_dropped.fetch_add(1, std::memory_order_relaxed);
        return false;
      }
      tcb = create_tcb(key);
      if (unlikely(!tcb)) {
        if (sm)
          sm->tcb_alloc_failed.fetch_add(1, std::memory_order_relaxed);
        return false;
      }
      // Passive open: инициализируем TCB по входящему SYN
      tcb->irs = rte_be_to_cpu_32(rx_l4->sent_seq);
      tcb->rcv_nxt = tcb->irs + 1;
      tcb->rcv_wnd = 65535u;
      tcb->iss = static_cast<uint32_t>(rte_rand());
      tcb->snd_una = tcb->iss;
      tcb->snd_nxt = tcb->iss;
      tcb->snd_wnd = rte_be_to_cpu_16(rx_l4->rx_win);
      tcb->session_state = StateMachine::SYN_RECEIVED;
      tcb->stream_index = stream_idx;
      is_new = true;
      if (sm)
        sm->tcp_connections_opened.fetch_add(1, std::memory_order_relaxed);
      timer_wheel_.add(tcb, TIMEOUT_SYN_RECEIVED);
    }

    uint8_t prev_state = tcb->session_state;
    uint8_t ack_flag = flags & RTE_TCP_ACK_FLAG;
    uint32_t seg_seq = rte_be_to_cpu_32(rx_l4->sent_seq);
    uint32_t seg_ack = rte_be_to_cpu_32(rx_l4->recv_ack);

    bool ack_valid =
        ack_flag && ((seg_ack - tcb->snd_una) <= (tcb->snd_nxt - tcb->snd_una));

    // ---- Обновление TCB по флагам ----
    if (!is_new) {
      switch (tcb->session_state) {
        case StateMachine::SYN_SENT:
          // Ожидаем SYN+ACK
          if ((flags & RTE_TCP_SYN_FLAG) && ack_valid) {
            // Вычисляем RTT
            if (sm && tcb->syn_sent_tsc) {
              uint64_t rtt_cycles = now_tsc - tcb->syn_sent_tsc;
              uint64_t hz = rte_get_tsc_hz();
              uint64_t rtt_ns = rtt_cycles * 1000000000ULL / hz;
              sm->last_rtt_ns.store(rtt_ns, std::memory_order_relaxed);
            }
            tcb->irs = seg_seq;
            tcb->rcv_nxt = seg_seq + 1;
            tcb->snd_una = seg_ack;
            tcb->snd_wnd = rte_be_to_cpu_16(rx_l4->rx_win);
            tcb->session_state = StateMachine::ESTABLISHED;
            if (sm)
              sm->tcp_connections_established.fetch_add(
                  1, std::memory_order_relaxed);
            timer_wheel_.rearm(tcb, TIMEOUT_ESTABLISHED);
          }
          break;

        case StateMachine::SYN_RECEIVED:
          if (ack_valid) {
            tcb->snd_una = seg_ack;
            tcb->session_state = StateMachine::ESTABLISHED;
            if (sm)
              sm->tcp_connections_established.fetch_add(
                  1, std::memory_order_relaxed);
            timer_wheel_.rearm(tcb, TIMEOUT_ESTABLISHED);
          }
          break;

        case StateMachine::ESTABLISHED:
          if (ack_valid)
            tcb->snd_una = seg_ack;
          if (flags & RTE_TCP_FIN_FLAG) {
            tcb->rcv_nxt = seg_seq + rx_payload_len + 1;
            tcb->session_state = StateMachine::CLOSE_WAIT;
          } else if (rx_payload_len > 0) {
            tcb->rcv_nxt = seg_seq + rx_payload_len;
            timer_wheel_.rearm(tcb, TIMEOUT_ESTABLISHED);
          }
          break;

        case StateMachine::FIN_WAIT_1:
          if (flags & RTE_TCP_FIN_FLAG) {
            tcb->rcv_nxt = seg_seq + 1;
            tcb->session_state =
                ack_valid ? StateMachine::TIME_WAIT : StateMachine::CLOSING;
            if (ack_valid)
              tcb->snd_una = seg_ack;
            timer_wheel_.rearm(tcb, TIMEOUT_TIME_WAIT);
          } else if (ack_valid) {
            tcb->snd_una = seg_ack;
            tcb->session_state = StateMachine::FIN_WAIT_2;
            timer_wheel_.rearm(tcb, TIMEOUT_FIN_WAIT);
          }
          break;

        case StateMachine::FIN_WAIT_2:
          if (flags & RTE_TCP_FIN_FLAG) {
            tcb->rcv_nxt = seg_seq + 1;
            tcb->session_state = StateMachine::TIME_WAIT;
            timer_wheel_.rearm(tcb, TIMEOUT_TIME_WAIT);
          }
          break;

        case StateMachine::CLOSING:
          if (ack_valid) {
            tcb->snd_una = seg_ack;
            tcb->session_state = StateMachine::TIME_WAIT;
            timer_wheel_.rearm(tcb, TIMEOUT_TIME_WAIT);
          }
          break;

        case StateMachine::LAST_ACK:
          if (ack_valid) {
            tcb->snd_una = seg_ack;
            tcb->session_state = StateMachine::CLOSED;
          }
          break;

        case StateMachine::TIME_WAIT:
          // рестарт таймера на повторный FIN
          timer_wheel_.rearm(tcb, TIMEOUT_TIME_WAIT);
          break;

        default:
          break;
      }
    }

    uint8_t cur_state = tcb->session_state;

    // ---- Убираем CLOSED / TIME_WAIT ----
    if (cur_state == StateMachine::CLOSED) {
      if (sm)
        sm->tcp_connections_closed.fetch_add(1, std::memory_order_relaxed);
      destroy_tcb(tcb);
      return false;
    }
    if (cur_state == StateMachine::TIME_WAIT &&
        prev_state == StateMachine::TIME_WAIT) {
      // повторный FIN — шлём ACK, потом таймаут сам уберёт
    }

    // ---- Формируем ответный сегмент ----
    SessionKey tx_key = key->reversed();
    uint16_t reply_flags = RTE_TCP_ACK_FLAG;
    bool use_tpl = false;

    if (is_new) {
      // SYN_RECEIVED: отвечаем SYN+ACK
      reply_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
    } else if (cur_state == StateMachine::ESTABLISHED && tpl_mbuf &&
               rx_payload_len == 0 && !(flags & RTE_TCP_FIN_FLAG)) {
      // ESTABLISHED + есть шаблон данных и входящий был чистый ACK
      // → генератор в INIT/BOTH режиме шлёт payload
      use_tpl = true;
    } else if (cur_state == StateMachine::CLOSE_WAIT) {
      // Автоматическое закрытие: посылаем FIN+ACK
      reply_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
      tcb->session_state = StateMachine::LAST_ACK;
      timer_wheel_.rearm(tcb, TIMEOUT_FIN_WAIT);
    }

    rte_mbuf* reply_mbuf = use_tpl ? tpl_mbuf : tx_mbuf;
    fill_tcp_segment(tcb, !use_tpl, reply_mbuf, &tx_key, reply_flags);
    tcb->last_tx_flags = static_cast<uint8_t>(reply_flags);

    // SYN и FIN занимают 1 sequence-number
    if (reply_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG))
      tcb->snd_nxt++;

    *out_reply = reply_mbuf;
    return true;
  }

  // ------------------------------------------------------------------
  // fill_tcp_segment — заполняет TCP-заголовок в mbuf.
  //   is_new_mbuf=true  → mbuf пустой, append заголовок
  //   is_new_mbuf=false → mbuf-клон шаблона, правим поля по смещению
  // ------------------------------------------------------------------
  void fill_tcp_segment(TCB* tcb,
                        bool is_new_mbuf,
                        rte_mbuf* mbuf,
                        const SessionKey* tx_key,
                        uint16_t flags) {
    rte_tcp_hdr* l4;
    if (is_new_mbuf) {
      l4 = reinterpret_cast<rte_tcp_hdr*>(
          rte_pktmbuf_append(mbuf, sizeof(rte_tcp_hdr)));
    } else {
      l4 = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*,
                                   mbuf->l2_len + mbuf->l3_len);
    }

    l4->src_port = rte_cpu_to_be_16(tx_key->src_port);
    l4->dst_port = rte_cpu_to_be_16(tx_key->dst_port);
    l4->sent_seq = rte_cpu_to_be_32(tcb->snd_nxt);
    l4->recv_ack = rte_cpu_to_be_32(tcb->rcv_nxt);
    l4->data_off = (sizeof(rte_tcp_hdr) / 4) << 4;
    l4->tcp_flags = static_cast<uint8_t>(flags);
    l4->rx_win = rte_cpu_to_be_16(static_cast<uint16_t>(tcb->rcv_wnd));
    l4->tcp_urp = 0;
    l4->cksum = 0;

    mbuf->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM | RTE_MBUF_F_TX_IPV4;
    mbuf->l4_len = sizeof(rte_tcp_hdr);
  }

  // ------------------------------------------------------------------
  // process_timers — вызывается раз в "тик" (~10ms).
  //   metrics_arr — массив StreamMetrics для всех streams этого lcore.
  //   send_cb(TCB*) — callback для ретрансмита: должен сформировать
  //                   и поставить в TX-burst повтор последнего сегмента.
  // ------------------------------------------------------------------
  template <typename SendRetransmitCb>
  void process_timers(StreamMetrics* metrics_arr, SendRetransmitCb&& send_cb) {
    TCB* expired = timer_wheel_.tick();
    while (expired) {
      TCB* next = expired->next_tcb;
      StreamMetrics* sm =
          metrics_arr ? &metrics_arr[expired->stream_index] : nullptr;

      switch (expired->session_state) {
        case StateMachine::SYN_SENT:
        case StateMachine::SYN_RECEIVED:
        case StateMachine::FIN_WAIT_1:
        case StateMachine::FIN_WAIT_2:
        case StateMachine::CLOSING:
        case StateMachine::LAST_ACK:
          if (expired->retransmission_count > 0) {
            expired->retransmission_count--;
            if (sm)
              sm->tcp_retransmits.fetch_add(1, std::memory_order_relaxed);
            send_cb(expired);
            timer_wheel_.add(expired, TIMEOUT_RETRANSMIT);
          } else {
            if (sm)
              sm->tcp_connections_closed.fetch_add(1,
                                                   std::memory_order_relaxed);
            destroy_tcb(expired);
          }
          break;

        case StateMachine::ESTABLISHED:
          // Idle-timeout — закрываем
          if (sm)
            sm->tcp_connections_closed.fetch_add(1, std::memory_order_relaxed);
          destroy_tcb(expired);
          break;

        case StateMachine::TIME_WAIT:
          if (sm)
            sm->tcp_connections_closed.fetch_add(1, std::memory_order_relaxed);
          destroy_tcb(expired);
          break;

        default:
          destroy_tcb(expired);
          break;
      }
      expired = next;
    }
  }

  ~TCP_Stack() {
    if (hash_table_)
      rte_hash_free(hash_table_);
    if (mempool_)
      rte_mempool_free(mempool_);
  }
};