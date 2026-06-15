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

#include "metrics.hpp"

// =====================================================================
// State machine (RFC 793)
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
// SessionKey — упакован, чтобы паддинг не влиял на hash/сравнение
// =====================================================================
// struct __rte_packed SessionKey {
struct SessionKey {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;

  // Инвертированный ключ — для формирования ответа (src/dst меняются местами)
  SessionKey reversed() const {
    SessionKey r;
    r.src_ip = dst_ip;
    r.dst_ip = src_ip;
    r.src_port = dst_port;
    r.dst_port = src_port;
    return r;
  }
};

// =====================================================================
// Timer wheel slot count. Степень двойки для быстрой mod-операции.
// =====================================================================
#define TW_SLOTS 4096u  // например 4096 слотов x 10ms tick = ~40s горизонт

// =====================================================================
// TCB — TCP Control Block
// =====================================================================
struct TCB {
  // --- Send sequence variables ---
  uint32_t snd_una;
  uint32_t snd_nxt;
  uint32_t snd_wnd;
  uint32_t snd_up;
  uint32_t snd_wl1;
  uint32_t snd_wl2;
  uint32_t iss;

  // --- Receive sequence variables ---
  uint32_t rcv_nxt;
  uint32_t rcv_wnd;
  uint32_t rcv_up;
  uint32_t irs;

  // --- State ---
  uint8_t session_state;

  // --- SessionKey, по которому был создан TCB (для удаления из hash) ---
  SessionKey key;

  // --- Индекс stream (в рамках LcoreContext::streams), нужен для
  //     записи метрик из retransmit-callback process_timers ---
  uint32_t stream_index;

  // --- Timer wheel linkage ---
  TCB* prev_tcb;
  TCB* next_tcb;
  uint32_t tw_slot;          // в каком слоте колеса сейчас находится
  uint8_t retransmission_count;

  // --- Указатель на шаблон payload для ESTABLISHED-фазы (если есть) ---
  rte_mbuf* payload_template;

  void reset() {
    snd_una = 0;
    snd_nxt = 0;
    snd_wnd = 0;
    snd_up = 0;
    snd_wl1 = 0;
    snd_wl2 = 0;
    iss = 0;
    rcv_nxt = 0;
    rcv_wnd = 0;
    rcv_up = 0;
    irs = 0;
    session_state = StateMachine::CLOSED;
    prev_tcb = nullptr;
    next_tcb = nullptr;
    tw_slot = UINT32_MAX;
    retransmission_count = 3;
    payload_template = nullptr;
    stream_index = 0;
  }
};

// =====================================================================
// Timer Wheel
// Каждый слот — голова двусвязного списка TCB.
// На каждый tick текущий слот обходится, для просроченных TCB
// вызывается callback (закрытие/удаление сессии или ретрансмит).
// =====================================================================
class TimerWheel {
 private:
  TCB* slots_[TW_SLOTS];
  uint32_t current_slot_ = 0;

 public:
  TimerWheel() {
    for (uint32_t i = 0; i < TW_SLOTS; ++i) slots_[i] = nullptr;
  }

  // Вставка TCB в слот на ticks_from_now тиков вперёд от текущего
  void add(TCB* tcb, uint32_t ticks_from_now) {
    uint32_t slot = (current_slot_ + ticks_from_now) % TW_SLOTS;
    tcb->tw_slot = slot;
    tcb->prev_tcb = nullptr;
    tcb->next_tcb = slots_[slot];
    if (slots_[slot] != nullptr)
      slots_[slot]->prev_tcb = tcb;
    slots_[slot] = tcb;
  }

  // Удаление TCB из текущего слота (например при переходе ESTABLISHED
  // или при ручном закрытии). Корректно отвязывает узел из списка.
  void remove(TCB* tcb) {
    if (tcb->tw_slot == UINT32_MAX)
      return;  // не находится в колесе

    if (tcb->prev_tcb != nullptr)
      tcb->prev_tcb->next_tcb = tcb->next_tcb;
    else
      slots_[tcb->tw_slot] = tcb->next_tcb;

    if (tcb->next_tcb != nullptr)
      tcb->next_tcb->prev_tcb = tcb->prev_tcb;

    tcb->prev_tcb = nullptr;
    tcb->next_tcb = nullptr;
    tcb->tw_slot = UINT32_MAX;
  }

  // Перевставка с новым таймаутом (remove + add)
  void rearm(TCB* tcb, uint32_t ticks_from_now) {
    remove(tcb);
    add(tcb, ticks_from_now);
  }

  // Продвижение колеса на один тик. Возвращает голову списка
  // просроченных TCB текущего слота (до продвижения), сам слот очищается.
  // Вызывающий код обходит список через next_tcb и решает, что делать
  // с каждым TCB (ретрансмит / удаление сессии).
  TCB* tick() {
    TCB* expired = slots_[current_slot_];
    slots_[current_slot_] = nullptr;

    // Узлы остаются с валидными prev/next до того момента, как
    // вызывающий код их обработает и вызовет remove()/повторный add().
    current_slot_ = (current_slot_ + 1) % TW_SLOTS;
    return expired;
  }
};

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

  // --- Таймауты в тиках колеса (тик = период вызова process_timers) ---
  static constexpr uint32_t TIMEOUT_SYN_RECEIVED = 500;   // ожидание ACK на SYN+ACK
  static constexpr uint32_t TIMEOUT_ESTABLISHED  = 6000;  // keepalive / idle
  static constexpr uint32_t TIMEOUT_FIN_WAIT     = 1000;  // ожидание FIN/ACK
  static constexpr uint32_t TIMEOUT_TIME_WAIT    = 3000;  // 2*MSL аналог
  static constexpr uint32_t TIMEOUT_RETRANSMIT   = 200;

 public:
  TCP_Stack(uint16_t core_id, uint16_t port_id, uint64_t total_sessions)
      : core_id_(core_id), port_id_(port_id), total_sessions_(total_sessions) {}

  // ------------------------------------------------------------------
  // Инициализация пула и хеш-таблицы
  // ------------------------------------------------------------------
  bool mempool_create() {
    std::string name = "tcb-pool-" + std::to_string(core_id_);
    mempool_ = rte_mempool_create(
        name.c_str(), total_sessions_, sizeof(TCB), 512, 0, nullptr, nullptr,
        nullptr, nullptr, rte_socket_id(), 0);
    return mempool_ != nullptr;
  }

  bool create_hash_table() {
    rte_hash_parameters config = {};
    std::string name = "tcb-hash-table-" + std::to_string(core_id_);

    config.entries = static_cast<uint32_t>(total_sessions_ * 1.3);
    config.extra_flag =
        RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT | RTE_HASH_EXTRA_FLAGS_EXT_TABLE;
    config.hash_func_init_val = 0;
    config.key_len = sizeof(SessionKey);
    config.name = name.c_str();
    config.socket_id = rte_socket_id();

    hash_table_ = rte_hash_create(&config);
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

  // Полное удаление сессии: из timer wheel, из hash, возврат в pool
  bool destroy_tcb(TCB* tcb) {
    if (unlikely(tcb == nullptr))
      return false;

    timer_wheel_.remove(tcb);

    if (unlikely(rte_hash_del_key(hash_table_, &tcb->key) < 0))
      return false;

    rte_mempool_put(mempool_, tcb);
    return true;
  }

  // ------------------------------------------------------------------
  // fillTcb — обновление TCB по входящему l4-заголовку.
  // Возвращает итоговый session_state.
  // is_new_tcb=true означает, что TCB только что создан в receiveMessage
  // (получен SYN, начальные поля iss/irs/rcv_nxt уже выставлены вызывающим
  // кодом) — здесь только довыставляем общие поля и не трогаем состояние.
  // ------------------------------------------------------------------
  uint8_t fillTcb(TCB* tcb, const rte_tcp_hdr* l4, bool is_new_tcb) {
    uint32_t seg_seq = rte_be_to_cpu_32(l4->sent_seq);
    uint32_t seg_ack = rte_be_to_cpu_32(l4->recv_ack);
    uint16_t flags = l4->tcp_flags;

    // -------- RST в любом состоянии --------
    if (unlikely(flags & RTE_TCP_RST_FLAG)) {
      tcb->session_state = StateMachine::CLOSED;
      return tcb->session_state;
    }

    if (is_new_tcb) {
      // Поля iss/irs/rcv_nxt уже инициализированы в receiveMessage
      // при создании TCB. Здесь только синхронизируем окно.
      tcb->snd_wnd = rte_be_to_cpu_32(l4->rx_win);
      return tcb->session_state;
    }

    // -------- Валидация ACK (RFC793 SEG.ACK в пределах SND.UNA..SND.NXT) --------
    bool ack_valid = (flags & RTE_TCP_ACK_FLAG) &&
                      (seg_ack - tcb->snd_una <= tcb->snd_nxt - tcb->snd_una);

    switch (tcb->session_state) {
      case StateMachine::SYN_SENT:
        if ((flags & RTE_TCP_SYN_FLAG) && (flags & RTE_TCP_ACK_FLAG) && ack_valid) {
          tcb->irs = seg_seq;
          tcb->rcv_nxt = seg_seq + 1;
          tcb->snd_una = seg_ack;
          tcb->session_state = StateMachine::ESTABLISHED;
        }
        break;

      case StateMachine::SYN_RECEIVED:
        if (flags & RTE_TCP_ACK_FLAG) {
          tcb->snd_una = seg_ack;
          tcb->session_state = StateMachine::ESTABLISHED;
        }
        break;

      case StateMachine::ESTABLISHED: {
        if (ack_valid)
          tcb->snd_una = seg_ack;

        uint32_t payload_len = 0;
        uint8_t l4_len = (l4->data_off >> 4) * 4;
        // payload_len считается вызывающим кодом из l3->total_length,
        // здесь предполагается, что caller передал корректный l4 со
        // встроенным размером сегмента (упрощённо опускаем расчёт).
        (void)l4_len;

        if (flags & RTE_TCP_FIN_FLAG) {
          tcb->rcv_nxt = seg_seq + payload_len + 1;
          tcb->session_state = StateMachine::CLOSE_WAIT;
        } else if (payload_len > 0) {
          tcb->rcv_nxt = seg_seq + payload_len;
        }
        break;
      }

      case StateMachine::FIN_WAIT_1:
        if (flags & RTE_TCP_FIN_FLAG) {
          tcb->rcv_nxt = seg_seq + 1;
          if (ack_valid) {
            tcb->snd_una = seg_ack;
            tcb->session_state = StateMachine::TIME_WAIT;
          } else {
            tcb->session_state = StateMachine::CLOSING;
          }
        } else if (ack_valid) {
          tcb->snd_una = seg_ack;
          tcb->session_state = StateMachine::FIN_WAIT_2;
        }
        break;

      case StateMachine::FIN_WAIT_2:
        if (flags & RTE_TCP_FIN_FLAG) {
          tcb->rcv_nxt = seg_seq + 1;
          tcb->session_state = StateMachine::TIME_WAIT;
        }
        break;

      case StateMachine::CLOSING:
        if (ack_valid) {
          tcb->snd_una = seg_ack;
          tcb->session_state = StateMachine::TIME_WAIT;
        }
        break;

      case StateMachine::LAST_ACK:
        if (ack_valid) {
          tcb->snd_una = seg_ack;
          tcb->session_state = StateMachine::CLOSED;
        }
        break;

      case StateMachine::TIME_WAIT:
        // Любой сегмент в TIME_WAIT — рестарт таймера (обрабатывается
        // в receiveMessage через timer_wheel_.rearm)
        break;

      default:
        break;
    }

    return tcb->session_state;
  }

  // ------------------------------------------------------------------
  // fillTcpSegment — формирование L4-заголовка (и при необходимости
  // L2/L3, если генератор сам собирает фрейм с нуля для нового mbuf).
  //
  // is_new_mbuf = true  -> mbuf пустой, пишем через rte_pktmbuf_append (_mtod
  //                         логически эквивалентен append на пустой mbuf)
  // is_new_mbuf = false -> mbuf — копия шаблона с уже выставленными
  //                         L2/L3/payload, правим только L4 поля через
  //                         rte_pktmbuf_mtod_offset
  // ------------------------------------------------------------------
  void fillTcpSegment(TCB* tcb, bool is_new_mbuf, rte_mbuf* mbuf,
                       const SessionKey* tx_key, uint16_t flags) {
    rte_tcp_hdr* l4;

    if (is_new_mbuf) {
      // Заголовки L2/L3 заполняются отдельным модулем генератора (шаблон
      // copy + патч адресов); здесь формируем только L4 в конце цепочки.
      l4 = reinterpret_cast<rte_tcp_hdr*>(
          rte_pktmbuf_append(mbuf, sizeof(rte_tcp_hdr)));
    } else {
      // mbuf — клон шаблона; L4 находится по фиксированному смещению
      // (l2_len + l3_len), которое должно быть проставлено при подготовке
      // шаблона.
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

    // Чексумма считается после того, как известны l2_len/l3_len mbuf'а
    // (выставляются генератором при подготовке L3).
    mbuf->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM | RTE_MBUF_F_TX_IPV4;
  }

  // ------------------------------------------------------------------
  // receiveMessage — основная точка входа
  //
  // key       — SessionKey из rx-фрейма (src=peer, dst=local)
  // tx_mbuf   — новый (пустой) mbuf для ответа
  // tpl_mbuf  — шаблонный mbuf с payload (для ESTABLISHED-фазы), может
  //             быть nullptr если у генератора нет данных для отправки
  // rx_l4     — l4-заголовок входящего сегмента
  //
  // Возвращает true, если в одном из mbuf сформирован ответ для отправки,
  // false — если фрейм был дропнут / ответа не требуется (например RST).
  // out_reply — указывает, в каком из mbuf лежит итоговый сегмент.
  // ------------------------------------------------------------------
  bool receiveMessage(const SessionKey* key, rte_mbuf* tx_mbuf,
                       rte_mbuf* tpl_mbuf, const rte_tcp_hdr* rx_l4,
                       rte_mbuf** out_reply, StreamMetrics* metrics,
                       uint32_t stream_index) {
    TCB* tcb = lookup_tcb(key);
    bool is_new_tcb = false;

    // ---- Шаг 1: поиск / создание TCB ----
    if (unlikely(tcb == nullptr)) {
      if (!(rx_l4->tcp_flags & RTE_TCP_SYN_FLAG)) {
        // Нет сессии и не SYN — дроп
        if (metrics)
          metrics->rx_dropped.fetch_add(1, std::memory_order_relaxed);
        return false;
      }

      tcb = create_tcb(key);
      if (unlikely(tcb == nullptr)) {
        if (metrics)
          metrics->tcb_alloc_failed.fetch_add(1, std::memory_order_relaxed);
        return false;  // нет свободных слотов
      }

      // Инициализация по входящему SYN
      tcb->irs = rte_be_to_cpu_32(rx_l4->sent_seq);
      tcb->rcv_nxt = tcb->irs + 1;
      tcb->rcv_wnd = 65535;
      tcb->iss = static_cast<uint32_t>(rte_rand());
      tcb->snd_una = tcb->iss;
      tcb->snd_nxt = tcb->iss;
      tcb->snd_wnd = rte_be_to_cpu_32(rx_l4->rx_win);
      tcb->session_state = StateMachine::SYN_RECEIVED;
      tcb->stream_index = stream_index;

      is_new_tcb = true;

      if (metrics)
        metrics->tcp_connections_opened.fetch_add(1, std::memory_order_relaxed);

      // Ставим в timer wheel ожидание ACK на SYN+ACK
      timer_wheel_.add(tcb, TIMEOUT_SYN_RECEIVED);
    } else {
      if (rx_l4->tcp_flags & RTE_TCP_SYN_FLAG &&
          tcb->session_state != StateMachine::LISTEN &&
          tcb->session_state != StateMachine::SYN_SENT) {
        // Повторный/посторонний SYN на уже существующую сессию — игнор
        if (metrics)
          metrics->rx_dropped.fetch_add(1, std::memory_order_relaxed);
        return false;
      }
    }

    // ---- Шаг 2: обновление TCB по входящему сегменту ----
    uint8_t prev_state = tcb->session_state;
    uint8_t status = fillTcb(tcb, rx_l4, is_new_tcb);

    // ---- RST -> немедленное удаление, без ответа ----
    if (status == StateMachine::CLOSED && !is_new_tcb) {
      if (metrics) {
        metrics->tcp_connections_reset.fetch_add(1, std::memory_order_relaxed);
        metrics->tcp_connections_closed.fetch_add(1, std::memory_order_relaxed);
      }
      destroy_tcb(tcb);
      return false;
    }

    // ---- Перевооружение таймеров по переходу состояния ----
    if (status != prev_state) {
      switch (status) {
        case StateMachine::ESTABLISHED:
          if (metrics)
            metrics->tcp_connections_established.fetch_add(
                1, std::memory_order_relaxed);
          timer_wheel_.rearm(tcb, TIMEOUT_ESTABLISHED);
          break;
        case StateMachine::FIN_WAIT_1:
        case StateMachine::FIN_WAIT_2:
        case StateMachine::CLOSING:
          timer_wheel_.rearm(tcb, TIMEOUT_FIN_WAIT);
          break;
        case StateMachine::TIME_WAIT:
          timer_wheel_.rearm(tcb, TIMEOUT_TIME_WAIT);
          break;
        case StateMachine::CLOSED:
          if (metrics)
            metrics->tcp_connections_closed.fetch_add(1, std::memory_order_relaxed);
          destroy_tcb(tcb);
          return false;
        default:
          break;
      }
    } else if (status == StateMachine::ESTABLISHED) {
      // Получили данные/ACK в established — keepalive таймер сдвигаем
      timer_wheel_.rearm(tcb, TIMEOUT_ESTABLISHED);
    }

    // ---- Шаг 3: выбор буфера и формирование ответа ----
    SessionKey tx_key = key->reversed();
    uint16_t reply_flags = RTE_TCP_ACK_FLAG;

    bool has_payload_to_send =
        (status == StateMachine::ESTABLISHED) && (tpl_mbuf != nullptr);

    rte_mbuf* reply_mbuf;
    bool is_new_mbuf;

    if (has_payload_to_send) {
      reply_mbuf = tpl_mbuf;  // ожидается, что caller уже сделал clone
      is_new_mbuf = false;
    } else {
      reply_mbuf = tx_mbuf;
      is_new_mbuf = true;
    }

    // ---- Флаги ответа в зависимости от перехода ----
    if (is_new_tcb) {
      reply_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
    } else if (status == StateMachine::CLOSE_WAIT) {
      // Авто-закрытие со стороны генератора: отвечаем ACK сразу,
      // FIN отправим отдельным сегментом по сценарию (не здесь)
      reply_flags = RTE_TCP_ACK_FLAG;
    } else if (status == StateMachine::TIME_WAIT) {
      reply_flags = RTE_TCP_ACK_FLAG;
    }

    fillTcpSegment(tcb, is_new_mbuf, reply_mbuf, &tx_key, reply_flags);

    // ---- Шаг 5: обновление TCB после отправки ----
    if (reply_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG))
      tcb->snd_nxt += 1;
    // payload_len для has_payload_to_send добавляется вызывающим кодом
    // после фактической компоновки данных в reply_mbuf, т.к. размер
    // payload известен только сценарию генератора.

    *out_reply = reply_mbuf;
    return true;
  }

  // ------------------------------------------------------------------
  // process_timers — вызывается периодически (раз в "тик", например
  // каждые 10ms из основного цикла на этом core). Обходит просроченные
  // TCB текущего слота и завершает/ретрансмитит сессии.
  //
  // metrics — массив StreamMetrics для всех streams этого lcore;
  //           индексируется tcb->stream_index, чтобы инкрементировать
  //           tcp_retransmits / tcp_connections_closed без передачи
  //           дополнительных аргументов на каждый TCB.
  //
  // send_cb(tcb, reply_mbuf) — callback для отправки ретрансмита,
  // вызывается только если требуется повтор последнего сегмента.
  // Сигнатура: void(TCB* tcb) — caller сам выделяет mbuf, вызывает
  // fillTcpSegment с нужными флагами (повтор последнего сегмента -
  // SYN+ACK для SYN_RECEIVED, FIN+ACK для FIN_WAIT_1/LAST_ACK и т.д.,
  // используя текущие snd_una/snd_nxt из tcb) и отправляет в tx burst.
  // ------------------------------------------------------------------
  template <typename SendRetransmitCb>
  void process_timers(StreamMetrics* metrics, SendRetransmitCb&& send_cb) {
    TCB* expired = timer_wheel_.tick();

    while (expired != nullptr) {
      TCB* next = expired->next_tcb;
      StreamMetrics* sm = metrics ? &metrics[expired->stream_index] : nullptr;

      switch (expired->session_state) {
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
            // Лимит ретрансмитов превышен — сессия мёртвая
            if (sm)
              sm->tcp_connections_closed.fetch_add(1, std::memory_order_relaxed);
            destroy_tcb(expired);
          }
          break;

        case StateMachine::ESTABLISHED:
          // Idle timeout — закрываем сессию (или keepalive по сценарию)
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
    if (hash_table_ != nullptr)
      rte_hash_free(hash_table_);
    if (mempool_ != nullptr)
      rte_mempool_free(mempool_);
  }
};