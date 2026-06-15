#pragma once

#include <cstdint>

#include <rte_random.h>

#include "test_instance.hpp"

// =====================================================================
// IMIX - стандартное распределение размеров фреймов, имитирующее
// интернет-трафик (по аналогии с RFC 6985 / распространённым
// промышленным IMIX). Используется при FrameMode::IMIX.
//
// Распределение (по числу пакетов):
//   7 пакетов x 64 байта   (~58%  по количеству, ~6% трафика)
//   4 пакета  x 594 байта
//   1 пакет   x 1518 байт
//
// Итого цикл из 12 пакетов. Возвращает следующий размер по
// детерминированному циклу (per-stream счётчик) либо случайно
// (по весам) - здесь реализован детерминированный цикл для
// предсказуемости теста.
// =====================================================================
class ImixGenerator {
 private:
  static constexpr uint16_t kPattern[12] = {
      64, 64, 64, 64, 64, 64, 64,   // 7x64
      594, 594, 594, 594,           // 4x594
      1518                            // 1x1518
  };
  uint32_t idx_ = 0;

 public:
  uint16_t next() {
    uint16_t sz = kPattern[idx_];
    idx_ = (idx_ + 1) % 12;
    return sz;
  }

  void reset() { idx_ = 0; }
};

// =====================================================================
// next_frame_size - выбирает размер фрейма для следующего сегмента
// согласно FrameMode stream-а.
//
// imix_state - per-stream состояние генератора IMIX (хранится в
// StreamRuntimeState, см. test_instance.hpp).
// =====================================================================
inline uint16_t next_frame_size(const StreamConfig& cfg,
                                 ImixGenerator& imix_state) {
  if (cfg.frame_mode == 1 /* IMIX */)
    return imix_state.next();
  return cfg.frame_size;  // FIX
}