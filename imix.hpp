#pragma once

#include <cstdint>
#include <array>

// =====================================================================
// IMIX — Internet Mix, стандартное распределение размеров пакетов.
//
// Классическое соотношение RFC 6985:
//   58.33% × 64  bytes  (7 из 12)
//   33.33% × 512 bytes  (4 из 12)
//    8.33% × 1518 bytes  (1 из 12)
//
// imix_next(idx) возвращает размер фрейма для текущего idx и
// инкрементирует idx (0..11 по кругу).
// =====================================================================

// Таблица из 12 записей (7+4+1)
static constexpr std::array<uint16_t, 12> kImixTable = {
     64,  64,  64,  64,  64,  64,  64,   // 7 × 64
    512, 512, 512, 512,                   // 4 × 512
   1518                                   // 1 × 1518
};

// Размер IP-payload = frame_size - 14 (ETH) - 4 (FCS, если считать)
// Здесь возвращаем полный размер фрейма, вычитание делает caller.
inline uint16_t imix_frame_size(uint8_t& idx) {
    uint16_t sz = kImixTable[idx % 12];
    idx = static_cast<uint8_t>((idx + 1) % 12);
    return sz;
}

// Минимальный/максимальный размер для ограничения frame_size
static constexpr uint16_t kMinFrameSize = 64;
static constexpr uint16_t kMaxFrameSize = 9000; // jumbo frames

// Размер полезной нагрузки UDP/TCP с учётом заголовков
// frame_size = 14 (ETH) + [4 VLAN] + 20 (IP) + 20 (TCP) или 8 (UDP) + payload
inline uint16_t tcp_payload_from_frame(uint16_t frame_size, bool has_vlan) {
    uint16_t hdr = 14 + (has_vlan ? 4 : 0) + 20 + 20;
    return (frame_size > hdr) ? (frame_size - hdr) : 0;
}

inline uint16_t udp_payload_from_frame(uint16_t frame_size, bool has_vlan) {
    uint16_t hdr = 14 + (has_vlan ? 4 : 0) + 20 + 8;
    return (frame_size > hdr) ? (frame_size - hdr) : 0;
}