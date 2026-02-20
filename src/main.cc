#include <uvgrtp/lib.hh>

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

// Set to 1 if incoming RTP payloads have an 8-byte timestamp prefix.
#ifndef HAS_TS_PREFIX
#define HAS_TS_PREFIX 0
#endif

// 1 = big-endian, 0 = little-endian
#ifndef TS_BIG_ENDIAN
#define TS_BIG_ENDIAN 1
#endif

namespace {
struct PpsInfo {
    bool valid = false;
    bool dependent_slice_segments_enabled = false;
};

class BitReader {
public:
    explicit BitReader(const std::vector<uint8_t>& data) : data_(data), bit_pos_(0) {}

    bool read_bit(uint8_t& out) {
        if (bit_pos_ >= data_.size() * 8) return false;
        size_t byte_idx = bit_pos_ / 8;
        size_t bit_idx = 7 - (bit_pos_ % 8);
        out = (data_[byte_idx] >> bit_idx) & 0x01;
        ++bit_pos_;
        return true;
    }

    bool read_ue(uint32_t& out) {
        uint32_t zeros = 0;
        uint8_t bit = 0;
        while (true) {
            if (!read_bit(bit)) return false;
            if (bit == 0) {
                ++zeros;
                if (zeros > 31) return false;
            } else {
                break;
            }
        }
        uint32_t value = 0;
        for (uint32_t i = 0; i < zeros; ++i) {
            if (!read_bit(bit)) return false;
            value = (value << 1) | bit;
        }
        out = (1u << zeros) - 1 + value;
        return true;
    }

private:
    const std::vector<uint8_t>& data_;
    size_t bit_pos_;
};

struct NalUnit {
    size_t offset = 0;
    size_t size = 0;
};

std::vector<NalUnit> find_annexb_nals(const uint8_t* data, size_t len) {
    std::vector<NalUnit> out;
    if (!data || len < 3) return out;

    std::vector<size_t> starts;
    for (size_t i = 0; i + 3 < len; ++i) {
        if (data[i] == 0x00 && data[i + 1] == 0x00 && data[i + 2] == 0x01) {
            starts.push_back(i + 3);
            continue;
        }
        if (i + 4 < len && data[i] == 0x00 && data[i + 1] == 0x00 && data[i + 2] == 0x00 &&
            data[i + 3] == 0x01) {
            starts.push_back(i + 4);
        }
    }

    if (starts.empty()) {
        out.push_back({0, len});
        return out;
    }

    for (size_t i = 0; i < starts.size(); ++i) {
        size_t start = starts[i];
        size_t end = (i + 1 < starts.size()) ? starts[i + 1] : len;
        if (start < end) {
            out.push_back({start, end - start});
        }
    }
    return out;
}

uint8_t hevc_nal_type_from_header(const uint8_t* nal, size_t len) {
    if (!nal || len < 2) return 0xff;
    return (nal[0] >> 1) & 0x3f;
}

std::vector<uint8_t> nal_to_rbsp(const uint8_t* nal_payload, size_t len) {
    std::vector<uint8_t> rbsp;
    rbsp.reserve(len);
    int zero_count = 0;
    for (size_t i = 0; i < len; ++i) {
        uint8_t b = nal_payload[i];
        if (zero_count == 2 && b == 0x03) {
            zero_count = 0;
            continue;
        }
        rbsp.push_back(b);
        if (b == 0x00) {
            ++zero_count;
        } else {
            zero_count = 0;
        }
    }
    return rbsp;
}

bool parse_pps_dependent_flag(const uint8_t* nal_payload, size_t len, uint32_t& pps_id, bool& dep_flag) {
    auto rbsp = nal_to_rbsp(nal_payload, len);
    BitReader br(rbsp);
    if (!br.read_ue(pps_id)) return false;
    uint32_t sps_id = 0;
    if (!br.read_ue(sps_id)) return false;
    uint8_t bit = 0;
    if (!br.read_bit(bit)) return false;
    dep_flag = (bit != 0);
    return true;
}

enum class SliceType { P, B, I, Unknown, Dependent, NotFirst };

SliceType parse_slice_type(uint8_t nal_type, const uint8_t* nal_payload, size_t len,
                           const std::array<PpsInfo, 64>& pps_table) {
    auto rbsp = nal_to_rbsp(nal_payload, len);
    BitReader br(rbsp);

    uint8_t bit = 0;
    if (!br.read_bit(bit)) return SliceType::Unknown;
    bool first_slice_segment_in_pic_flag = (bit != 0);

    // IRAP pictures have an extra flag before PPS id
    if (nal_type >= 16 && nal_type <= 23) {
        if (!br.read_bit(bit)) return SliceType::Unknown; // no_output_of_prior_pics_flag
    }

    uint32_t pps_id = 0;
    if (!br.read_ue(pps_id)) return SliceType::Unknown;

    if (!first_slice_segment_in_pic_flag) {
        // slice_segment_address length depends on SPS; skip parsing to avoid misalignment
        return SliceType::NotFirst;
    }

    bool dependent_slice_segment_flag = false;
    if (pps_id < pps_table.size() && pps_table[pps_id].valid &&
        pps_table[pps_id].dependent_slice_segments_enabled) {
        if (!br.read_bit(bit)) return SliceType::Unknown;
        dependent_slice_segment_flag = (bit != 0);
    }

    if (dependent_slice_segment_flag) {
        return SliceType::Dependent;
    }

    uint32_t slice_type = 0;
    if (!br.read_ue(slice_type)) return SliceType::Unknown;
    switch (slice_type) {
        case 0: return SliceType::P;
        case 1: return SliceType::B;
        case 2: return SliceType::I;
        default: return SliceType::Unknown;
    }
}

std::string hevc_nal_type_name(uint8_t t) {
    switch (t) {
        case 32: return "VPS";
        case 33: return "SPS";
        case 34: return "PPS";
        case 19: return "IDR_W_RADL";
        case 20: return "IDR_N_LP";
        case 21: return "CRA";
        default:
            if (t <= 31) return "VCL_SLICE";
            return "OTHER";
    }
}

void write_u32_be(std::ofstream& out, uint32_t v) {
    uint8_t b[4] = {
        static_cast<uint8_t>((v >> 24) & 0xff),
        static_cast<uint8_t>((v >> 16) & 0xff),
        static_cast<uint8_t>((v >> 8) & 0xff),
        static_cast<uint8_t>(v & 0xff),
    };
    out.write(reinterpret_cast<const char*>(b), 4);
}

void write_nal_with_len(std::ofstream& out, const uint8_t* nal, size_t nal_size) {
    if (!nal || nal_size == 0) {
        return;
    }
    const uint8_t start_code[4] = {0x00, 0x00, 0x00, 0x01};
    uint32_t total_size = static_cast<uint32_t>(nal_size + 4);
    write_u32_be(out, total_size);
    out.write(reinterpret_cast<const char*>(start_code), 4);
    out.write(reinterpret_cast<const char*>(nal), static_cast<std::streamsize>(nal_size));
}

uint64_t read_ts_u64(const uint8_t* p) {
    uint64_t v = 0;
#if TS_BIG_ENDIAN
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | static_cast<uint64_t>(p[i]);
    }
#else
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | static_cast<uint64_t>(p[i]);
    }
#endif
    return v;
}

int create_rtcp_socket(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        std::cerr << "Failed to create RTCP socket on port " << port << ": "
                  << std::strerror(errno) << "\n";
        return -1;
    }

    int opt = 1;
    (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "Failed to bind RTCP socket on port " << port << ": "
                  << std::strerror(errno) << "\n";
        ::close(fd);
        return -1;
    }

    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        (void)::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    return fd;
}

uint16_t read_be16(const uint8_t* p);
uint32_t read_be32(const uint8_t* p);

void print_hex_preview(const uint8_t* data, size_t len, size_t max_bytes = 24) {
    if (!data || len == 0) {
        std::cout << "(empty)";
        return;
    }

    size_t n = std::min(len, max_bytes);
    std::cout << std::hex << std::setfill('0');
    for (size_t i = 0; i < n; ++i) {
        std::cout << std::setw(2) << static_cast<unsigned int>(data[i]);
        if (i + 1 < n) {
            std::cout << " ";
        }
    }
    if (len > n) {
        std::cout << " ...";
    }
    std::cout << std::dec;
}

void log_rtp_ext_rfc8285_one_byte(const uint8_t* data, size_t len) {
    std::cout << "[RTP][EXT][8285-one-byte] entries:\n";
    size_t off = 0;
    size_t idx = 0;
    while (off < len) {
        uint8_t b = data[off];
        if (b == 0) {
            ++off;
            continue;
        }

        uint8_t id = (b >> 4) & 0x0f;
        uint8_t l = (b & 0x0f) + 1; // encoded as len-1
        ++off;

        if (id == 15) {
            std::cout << "[RTP][EXT][8285-one-byte]  id=15(reserved), stop\n";
            return;
        }

        if (off + l > len) {
            std::cout << "[RTP][EXT][8285-one-byte]  malformed: id=" << static_cast<unsigned int>(id)
                      << " len=" << static_cast<unsigned int>(l)
                      << " remain=" << (len - off) << "\n";
            return;
        }

        std::cout << "[RTP][EXT][8285-one-byte]  [" << idx
                  << "] id=" << static_cast<unsigned int>(id)
                  << " len=" << static_cast<unsigned int>(l)
                  << " data=";
        print_hex_preview(&data[off], l, 16);
        std::cout << "\n";

        off += l;
        ++idx;
    }
}

void log_rtp_ext_rfc8285_two_byte(const uint8_t* data, size_t len, uint8_t appbits) {
    std::cout << "[RTP][EXT][8285-two-byte] appbits=" << static_cast<unsigned int>(appbits) << " entries:\n";
    size_t off = 0;
    size_t idx = 0;
    while (off < len) {
        if (data[off] == 0) {
            ++off;
            continue;
        }
        if (off + 2 > len) {
            std::cout << "[RTP][EXT][8285-two-byte]  malformed header remain=" << (len - off) << "\n";
            return;
        }

        uint8_t id = data[off];
        uint8_t l = data[off + 1];
        off += 2;

        if (off + l > len) {
            std::cout << "[RTP][EXT][8285-two-byte]  malformed: id=" << static_cast<unsigned int>(id)
                      << " len=" << static_cast<unsigned int>(l)
                      << " remain=" << (len - off) << "\n";
            return;
        }

        std::cout << "[RTP][EXT][8285-two-byte]  [" << idx
                  << "] id=" << static_cast<unsigned int>(id)
                  << " len=" << static_cast<unsigned int>(l)
                  << " data=";
        print_hex_preview(&data[off], l, 16);
        std::cout << "\n";

        off += l;
        ++idx;
    }
}

void log_rtp_extension(const uvgrtp::frame::rtp_frame* frame) {
    if (!frame || !frame->ext) {
        return;
    }

    const uint16_t profile = frame->ext->type;
    const size_t ext_len = frame->ext->len;
    const uint8_t* ext_data = frame->ext->data;

    std::cout << "[RTP][EXT] profile=0x"
              << std::hex << std::setw(4) << std::setfill('0') << profile
              << std::dec << " len=" << ext_len << " bytes\n";

    if (!ext_data || ext_len == 0) {
        std::cout << "[RTP][EXT] empty\n";
        return;
    }

    if (profile == 0xBEDE) {
        log_rtp_ext_rfc8285_one_byte(ext_data, ext_len);
        return;
    }

    if ((profile & 0xFFF0) == 0x1000) {
        uint8_t appbits = static_cast<uint8_t>(profile & 0x000f);
        log_rtp_ext_rfc8285_two_byte(ext_data, ext_len, appbits);
        return;
    }

    size_t words = ext_len / 4;
    size_t rem = ext_len % 4;
    std::cout << "[RTP][EXT][3550] words=" << words << " rem=" << rem << "\n";

    const size_t max_words_to_log = std::min<size_t>(words, 8);
    for (size_t i = 0; i < max_words_to_log; ++i) {
        uint32_t w = read_be32(&ext_data[i * 4]);
        std::cout << "[RTP][EXT][3550]  word[" << i << "]=0x"
                  << std::hex << std::setw(8) << std::setfill('0') << w
                  << std::dec << "\n";
    }
    if (words > max_words_to_log) {
        std::cout << "[RTP][EXT][3550]  ... (" << (words - max_words_to_log) << " more words)\n";
    }
    if (rem > 0) {
        std::cout << "[RTP][EXT][3550]  tail=";
        print_hex_preview(&ext_data[words * 4], rem, rem);
        std::cout << "\n";
    }
}

uint16_t read_be16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t read_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

const char* rtcp_pt_name(uint8_t pt) {
    switch (pt) {
        case 200: return "SR";
        case 201: return "RR";
        case 202: return "SDES";
        case 203: return "BYE";
        case 204: return "APP";
        case 205: return "RTPFB";
        case 206: return "PSFB";
        default: return "UNKNOWN";
    }
}

void log_rtcp_packet_details(const uint8_t* pkt, size_t pkt_len, size_t idx) {
    if (pkt_len < 4) {
        std::cout << "[RTCP]   [" << idx << "] short packet len=" << pkt_len << "\n";
        return;
    }

    uint8_t v = (pkt[0] >> 6) & 0x03;
    bool padding = (pkt[0] & 0x20) != 0;
    uint8_t count_or_fmt = pkt[0] & 0x1f;
    uint8_t pt = pkt[1];

    std::cout << "[RTCP]   [" << idx << "] "
              << rtcp_pt_name(pt) << "(" << static_cast<unsigned int>(pt) << ")"
              << " v=" << static_cast<unsigned int>(v)
              << " p=" << (padding ? 1 : 0)
              << " count/fmt=" << static_cast<unsigned int>(count_or_fmt)
              << " len=" << pkt_len << "\n";

    if (pt == 200) { // SR
        if (pkt_len >= 28) {
            uint32_t sender_ssrc = read_be32(&pkt[4]);
            uint64_t ntp = (static_cast<uint64_t>(read_be32(&pkt[8])) << 32) | read_be32(&pkt[12]);
            uint32_t rtp_ts = read_be32(&pkt[16]);
            uint32_t pkt_count = read_be32(&pkt[20]);
            uint32_t oct_count = read_be32(&pkt[24]);
            std::cout << "[RTCP]     sender_ssrc=0x" << std::hex << sender_ssrc
                      << " ntp=0x" << ntp
                      << " rtp_ts=" << std::dec << rtp_ts
                      << " sender_pkts=" << pkt_count
                      << " sender_octets=" << oct_count
                      << "\n";
        }
        return;
    }

    if (pt == 201) { // RR
        if (pkt_len >= 8) {
            uint32_t sender_ssrc = read_be32(&pkt[4]);
            std::cout << "[RTCP]     sender_ssrc=0x" << std::hex << sender_ssrc
                      << std::dec << " report_count=" << static_cast<unsigned int>(count_or_fmt)
                      << "\n";
        }
        return;
    }

    if (pt == 202) { // SDES
        if (pkt_len >= 8) {
            uint32_t first_ssrc = read_be32(&pkt[4]);
            std::cout << "[RTCP]     chunks=" << static_cast<unsigned int>(count_or_fmt)
                      << " first_ssrc=0x" << std::hex << first_ssrc << std::dec << "\n";
        }
        return;
    }

    if (pt == 203) { // BYE
        if (pkt_len >= 8) {
            uint32_t first_ssrc = read_be32(&pkt[4]);
            std::cout << "[RTCP]     sources=" << static_cast<unsigned int>(count_or_fmt)
                      << " first_ssrc=0x" << std::hex << first_ssrc << std::dec << "\n";
        }
        return;
    }

    if (pt == 204) { // APP
        if (pkt_len >= 12) {
            uint32_t ssrc = read_be32(&pkt[4]);
            char name[5] = {
                static_cast<char>(pkt[8]),
                static_cast<char>(pkt[9]),
                static_cast<char>(pkt[10]),
                static_cast<char>(pkt[11]),
                '\0'
            };
            std::cout << "[RTCP]     subtype=" << static_cast<unsigned int>(count_or_fmt)
                      << " ssrc=0x" << std::hex << ssrc << std::dec
                      << " name=" << name << "\n";
        }
        return;
    }

    if (pt == 205 || pt == 206) { // RTPFB / PSFB
        if (pkt_len >= 12) {
            uint32_t sender_ssrc = read_be32(&pkt[4]);
            uint32_t media_ssrc = read_be32(&pkt[8]);
            std::cout << "[RTCP]     fmt=" << static_cast<unsigned int>(count_or_fmt)
                      << " sender_ssrc=0x" << std::hex << sender_ssrc
                      << " media_ssrc=0x" << media_ssrc
                      << std::dec << "\n";
        }
    }
}

void log_rtcp_compound(const uint8_t* data, size_t len) {
    size_t offset = 0;
    size_t index = 0;
    while (offset + 4 <= len) {
        uint16_t length_words = read_be16(&data[offset + 2]);
        size_t pkt_len = static_cast<size_t>(length_words + 1u) * 4u;
        if (pkt_len == 0 || offset + pkt_len > len) {
            std::cout << "[RTCP]   [" << index << "] invalid length, remain=" << (len - offset)
                      << " declared=" << pkt_len << "\n";
            return;
        }
        log_rtcp_packet_details(&data[offset], pkt_len, index);
        offset += pkt_len;
        ++index;
    }

    if (offset != len) {
        std::cout << "[RTCP]   trailing_bytes=" << (len - offset) << "\n";
    }
}

void drain_rtcp_socket(int fd) {
    if (fd < 0) {
        return;
    }

    std::array<uint8_t, 2048> buf{};
    while (true) {
        sockaddr_in src{};
        socklen_t src_len = sizeof(src);
        ssize_t n = ::recvfrom(fd,
                               reinterpret_cast<char*>(buf.data()),
                               buf.size(),
                               0,
                               reinterpret_cast<sockaddr*>(&src),
                               &src_len);
        if (n <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            std::cerr << "RTCP recvfrom failed: " << std::strerror(errno) << "\n";
            return;
        }

        char ip[INET_ADDRSTRLEN] = {0};
        const char* ip_str = ::inet_ntop(AF_INET, &src.sin_addr, ip, sizeof(ip));
        if (!ip_str) {
            ip_str = "unknown";
        }

        std::cout << "[RTCP] recv: " << n
                  << " bytes from " << ip_str << ":" << ntohs(src.sin_port)
                  << "\n";
        log_rtcp_compound(buf.data(), static_cast<size_t>(n));

        const size_t dump_len = std::min<size_t>(static_cast<size_t>(n), 48);
        std::cout << "[RTCP] hex:";
        std::cout << std::hex << std::setfill('0');
        for (size_t i = 0; i < dump_len; ++i) {
            std::cout << " " << std::setw(2) << static_cast<unsigned int>(buf[i]);
        }
        if (static_cast<size_t>(n) > dump_len) {
            std::cout << " ...";
        }
        std::cout << std::dec << "\n";
    }
}
} // namespace

int main(int argc, char** argv) {
    uvgrtp::context ctx;

    constexpr uint16_t kRtpPort = 53551;
    constexpr uint16_t kRtcpPort = kRtpPort + 1;

    auto sess = ctx.create_session("0.0.0.0");
    auto stream = sess->create_stream(
        kRtpPort,
        RTP_FORMAT_H265,
        RCE_RECEIVE_ONLY
    );

    if (stream) {
        (void)stream->configure_ctx(RCC_DYN_PAYLOAD_TYPE, 96);
    } else {
        std::cerr << "Failed to create RTP stream on port " << kRtpPort << "\n";
        return 1;
    }

    int rtcp_fd = create_rtcp_socket(kRtcpPort);
    if (rtcp_fd >= 0) {
        std::cout << "Listening RTCP on UDP port " << kRtcpPort << "\n";
    }

    std::string out_path = (argc > 1) ? argv[1] : "nal_dump.bin";
    std::ofstream out(out_path, std::ios::binary);
    if (!out) {
        std::cerr << "Failed to open output file: " << out_path << "\n";
        return 1;
    }

    std::vector<uint8_t> vps_nal;
    std::vector<uint8_t> sps_nal;
    std::vector<uint8_t> pps_nal;

    while (true) {
        auto frame = stream->pull_frame(20);
        drain_rtcp_socket(rtcp_fd);
        if (frame) {
            if (frame->header.ext && frame->ext) {
                log_rtp_extension(frame);
            }
            // frame->payload -> Annex-B HEVC NAL
            // frame->payload_len
            const uint8_t* payload = frame->payload;
            size_t payload_len = frame->payload_len;
#if HAS_TS_PREFIX
            {
                if (payload_len <= 8) {
                    uvgrtp::frame::dealloc_frame(frame);
                    continue;
                }
                uint64_t ts = read_ts_u64(payload);
                std::cout << "timestamp: " << ts << " (0x"
                          << std::hex << std::setw(16) << std::setfill('0') << ts
                          << std::dec << ")\n";
                payload += 8;
                payload_len -= 8;
            }
#endif

            static std::array<PpsInfo, 64> pps_table{};
            auto nals = find_annexb_nals(payload, payload_len);
            for (const auto& nal : nals) {
                uint8_t nal_type = hevc_nal_type_from_header(&payload[nal.offset], nal.size);
                if (nal_type != 0xff) {
                    std::cout << "NAL type: " << hevc_nal_type_name(nal_type)
                              << " (" << static_cast<unsigned int>(nal_type) << ")\n";
                } else {
                    std::cout << "NAL type: unknown\n";
                }

                if (nal_type == 34) { // PPS
                    if (nal.size > 2) {
                        uint32_t pps_id = 0;
                        bool dep = false;
                        if (parse_pps_dependent_flag(&payload[nal.offset + 2],
                                                     nal.size - 2,
                                                     pps_id, dep)) {
                            if (pps_id < pps_table.size()) {
                                pps_table[pps_id].valid = true;
                                pps_table[pps_id].dependent_slice_segments_enabled = dep;
                            }
                        }
                        pps_nal.assign(&payload[nal.offset], &payload[nal.offset + nal.size]);
                    }
                } else if (nal_type == 33) { // SPS
                    sps_nal.assign(&payload[nal.offset], &payload[nal.offset + nal.size]);
                } else if (nal_type == 32) { // VPS
                    vps_nal.assign(&payload[nal.offset], &payload[nal.offset + nal.size]);
                } else if (nal_type <= 31) { // VCL
                    if (nal.size > 2) {
                        auto slice_type = parse_slice_type(nal_type,
                                                          &payload[nal.offset + 2],
                                                          nal.size - 2,
                                                          pps_table);
                    switch (slice_type) {
                        case SliceType::I: std::cout << "Slice type: I\n"; break;
                        case SliceType::P: std::cout << "Slice type: P\n"; break;
                        case SliceType::B: std::cout << "Slice type: B\n"; break;
                        case SliceType::Dependent: std::cout << "Slice type: dependent\n"; break;
                        case SliceType::NotFirst: std::cout << "Slice type: not-first\n"; break;
                        default: std::cout << "Slice type: unknown\n"; break;
                    }
                    }
                }
            }

            for (const auto& nal : nals) {
                if (nal.size == 0) {
                    continue;
                }
                uint8_t nal_type = hevc_nal_type_from_header(&payload[nal.offset], nal.size);
                bool is_idr = (nal_type == 19 || nal_type == 20);
                if (is_idr && !vps_nal.empty() && !sps_nal.empty() && !pps_nal.empty()) {
                    write_nal_with_len(out, vps_nal.data(), vps_nal.size());
                    write_nal_with_len(out, sps_nal.data(), sps_nal.size());
                    write_nal_with_len(out, pps_nal.data(), pps_nal.size());
                }
                write_nal_with_len(out, &payload[nal.offset], nal.size);
            }

            size_t n = std::min<size_t>(20, payload_len);
            std::cout << "first 20 bytes:";
            std::cout << std::hex << std::setfill('0');
            for (size_t i = 0; i < n; ++i) {
                std::cout << " " << std::setw(2) << static_cast<unsigned int>(payload[i]);
            }
            std::cout << std::dec << "\n";
            uvgrtp::frame::dealloc_frame(frame);
        }
    }
}

