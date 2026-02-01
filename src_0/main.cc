#include <uvgrtp/lib.hh>

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

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
} // namespace

int main(int argc, char** argv) {
    uvgrtp::context ctx;

    auto sess = ctx.create_session("0.0.0.0");
    auto stream = sess->create_stream(
        5004,
        RTP_FORMAT_H265,
        RCE_RECEIVE_ONLY
    );

    if (stream) {
        (void)stream->configure_ctx(RCC_DYN_PAYLOAD_TYPE, 96);
    }

    const std::string out_path = (argc > 1) ? argv[1] : "nal_dump.bin";
    std::ofstream out(out_path, std::ios::binary);
    if (!out) {
        std::cerr << "Failed to open output file: " << out_path << "\n";
        return 1;
    }

    std::vector<uint8_t> vps_nal;
    std::vector<uint8_t> sps_nal;
    std::vector<uint8_t> pps_nal;

    while (true) {
        auto frame = stream->pull_frame();
        if (frame) {
            // frame->payload -> Annex-B HEVC NAL
            // frame->payload_len
            static std::array<PpsInfo, 64> pps_table{};
            auto nals = find_annexb_nals(frame->payload, frame->payload_len);
            for (const auto& nal : nals) {
                uint8_t nal_type = hevc_nal_type_from_header(&frame->payload[nal.offset], nal.size);
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
                        if (parse_pps_dependent_flag(&frame->payload[nal.offset + 2],
                                                     nal.size - 2,
                                                     pps_id, dep)) {
                            if (pps_id < pps_table.size()) {
                                pps_table[pps_id].valid = true;
                                pps_table[pps_id].dependent_slice_segments_enabled = dep;
                            }
                        }
                        pps_nal.assign(&frame->payload[nal.offset], &frame->payload[nal.offset + nal.size]);
                    }
                } else if (nal_type == 33) { // SPS
                    sps_nal.assign(&frame->payload[nal.offset], &frame->payload[nal.offset + nal.size]);
                } else if (nal_type == 32) { // VPS
                    vps_nal.assign(&frame->payload[nal.offset], &frame->payload[nal.offset + nal.size]);
                } else if (nal_type <= 31) { // VCL
                    if (nal.size > 2) {
                        auto slice_type = parse_slice_type(nal_type,
                                                          &frame->payload[nal.offset + 2],
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
                uint8_t nal_type = hevc_nal_type_from_header(&frame->payload[nal.offset], nal.size);
                bool is_idr = (nal_type == 19 || nal_type == 20);
                if (is_idr && !vps_nal.empty() && !sps_nal.empty() && !pps_nal.empty()) {
                    write_nal_with_len(out, vps_nal.data(), vps_nal.size());
                    write_nal_with_len(out, sps_nal.data(), sps_nal.size());
                    write_nal_with_len(out, pps_nal.data(), pps_nal.size());
                }
                write_nal_with_len(out, &frame->payload[nal.offset], nal.size);
            }

            size_t n = std::min<size_t>(20, frame->payload_len);
            std::cout << "first 20 bytes:";
            std::cout << std::hex << std::setfill('0');
            for (size_t i = 0; i < n; ++i) {
                std::cout << " " << std::setw(2) << static_cast<unsigned int>(frame->payload[i]);
            }
            std::cout << std::dec << "\n";
            uvgrtp::frame::dealloc_frame(frame);
        }
    }
}
