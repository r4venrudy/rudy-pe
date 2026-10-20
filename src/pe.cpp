#include "rudy_pe/pe.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <iomanip>
#include <limits>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>

namespace rudy_pe {
namespace {

constexpr std::size_t kMaxSections = 96;
constexpr std::size_t kMaxImports = 10000;
constexpr std::size_t kMaxDescriptors = 4096;
constexpr std::size_t kMaxThunks = 65536;
constexpr std::size_t kMaxNameBytes = 512;

class Reader {
  public:
    explicit Reader(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}
    bool has(std::uint64_t at, std::uint64_t n) const {
        return at <= bytes_.size() && n <= bytes_.size() - static_cast<std::size_t>(at);
    }
    std::uint8_t u8(std::uint64_t at) const {
        require(at, 1);
        return bytes_[static_cast<std::size_t>(at)];
    }
    std::uint16_t u16(std::uint64_t at) const {
        require(at, 2);
        const auto p = static_cast<std::size_t>(at);
        return static_cast<std::uint16_t>(bytes_[p]) |
               static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes_[p + 1]) << 8U);
    }
    std::uint32_t u32(std::uint64_t at) const {
        require(at, 4);
        const auto p = static_cast<std::size_t>(at);
        return static_cast<std::uint32_t>(bytes_[p]) |
               (static_cast<std::uint32_t>(bytes_[p + 1]) << 8U) |
               (static_cast<std::uint32_t>(bytes_[p + 2]) << 16U) |
               (static_cast<std::uint32_t>(bytes_[p + 3]) << 24U);
    }
    std::uint64_t u64(std::uint64_t at) const {
        return static_cast<std::uint64_t>(u32(at)) |
               (static_cast<std::uint64_t>(u32(at + 4U)) << 32U);
    }
    std::string ascii(std::uint64_t at, std::size_t limit) const {
        std::string s;
        for (std::size_t i = 0; i < limit; ++i) {
            if (!has(at + i, 1)) throw ParseError("string extends beyond file");
            const auto c = u8(at + i);
            if (c == 0) return s;
            if (c < 0x20U || c > 0x7eU) throw ParseError("non-ASCII byte in PE name");
            s.push_back(static_cast<char>(c));
        }
        throw ParseError("unterminated PE name");
    }
    std::span<const std::uint8_t> bytes() const { return bytes_; }
  private:
    void require(std::uint64_t at, std::uint64_t n) const {
        if (!has(at, n)) throw ParseError("truncated PE structure");
    }
    std::span<const std::uint8_t> bytes_;
};

struct Directory { std::uint32_t address{}; std::uint32_t size{}; };
struct ParsedSection { Section value; std::uint64_t virtual_end{}; std::uint64_t raw_end{}; };

std::string section_name(const Reader& r, std::uint64_t at) {
    std::string name;
    for (std::size_t i = 0; i < 8; ++i) {
        const auto c = r.u8(at + i);
        if (c == 0) break;
        name.push_back(c >= 0x20U && c <= 0x7eU ? static_cast<char>(c) : '.');
    }
    return name.empty() ? "<unnamed>" : name;
}

std::string machine_name(std::uint16_t value) {
    switch (value) {
    case 0x014c: return "I386";
    case 0x01c0: return "ARM";
    case 0x01c4: return "ARMNT";
    case 0x0200: return "IA64";
    case 0x8664: return "AMD64";
    case 0xaa64: return "ARM64";
    case 0xa641: return "ARM64EC";
    case 0x5032: return "RISC-V 32";
    case 0x5064: return "RISC-V 64";
    default: return "Unknown";
    }
}

std::string escape(std::string_view value) {
    std::ostringstream out;
    for (const char raw : value) {
        const auto c = static_cast<unsigned char>(raw);
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20U) {
                out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                    << static_cast<unsigned>(c) << std::dec;
            } else out << static_cast<char>(c);
        }
    }
    return out.str();
}

std::string hex(std::uint64_t value, unsigned width = 0) {
    std::ostringstream out;
    out << "0x" << std::uppercase << std::hex << std::setfill('0')
        << std::setw(static_cast<int>(width)) << value;
    return out.str();
}

double entropy(std::span<const std::uint8_t> data) {
    if (data.empty()) return 0.0;
    std::array<std::uint64_t, 256> counts{};
    for (const auto byte : data) ++counts[byte];
    const double total = static_cast<double>(data.size());
    double result = 0.0;
    for (const auto count : counts) {
        if (count == 0) continue;
        const double p = static_cast<double>(count) / total;
        result -= p * std::log2(p);
    }
    return result;
}

void add_finding(Report& report, std::string code, Severity severity, std::string message,
                 std::string section = {}) {
    report.findings.push_back({std::move(code), severity, std::move(message), std::move(section)});
}

class Parser {
  public:
    explicit Parser(std::span<const std::uint8_t> bytes) : reader_(bytes) {
        report_.file_size = bytes.size();
    }
    Report run() {
        headers();
        sections();
        section_findings();
        certificates();
        imports();
        exports();
        entrypoint();
        return std::move(report_);
    }
  private:
    Reader reader_;
    Report report_;
    std::vector<ParsedSection> sections_;
    std::vector<Directory> directories_;
    std::uint32_t size_of_headers_{};
    std::uint32_t import_rva_{};
    std::uint32_t import_size_{};
    std::uint32_t export_rva_{};
    std::uint32_t export_size_{};
    std::uint32_t certificate_offset_{};

    Directory directory(std::size_t i) const {
        return i < directories_.size() ? directories_[i] : Directory{};
    }
    std::optional<std::uint64_t> rva_offset(std::uint64_t rva, std::uint64_t length) const {
        if (rva < size_of_headers_) return reader_.has(rva, length) ? std::optional{rva} : std::nullopt;
        const ParsedSection* match = nullptr;
        for (const auto& s : sections_) {
            const std::uint64_t extent = std::max(s.value.virtual_size, s.value.raw_size);
            const std::uint64_t start = s.value.virtual_address;
            if (rva >= start && rva - start < extent) {
                if (match != nullptr) return std::nullopt;
                match = &s;
            }
        }
        if (match == nullptr) return std::nullopt;
        const std::uint64_t delta = rva - match->value.virtual_address;
        if (delta > match->value.raw_size || length > match->value.raw_size - delta) return std::nullopt;
        const std::uint64_t at = static_cast<std::uint64_t>(match->value.raw_offset) + delta;
        return reader_.has(at, length) ? std::optional{at} : std::nullopt;
    }
    std::optional<std::uint64_t> directory_offset(std::uint32_t rva, std::uint32_t size,
                                                  std::string_view label) {
        const auto at = rva_offset(rva, size == 0 ? 1U : size);
        if (!at) add_finding(report_, "directory-unmapped", Severity::medium,
                             std::string(label) + " directory does not map to unambiguous file bytes");
        return at;
    }

    void headers() {
        if (reader_.bytes().size() < 64) throw ParseError("file is too small for an MS-DOS header");
        if (reader_.u16(0) != 0x5a4d) throw ParseError("missing MZ signature");
        const std::uint32_t pe = reader_.u32(0x3c);
        if (!reader_.has(pe, 24) || reader_.u32(pe) != 0x00004550)
            throw ParseError("missing or truncated PE signature/header");
        const std::uint64_t coff = static_cast<std::uint64_t>(pe) + 4U;
        report_.machine_code = reader_.u16(coff);
        report_.machine = machine_name(report_.machine_code);
        const auto count = reader_.u16(coff + 2U);
        const auto optional_size = reader_.u16(coff + 16U);
        report_.is_dll = (reader_.u16(coff + 18U) & 0x2000U) != 0;
        const std::uint64_t optional = coff + 20U;
        if (!reader_.has(optional, optional_size)) throw ParseError("optional header extends beyond file");
        if (optional_size < 72U) throw ParseError("optional header is too short");
        const auto magic = reader_.u16(optional);
        std::uint32_t count_at = 0;
        std::uint32_t directories_at = 0;
        if (magic == 0x10bU) {
            report_.bitness = 32;
            count_at = 92;
            directories_at = 96;
        } else if (magic == 0x20bU) {
            report_.bitness = 64;
            count_at = 108;
            directories_at = 112;
        } else throw ParseError("unsupported optional-header magic");
        if (optional_size < count_at + 4U) throw ParseError("optional header is missing required fields");
        report_.entrypoint_rva = reader_.u32(optional + 16U);
        const auto size_of_image = reader_.u32(optional + 56U);
        size_of_headers_ = reader_.u32(optional + 60U);
        report_.subsystem = reader_.u16(optional + 68U);
        if (size_of_image == 0)
            add_finding(report_, "empty-image-size", Severity::medium, "SizeOfImage is zero");
        if (size_of_headers_ > reader_.bytes().size())
            add_finding(report_, "headers-out-of-file", Severity::high, "SizeOfHeaders exceeds file size");
        if (count > kMaxSections) throw ParseError("section count exceeds safe limit (96)");
        if (count == 0) add_finding(report_, "no-sections", Severity::medium, "image declares no sections");

        const std::uint32_t declared = reader_.u32(optional + count_at);
        const std::uint32_t available = (optional_size - directories_at) / 8U;
        if (declared > available)
            add_finding(report_, "truncated-directory-table", Severity::medium,
                        "data-directory count exceeds bytes available in optional header");
        const auto directory_count = std::min(declared, available);
        directories_.reserve(directory_count);
        for (std::uint32_t i = 0; i < directory_count; ++i) {
            const auto at = optional + directories_at + static_cast<std::uint64_t>(i) * 8U;
            directories_.push_back({reader_.u32(at), reader_.u32(at + 4U)});
        }
        const auto e = directory(0);
        export_rva_ = e.address;
        export_size_ = e.size;
        const auto i = directory(1);
        import_rva_ = i.address;
        import_size_ = i.size;
        const auto c = directory(4);
        certificate_offset_ = c.address;
        report_.certificate_table_size = c.size;
    }

    void sections() {
        const std::uint64_t pe = reader_.u32(0x3c);
        const std::uint64_t coff = pe + 4U;
        const auto count = reader_.u16(coff + 2U);
        const auto optional_size = reader_.u16(coff + 16U);
        const std::uint64_t table = coff + 20U + optional_size;
        if (!reader_.has(table, static_cast<std::uint64_t>(count) * 40U))
            throw ParseError("section table extends beyond file");
        sections_.reserve(count);
        report_.sections.reserve(count);
        for (std::uint16_t i = 0; i < count; ++i) {
            const std::uint64_t at = table + static_cast<std::uint64_t>(i) * 40U;
            Section s;
            s.name = section_name(reader_, at);
            s.virtual_size = reader_.u32(at + 8U);
            s.virtual_address = reader_.u32(at + 12U);
            s.raw_size = reader_.u32(at + 16U);
            s.raw_offset = reader_.u32(at + 20U);
            s.characteristics = reader_.u32(at + 36U);
            const std::uint64_t raw_end = static_cast<std::uint64_t>(s.raw_offset) + s.raw_size;
            const std::uint64_t virtual_end = static_cast<std::uint64_t>(s.virtual_address) +
                std::max(s.virtual_size, s.raw_size);
            s.raw_range_valid = reader_.has(s.raw_offset, s.raw_size);
            if (s.raw_size != 0 && !s.raw_range_valid)
                add_finding(report_, "section-raw-out-of-file", Severity::error,
                            "section raw range exceeds file size", s.name);
            if (s.raw_size != 0 && s.raw_offset < size_of_headers_)
                add_finding(report_, "section-overlaps-headers", Severity::high,
                            "section raw data begins inside PE headers", s.name);
            if ((s.characteristics & 0xa0000000U) == 0xa0000000U)
                add_finding(report_, "section-writable-executable", Severity::high,
                            "section is both writable and executable", s.name);
            if (s.raw_range_valid && s.raw_size != 0) {
                const auto begin = reader_.bytes().begin() + static_cast<std::ptrdiff_t>(s.raw_offset);
                s.entropy = entropy(std::span<const std::uint8_t>(begin, s.raw_size));
                if (s.raw_size >= 256U && s.entropy >= 7.2)
                    add_finding(report_, "section-high-entropy", Severity::low,
                                "high byte entropy; compression or packing is possible", s.name);
            }
            sections_.push_back({s, virtual_end, raw_end});
            report_.sections.push_back(s);
        }
    }

    void section_findings() {
        std::set<std::string> names;
        std::uint64_t image_end = std::min<std::uint64_t>(size_of_headers_, reader_.bytes().size());
        std::vector<const ParsedSection*> raw;
        std::vector<const ParsedSection*> virt;
        for (const auto& s : sections_) {
            if (!names.insert(s.value.name).second)
                add_finding(report_, "duplicate-section-name", Severity::low,
                            "section name is duplicated", s.value.name);
            if (s.value.raw_range_valid && s.value.raw_size != 0) {
                image_end = std::max(image_end, s.raw_end);
                raw.push_back(&s);
            }
            if (s.virtual_end > s.value.virtual_address) virt.push_back(&s);
        }
        std::sort(raw.begin(), raw.end(), [](const auto* a, const auto* b) {
            return a->value.raw_offset < b->value.raw_offset;
        });
        std::uint64_t raw_high_water = raw.empty() ? 0 : raw.front()->raw_end;
        for (std::size_t i = 1; i < raw.size(); ++i) {
            if (raw[i]->value.raw_offset < raw_high_water)
                add_finding(report_, "section-raw-overlap", Severity::high,
                            "section raw ranges overlap", raw[i]->value.name);
            raw_high_water = std::max(raw_high_water, raw[i]->raw_end);
        }
        std::sort(virt.begin(), virt.end(), [](const auto* a, const auto* b) {
            return a->value.virtual_address < b->value.virtual_address;
        });
        std::uint64_t virtual_high_water = virt.empty() ? 0 : virt.front()->virtual_end;
        for (std::size_t i = 1; i < virt.size(); ++i) {
            if (virt[i]->value.virtual_address < virtual_high_water)
                add_finding(report_, "section-virtual-overlap", Severity::medium,
                            "section virtual ranges overlap", virt[i]->value.name);
            virtual_high_water = std::max(virtual_high_water, virt[i]->virtual_end);
        }
        if (image_end < reader_.bytes().size()) {
            report_.overlay_bytes = reader_.bytes().size() - static_cast<std::size_t>(image_end);
            add_finding(report_, "trailing-data", Severity::info,
                        "bytes follow the last mapped header or section; certificate data may be included");
        }
    }

    void certificates() {
        if (certificate_offset_ == 0 && report_.certificate_table_size == 0) return;
        if (certificate_offset_ == 0 || report_.certificate_table_size == 0 ||
            !reader_.has(certificate_offset_, report_.certificate_table_size)) {
            add_finding(report_, "certificate-table-out-of-file", Severity::high,
                        "certificate table offset/size are inconsistent or outside file");
            return;
        }
        if (certificate_offset_ % 8U != 0)
            add_finding(report_, "certificate-table-unaligned", Severity::medium,
                        "certificate table is not 8-byte aligned");
        const std::uint64_t certificate_end = static_cast<std::uint64_t>(certificate_offset_) +
            report_.certificate_table_size;
        for (const auto& section : sections_) {
            if (section.value.raw_range_valid && section.value.raw_size != 0 &&
                certificate_offset_ < section.raw_end && certificate_end > section.value.raw_offset) {
                add_finding(report_, "certificate-table-overlaps-section", Severity::high,
                            "certificate table overlaps section raw data", section.value.name);
            }
        }
        std::uint64_t cursor = 0;
        while (cursor < report_.certificate_table_size) {
            const auto remaining = static_cast<std::uint64_t>(report_.certificate_table_size) - cursor;
            const auto at = static_cast<std::uint64_t>(certificate_offset_) + cursor;
            if (remaining < 8U) {
                add_finding(report_, "certificate-table-malformed", Severity::high,
                            "certificate table has a partial entry header");
                return;
            }
            const auto length = reader_.u32(at);
            if (length < 8U || length > remaining) {
                add_finding(report_, "certificate-table-malformed", Severity::high,
                            "certificate entry length is invalid or exceeds the table");
                return;
            }
            report_.certificates.push_back({reader_.u16(at + 4U), reader_.u16(at + 6U), length});
            const std::uint64_t aligned = (static_cast<std::uint64_t>(length) + 7U) & ~std::uint64_t{7U};
            if (aligned > remaining) {
                add_finding(report_, "certificate-table-malformed", Severity::high,
                            "aligned certificate entry exceeds the declared table size");
                return;
            }
            cursor += aligned;
        }
    }

    void imports() {
        if (import_rva_ == 0 && import_size_ == 0) return;
        if (import_rva_ == 0 || import_size_ == 0) {
            add_finding(report_, "import-directory-malformed", Severity::medium,
                        "import directory has only one of address and size");
            return;
        }
        const auto base = directory_offset(import_rva_, import_size_, "import");
        if (!base) return;
        bool terminated = false;
        const std::uint64_t limit = std::min<std::uint64_t>(import_size_ / 20U, kMaxDescriptors);
        for (std::uint64_t i = 0; i < limit; ++i) {
            const auto at = *base + i * 20U;
            const auto lookup = reader_.u32(at);
            const auto stamp = reader_.u32(at + 4U);
            const auto forwarder = reader_.u32(at + 8U);
            const auto name_rva = reader_.u32(at + 12U);
            const auto first_thunk = reader_.u32(at + 16U);
            if (lookup == 0 && stamp == 0 && forwarder == 0 && name_rva == 0 && first_thunk == 0) {
                terminated = true;
                break;
            }
            try {
                if (name_rva == 0) throw ParseError("import descriptor has no DLL name");
                const auto module_at = rva_offset(name_rva, 1);
                if (!module_at) throw ParseError("DLL name RVA is unmapped");
                const auto library = reader_.ascii(*module_at, kMaxNameBytes);
                const std::uint32_t thunk_rva = lookup == 0 ? first_thunk : lookup;
                if (thunk_rva == 0) throw ParseError("import descriptor has no lookup table");
                bool thunk_end = false;
                for (std::size_t j = 0; j < kMaxThunks; ++j) {
                    const std::uint64_t width = report_.bitness == 64 ? 8U : 4U;
                    const std::uint64_t item_rva = static_cast<std::uint64_t>(thunk_rva) + j * width;
                    const auto item_at = rva_offset(item_rva, width);
                    if (!item_at) throw ParseError("import thunk is unmapped");
                    const std::uint64_t value = report_.bitness == 64 ? reader_.u64(*item_at) : reader_.u32(*item_at);
                    if (value == 0) { thunk_end = true; break; }
                    if (report_.imports.size() >= kMaxImports) {
                        add_finding(report_, "import-limit-reached", Severity::info,
                                    "import enumeration stopped at the 10,000-entry safety limit");
                        return;
                    }
                    const std::uint64_t ordinal_bit = report_.bitness == 64
                        ? (std::uint64_t{1} << 63U) : (std::uint64_t{1} << 31U);
                    if ((value & ordinal_bit) != 0) {
                        report_.imports.push_back({library, {}, static_cast<std::uint16_t>(value & 0xffffU), true});
                    } else {
                        if (value > std::numeric_limits<std::uint32_t>::max())
                            throw ParseError("import name RVA exceeds PE address width");
                        const auto symbol_at = rva_offset(value, 3);
                        if (!symbol_at) throw ParseError("import name is unmapped");
                        report_.imports.push_back(
                            {library, reader_.ascii(*symbol_at + 2U, kMaxNameBytes), 0, false});
                    }
                }
                if (!thunk_end) throw ParseError("import thunk lacks a null terminator within safe limit");
            } catch (const ParseError& error) {
                add_finding(report_, "import-entry-malformed", Severity::medium, error.what());
                return;
            }
        }
        if (!terminated)
            add_finding(report_, "import-directory-unterminated", Severity::medium,
                        "no null import descriptor within its declared size or safe limit");
    }

    void exports() {
        if (export_rva_ == 0 && export_size_ == 0) return;
        if (export_rva_ == 0 || export_size_ == 0) {
            add_finding(report_, "export-directory-malformed", Severity::medium,
                        "export directory has only one of address and size");
            return;
        }
        if (export_size_ < 40U) {
            add_finding(report_, "export-directory-malformed", Severity::medium,
                        "export directory is shorter than its fixed header");
            return;
        }
        const auto at = directory_offset(export_rva_, 40U, "export");
        if (at) report_.exported_function_count = reader_.u32(*at + 20U);
    }

    void entrypoint() {
        if (report_.entrypoint_rva == 0) return;
        if (!rva_offset(report_.entrypoint_rva, 1))
            add_finding(report_, "entrypoint-unmapped", Severity::high,
                        "entry point RVA does not map to an unambiguous file byte");
        const bool executable = std::any_of(sections_.begin(), sections_.end(), [&](const auto& s) {
            const auto extent = std::max(s.value.virtual_size, s.value.raw_size);
            const auto start = static_cast<std::uint64_t>(s.value.virtual_address);
            return (s.value.characteristics & 0x20000000U) != 0 &&
                   report_.entrypoint_rva >= start && report_.entrypoint_rva - start < extent;
        });
        if (!executable)
            add_finding(report_, "entrypoint-not-executable", Severity::medium,
                        "entry point is outside sections marked executable");
    }
};

} // namespace

Report inspect(std::span<const std::uint8_t> bytes) { return Parser(bytes).run(); }

std::string to_string(Severity severity) {
    switch (severity) {
    case Severity::info: return "info";
    case Severity::low: return "low";
    case Severity::medium: return "medium";
    case Severity::high: return "high";
    case Severity::error: return "error";
    }
    return "unknown";
}

std::string to_json(const Report& r) {
    std::ostringstream o;
    o << "{\n  \"format\": \"Rudy PE report v1\",\n"
      << "  \"file_size\": " << r.file_size << ",\n"
      << "  \"machine\": \"" << escape(r.machine) << "\",\n"
      << "  \"machine_code\": \"" << hex(r.machine_code, 4) << "\",\n"
      << "  \"bitness\": " << r.bitness << ",\n"
      << "  \"dll\": " << (r.is_dll ? "true" : "false") << ",\n"
      << "  \"entrypoint_rva\": \"" << hex(r.entrypoint_rva, 8) << "\",\n"
      << "  \"subsystem\": " << r.subsystem << ",\n"
      << "  \"overlay_bytes\": " << r.overlay_bytes << ",\n"
      << "  \"certificate_table_bytes\": " << r.certificate_table_size << ",\n"
      << "  \"certificate_entries\": [";
    for (std::size_t i = 0; i < r.certificates.size(); ++i) {
        const auto& c = r.certificates[i];
        o << (i == 0 ? "\n" : ",\n") << "    {\"revision\": \"" << hex(c.revision, 4)
          << "\", \"type\": \"" << hex(c.type, 4) << "\", \"length\": " << c.length << "}";
    }
    if (!r.certificates.empty()) o << "\n  ";
    o << "],\n  \"sections\": [";
    for (std::size_t i = 0; i < r.sections.size(); ++i) {
        const auto& s = r.sections[i];
        o << (i == 0 ? "\n" : ",\n") << "    {\"name\": \"" << escape(s.name)
          << "\", \"virtual_address\": \"" << hex(s.virtual_address, 8)
          << "\", \"virtual_size\": " << s.virtual_size << ", \"raw_offset\": " << s.raw_offset
          << ", \"raw_size\": " << s.raw_size << ", \"characteristics\": \"" << hex(s.characteristics, 8)
          << "\", \"entropy\": " << std::fixed << std::setprecision(4) << s.entropy
          << ", \"raw_range_valid\": " << (s.raw_range_valid ? "true" : "false") << "}";
    }
    if (!r.sections.empty()) o << "\n  ";
    o << "],\n  \"import_count\": " << r.imports.size() << ",\n  \"imports\": [";
    for (std::size_t i = 0; i < r.imports.size(); ++i) {
        const auto& item = r.imports[i];
        o << (i == 0 ? "\n" : ",\n") << "    {\"library\": \"" << escape(item.library) << "\", ";
        if (item.by_ordinal) o << "\"ordinal\": " << item.ordinal;
        else o << "\"name\": \"" << escape(item.name) << "\"";
        o << "}";
    }
    if (!r.imports.empty()) o << "\n  ";
    o << "],\n  \"exported_function_count\": " << r.exported_function_count << ",\n  \"findings\": [";
    for (std::size_t i = 0; i < r.findings.size(); ++i) {
        const auto& f = r.findings[i];
        o << (i == 0 ? "\n" : ",\n") << "    {\"code\": \"" << escape(f.code)
          << "\", \"severity\": \"" << to_string(f.severity) << "\", \"message\": \"" << escape(f.message) << "\"";
        if (!f.section.empty()) o << ", \"section\": \"" << escape(f.section) << "\"";
        o << "}";
    }
    if (!r.findings.empty()) o << "\n  ";
    o << "]\n}\n";
    return o.str();
}

std::string to_sarif(const Report& r) {
    std::set<std::string> codes;
    for (const auto& f : r.findings) codes.insert(f.code);
    std::ostringstream o;
    o << "{\n  \"version\": \"2.1.0\",\n"
      << "  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n"
      << "  \"runs\": [{\n    \"tool\": {\"driver\": {\"name\": \"Rudy PE\", \"rules\": [";
    std::size_t i = 0;
    for (const auto& code : codes) {
        o << (i++ == 0 ? "" : ",") << "{\"id\": \"" << escape(code)
          << "\", \"shortDescription\": {\"text\": \"" << escape(code) << "\"}}";
    }
    o << "]}},\n    \"results\": [";
    for (std::size_t j = 0; j < r.findings.size(); ++j) {
        const auto& f = r.findings[j];
        const char* level = (f.severity == Severity::high || f.severity == Severity::error)
            ? "error" : (f.severity == Severity::medium ? "warning" : "note");
        o << (j == 0 ? "\n" : ",\n") << "      {\"ruleId\": \"" << escape(f.code)
          << "\", \"level\": \"" << level << "\", \"message\": {\"text\": \"" << escape(f.message);
        if (!f.section.empty()) o << " [section " << escape(f.section) << "]";
        o << "\"}}";
    }
    if (!r.findings.empty()) o << "\n    ";
    o << "]\n  }]\n}\n";
    return o.str();
}

std::string to_text(const Report& r) {
    std::ostringstream o;
    o << "Rudy PE | " << r.machine << " " << r.bitness << "-bit" << (r.is_dll ? " DLL" : " image") << "\n"
      << "File size: " << r.file_size << " bytes | entry point: " << hex(r.entrypoint_rva, 8)
      << " | trailing bytes: " << r.overlay_bytes << "\n"
      << "Certificate table: " << r.certificate_table_size << " bytes, " << r.certificates.size()
      << " structurally valid entries (presence is not signature validation)\n"
      << "Sections (" << r.sections.size() << "):\n";
    for (const auto& s : r.sections)
        o << "  " << std::left << std::setw(8) << s.name << " RVA " << hex(s.virtual_address, 8)
          << " raw " << s.raw_size << " bytes, entropy " << std::fixed << std::setprecision(2) << s.entropy
          << (s.raw_range_valid ? "" : " [out of file]") << "\n";
    o << "Imports: " << r.imports.size() << " | exported functions: " << r.exported_function_count << "\n";
    for (const auto& item : r.imports) {
        o << "  " << item.library << "!";
        if (item.by_ordinal) o << "#" << item.ordinal;
        else o << item.name;
        o << "\n";
    }
    o << "Structural findings are triage signals, not a malware verdict.\n";
    for (const auto& f : r.findings) {
        o << "  [" << to_string(f.severity) << "] " << f.code << ": " << f.message;
        if (!f.section.empty()) o << " (" << f.section << ")";
        o << "\n";
    }
    if (r.findings.empty()) o << "  No structural findings. This is not a malware verdict.\n";
    return o.str();
}

} // namespace rudy_pe
