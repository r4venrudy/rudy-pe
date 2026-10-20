#pragma once

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace rudy_pe {

enum class Severity { info, low, medium, high, error };

struct Finding {
    std::string code;
    Severity severity{};
    std::string message;
    std::string section;
};

struct Section {
    std::string name;
    std::uint32_t virtual_address{};
    std::uint32_t virtual_size{};
    std::uint32_t raw_offset{};
    std::uint32_t raw_size{};
    std::uint32_t characteristics{};
    double entropy{};
    bool raw_range_valid{};
};

struct Import {
    std::string library;
    std::string name;
    std::uint16_t ordinal{};
    bool by_ordinal{};
};

struct CertificateEntry {
    std::uint16_t revision{};
    std::uint16_t type{};
    std::uint32_t length{};
};

struct Report {
    std::string machine;
    std::uint16_t machine_code{};
    unsigned bitness{};
    std::uint64_t file_size{};
    std::uint32_t entrypoint_rva{};
    std::uint32_t subsystem{};
    bool is_dll{};
    std::uint64_t overlay_bytes{};
    std::uint32_t certificate_table_size{};
    std::vector<CertificateEntry> certificates;
    std::vector<Section> sections;
    std::vector<Import> imports;
    std::uint32_t exported_function_count{};
    std::vector<Finding> findings;
};

class ParseError final : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

Report inspect(std::span<const std::uint8_t> bytes);

std::string to_json(const Report& report);
std::string to_sarif(const Report& report);
std::string to_text(const Report& report);
std::string to_string(Severity severity);

} // namespace rudy_pe
