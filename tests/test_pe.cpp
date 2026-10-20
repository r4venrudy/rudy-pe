#include "rudy_pe/pe.hpp"

#include <cstdint>
#include <exception>
#include <iostream>
#include <string>
#include <vector>

namespace {

void put16(std::vector<std::uint8_t>& b, std::size_t at, std::uint16_t v) {
    b.at(at) = static_cast<std::uint8_t>(v & 0xffU);
    b.at(at + 1U) = static_cast<std::uint8_t>((v >> 8U) & 0xffU);
}
void put32(std::vector<std::uint8_t>& b, std::size_t at, std::uint32_t v) {
    for (std::size_t i = 0; i < 4; ++i) b.at(at + i) = static_cast<std::uint8_t>((v >> (i * 8U)) & 0xffU);
}
void put64(std::vector<std::uint8_t>& b, std::size_t at, std::uint64_t v) {
    for (std::size_t i = 0; i < 8; ++i) b.at(at + i) = static_cast<std::uint8_t>((v >> (i * 8U)) & 0xffU);
}

std::vector<std::uint8_t> minimal_pe() {
    std::vector<std::uint8_t> b(0x400, 0);
    put16(b, 0, 0x5a4d);
    put32(b, 0x3c, 0x80);
    put32(b, 0x80, 0x00004550);
    put16(b, 0x84, 0x8664);
    put16(b, 0x86, 1);
    put16(b, 0x94, 0xf0);
    const std::size_t opt = 0x98;
    put16(b, opt, 0x20b);
    put32(b, opt + 16U, 0x1000);
    put64(b, opt + 24U, 0x140000000ULL);
    put32(b, opt + 32U, 0x1000);
    put32(b, opt + 36U, 0x200);
    put32(b, opt + 56U, 0x2000);
    put32(b, opt + 60U, 0x200);
    put16(b, opt + 68U, 3);
    put32(b, opt + 108U, 16);
    const std::size_t sec = 0x188;
    const std::string name = ".text";
    for (std::size_t i = 0; i < name.size(); ++i) b[sec + i] = static_cast<std::uint8_t>(name[i]);
    put32(b, sec + 8U, 0x100);
    put32(b, sec + 12U, 0x1000);
    put32(b, sec + 16U, 0x200);
    put32(b, sec + 20U, 0x200);
    put32(b, sec + 36U, 0x60000020);
    b[0x200] = 0xc3;
    return b;
}

std::vector<std::uint8_t> minimal_pe32() {
    std::vector<std::uint8_t> b(0x400, 0);
    put16(b, 0, 0x5a4d);
    put32(b, 0x3c, 0x80);
    put32(b, 0x80, 0x00004550);
    put16(b, 0x84, 0x014c);
    put16(b, 0x86, 1);
    put16(b, 0x94, 0xe0);
    const std::size_t opt = 0x98;
    put16(b, opt, 0x10b);
    put32(b, opt + 16U, 0x1000);
    put32(b, opt + 28U, 0x400000);
    put32(b, opt + 32U, 0x1000);
    put32(b, opt + 36U, 0x200);
    put32(b, opt + 56U, 0x2000);
    put32(b, opt + 60U, 0x200);
    put16(b, opt + 68U, 3);
    put32(b, opt + 92U, 16);
    const std::size_t sec = 0x178;
    const std::string name = ".text";
    for (std::size_t i = 0; i < name.size(); ++i) b[sec + i] = static_cast<std::uint8_t>(name[i]);
    put32(b, sec + 8U, 0x100);
    put32(b, sec + 12U, 0x1000);
    put32(b, sec + 16U, 0x200);
    put32(b, sec + 20U, 0x200);
    put32(b, sec + 36U, 0x60000020);
    return b;
}

bool has_finding(const rudy_pe::Report& report, const std::string& code) {
    for (const auto& finding : report.findings) if (finding.code == code) return true;
    return false;
}

std::size_t finding_count(const rudy_pe::Report& report, const std::string& code) {
    std::size_t count = 0;
    for (const auto& finding : report.findings) if (finding.code == code) ++count;
    return count;
}

void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void test_valid_image() {
    const auto bytes = minimal_pe();
    const auto report = rudy_pe::inspect(bytes);
    check(report.bitness == 64, "PE32+ bitness should be 64");
    check(report.machine == "AMD64", "machine should be AMD64");
    check(report.sections.size() == 1, "one section expected");
    check(report.sections.front().name == ".text", "section name should be parsed");
    check(report.sections.front().raw_range_valid, "section raw range should be valid");
    check(report.sections.front().entropy < 0.1, "one-byte section should have near-zero entropy");
    check(report.findings.empty(), "minimal valid image should have no findings");
}

void test_valid_pe32() {
    const auto report = rudy_pe::inspect(minimal_pe32());
    check(report.bitness == 32, "PE32 bitness should be 32");
    check(report.machine == "I386", "machine should be I386");
    check(report.sections.size() == 1, "PE32 one section expected");
    check(report.findings.empty(), "minimal PE32 image should have no findings");
}

void test_rwx_and_overlay() {
    auto bytes = minimal_pe();
    put32(bytes, 0x188 + 36U, 0xe0000020);
    bytes.push_back(0x41);
    const auto report = rudy_pe::inspect(bytes);
    check(has_finding(report, "section-writable-executable"), "RWX section should be reported");
    check(has_finding(report, "trailing-data"), "overlay should be reported");
    check(report.overlay_bytes == 1, "overlay byte count should be exact");
}

void test_certificate_table() {
    auto bytes = minimal_pe();
    bytes.resize(0x410, 0);
    const auto opt = 0x98U;
    put32(bytes, opt + 112U + 4U * 8U, 0x400); // Security directory is a file offset.
    put32(bytes, opt + 112U + 4U * 8U + 4U, 8);
    put32(bytes, 0x400, 8);
    put16(bytes, 0x404, 0x0200);
    put16(bytes, 0x406, 2);
    const auto report = rudy_pe::inspect(bytes);
    check(report.certificates.size() == 1, "one certificate record should parse");
    check(report.certificates.front().length == 8, "certificate record length should parse");
    check(report.overlay_bytes == 16, "certificate area should remain visible as overlay data");
}

void test_imports() {
    auto bytes = minimal_pe();
    const auto opt = 0x98U;
    put32(bytes, opt + 112U + 8U, 0x1100);
    put32(bytes, opt + 112U + 8U + 4U, 40);
    put32(bytes, 0x300, 0x1160); // OriginalFirstThunk
    put32(bytes, 0x30c, 0x1140); // DLL name RVA
    put32(bytes, 0x310, 0x1180); // FirstThunk
    const std::string library = "KERNEL32.dll";
    for (std::size_t i = 0; i < library.size(); ++i) bytes[0x340 + i] = static_cast<std::uint8_t>(library[i]);
    put64(bytes, 0x360, 0x1170);
    put64(bytes, 0x368, 0);
    put16(bytes, 0x370, 0);
    const std::string function = "ExitProcess";
    for (std::size_t i = 0; i < function.size(); ++i) bytes[0x372 + i] = static_cast<std::uint8_t>(function[i]);
    const auto report = rudy_pe::inspect(bytes);
    check(report.imports.size() == 1, "one imported function should parse");
    check(report.imports.front().library == library, "import library should parse");
    check(report.imports.front().name == function, "import name should parse");
}

void test_ordinal_import32() {
    auto bytes = minimal_pe32();
    const auto opt = 0x98U;
    put32(bytes, opt + 96U + 8U, 0x1100);
    put32(bytes, opt + 96U + 8U + 4U, 40);
    put32(bytes, 0x300, 0x1160);
    put32(bytes, 0x30c, 0x1140);
    put32(bytes, 0x310, 0x1180);
    const std::string library = "USER32.dll";
    for (std::size_t i = 0; i < library.size(); ++i) bytes[0x340 + i] = static_cast<std::uint8_t>(library[i]);
    put32(bytes, 0x360, 0x80000007);
    put32(bytes, 0x364, 0);
    const auto report = rudy_pe::inspect(bytes);
    check(report.imports.size() == 1, "one ordinal import should parse");
    check(report.imports.front().by_ordinal, "ordinal import should be marked by ordinal");
    check(report.imports.front().ordinal == 7, "ordinal import number should parse");
}

void test_unmapped_entrypoint() {
    auto bytes = minimal_pe();
    put32(bytes, 0x98 + 16U, 0x1100);
    put32(bytes, 0x188 + 8U, 0x200);
    put32(bytes, 0x188 + 16U, 0x100);
    const auto report = rudy_pe::inspect(bytes);
    check(has_finding(report, "entrypoint-unmapped"), "entry point in virtual-only section tail should be reported");
}

void test_rejects_truncation() {
    const std::vector<std::uint8_t> bytes{0x4d, 0x5a};
    bool rejected = false;
    try { (void)rudy_pe::inspect(bytes); }
    catch (const rudy_pe::ParseError&) { rejected = true; }
    check(rejected, "truncated DOS header must be rejected");
}

void test_malformed_certificate() {
    auto bytes = minimal_pe();
    bytes.resize(0x410, 0);
    const auto opt = 0x98U;
    put32(bytes, opt + 112U + 4U * 8U, 0x400);
    put32(bytes, opt + 112U + 4U * 8U + 4U, 8);
    put32(bytes, 0x400, 7);
    const auto report = rudy_pe::inspect(bytes);
    check(has_finding(report, "certificate-table-malformed"), "invalid certificate length should be reported");
}

void test_certificate_section_overlap() {
    auto bytes = minimal_pe();
    const auto opt = 0x98U;
    put32(bytes, opt + 112U + 4U * 8U, 0x300);
    put32(bytes, opt + 112U + 4U * 8U + 4U, 8);
    put32(bytes, 0x300, 8);
    put16(bytes, 0x304, 0x0200);
    put16(bytes, 0x306, 2);
    const auto report = rudy_pe::inspect(bytes);
    check(has_finding(report, "certificate-table-overlaps-section"),
          "certificate data inside a section should be reported");
}

void test_nested_section_overlaps() {
    auto bytes = minimal_pe();
    put16(bytes, 0x86, 3);
    put32(bytes, 0x188 + 8U, 0x180);
    put32(bytes, 0x188 + 16U, 0x180);
    const std::size_t second = 0x188 + 40U;
    const std::size_t third = second + 40U;
    const std::string second_name = ".data";
    const std::string third_name = ".rsrc";
    for (std::size_t i = 0; i < second_name.size(); ++i) bytes[second + i] = static_cast<std::uint8_t>(second_name[i]);
    put32(bytes, second + 8U, 0x10);
    put32(bytes, second + 12U, 0x1020);
    put32(bytes, second + 16U, 0x10);
    put32(bytes, second + 20U, 0x220);
    put32(bytes, second + 36U, 0xc0000040);
    for (std::size_t i = 0; i < third_name.size(); ++i) bytes[third + i] = static_cast<std::uint8_t>(third_name[i]);
    put32(bytes, third + 8U, 0x10);
    put32(bytes, third + 12U, 0x1040);
    put32(bytes, third + 16U, 0x10);
    put32(bytes, third + 20U, 0x240);
    put32(bytes, third + 36U, 0x40000040);
    const auto report = rudy_pe::inspect(bytes);
    check(finding_count(report, "section-raw-overlap") == 2,
          "nested raw ranges must report both later overlaps");
    check(finding_count(report, "section-virtual-overlap") == 2,
          "nested virtual ranges must report both later overlaps");
}

} // namespace

int main() {
    try {
        test_valid_image();
        test_valid_pe32();
        test_rwx_and_overlay();
        test_certificate_table();
        test_imports();
        test_ordinal_import32();
        test_unmapped_entrypoint();
        test_rejects_truncation();
        test_malformed_certificate();
        test_certificate_section_overlap();
        test_nested_section_overlaps();
        std::cout << "All Rudy PE parser tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "test failure: " << error.what() << "\n";
        return 1;
    }
}
