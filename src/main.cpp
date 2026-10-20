#include "rudy_pe/pe.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <string>
#include <vector>

namespace {

constexpr std::uint64_t kMaxFileSize = 1024ULL * 1024ULL * 1024ULL;

void usage(std::ostream& out) {
    out << "Rudy PE - offline Portable Executable structure inspector\n\n"
        << "Usage: rudy-pe [--format text|json|sarif] <file.exe|file.dll>\n"
        << "       rudy-pe --help\n\n"
        << "Reads a file as data; it never loads or executes the target.\n"
        << "Exit codes: 0 report created, 1 I/O or argument error, 2 malformed PE.\n";
}

} // namespace

int main(int argc, char** argv) {
    std::string format = "text";
    std::filesystem::path path;
    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        if (arg == "--help" || arg == "-h") {
            usage(std::cout);
            return 0;
        }
        if (arg == "--format") {
            if (++i >= argc) {
                std::cerr << "error: --format requires text, json, or sarif\n";
                return 1;
            }
            format = argv[i];
            continue;
        }
        if (!arg.empty() && arg[0] == '-') {
            std::cerr << "error: unknown option: " << arg << "\n";
            usage(std::cerr);
            return 1;
        }
        if (!path.empty()) {
            std::cerr << "error: exactly one input file is supported\n";
            return 1;
        }
        path = arg;
    }
    if (path.empty()) {
        usage(std::cerr);
        return 1;
    }
    if (format != "text" && format != "json" && format != "sarif") {
        std::cerr << "error: format must be text, json, or sarif\n";
        return 1;
    }

    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec) {
        std::cerr << "error: cannot read file size: " << ec.message() << "\n";
        return 1;
    }
    if (size > kMaxFileSize || size > std::numeric_limits<std::size_t>::max()) {
        std::cerr << "error: file exceeds the 1 GiB safety limit\n";
        return 1;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        std::cerr << "error: cannot open input file\n";
        return 1;
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    if (!bytes.empty()) {
        input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!input || static_cast<std::size_t>(input.gcount()) != bytes.size()) {
            std::cerr << "error: could not read the complete input file\n";
            return 1;
        }
    }

    try {
        const auto report = rudy_pe::inspect(bytes);
        if (format == "json") std::cout << rudy_pe::to_json(report);
        else if (format == "sarif") std::cout << rudy_pe::to_sarif(report);
        else std::cout << rudy_pe::to_text(report);
    } catch (const rudy_pe::ParseError& error) {
        std::cerr << "malformed PE: " << error.what() << "\n";
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << "\n";
        return 1;
    }
    return 0;
}
