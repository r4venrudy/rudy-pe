#include "rudy_pe/pe.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    try {
        const auto report = rudy_pe::inspect(std::span<const std::uint8_t>(data, size));
        (void)rudy_pe::to_json(report);
        (void)rudy_pe::to_sarif(report);
        (void)rudy_pe::to_text(report);
    } catch (const rudy_pe::ParseError&) {
        // Malformed byte sequences are expected and are part of the fuzz input space.
    }
    return 0;
}
