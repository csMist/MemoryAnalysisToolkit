/**
 * @file scan_own_process.cpp
 * @brief Example program demonstrating memory scanning of the current process
 *
 * This example shows how to use memscan-util to analyze the memory layout
 * and search for patterns in the current process's memory space.
 *
 * @author Memory Scanner Utility
 * @version 1.0.0
 * @date 2025
 */

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include "memscan/memscan.hpp"

using namespace memscan;

void printMemoryRegions(const Process& process) {
    std::cout << "Memory regions in process " << process.getName()
              << " (PID: " << process.getPid() << "):\n";
    std::cout << std::string(80, '=') << "\n";

    auto regions = process.enumerateRegions();
    for (const auto& region : regions) {
        std::cout << std::hex << std::setfill('0')
                  << "0x" << std::setw(16) << region.getBaseAddress()
                  << " - 0x" << std::setw(16) << region.getEndAddress()
                  << " (" << std::dec << region.getSize() << " bytes) "
                  << region.getProtectionString() << " "
                  << region.getTypeString();

        if (!region.getPathname().empty()) {
            std::cout << " " << region.getPathname();
        }

        std::cout << "\n";
    }
    std::cout << "\nTotal regions: " << regions.size() << "\n\n";
}

void scanForPatterns(const Process& process, const PatternScanner& scanner) {
    std::cout << "Scanning for common patterns...\n";
    std::cout << std::string(50, '-') << "\n";

    // Common patterns to search for
    std::vector<std::pair<std::string, Pattern>> patterns = {
        {"Null bytes (common in initialized data)", Pattern("00 00 00 00")},
        {"ASCII 'main' function name", Pattern("6D 61 69 6E")},  // "main" in ASCII
        {"x86 NOP instruction", Pattern("90")},
        {"Common function prologue (push rbp; mov rbp, rsp)", Pattern("55 48 89 E5")},
        {"ELF magic bytes", Pattern("7F 45 4C 46")},  // "\x7FELF"
    };

    for (const auto& [description, pattern] : patterns) {
        std::cout << "Searching for: " << description << "\n";
        std::cout << "Pattern: " << pattern.toString() << "\n";

        try {
            auto results = scanner.scan(pattern);
            std::cout << "Found " << results.size() << " matches\n";

            if (!results.empty()) {
                std::cout << "First few matches:\n";
                size_t count = 0;
                for (const auto& result : results) {
                    if (count >= 5) break; // Show only first 5 matches

                    std::cout << "  0x" << std::hex << result.address
                              << " (offset 0x" << result.offset << " in "
                              << result.region->getTypeString() << " region";

                    if (!result.region->getPathname().empty()) {
                        std::cout << " " << result.region->getPathname();
                    }
                    std::cout << ")\n";
                    count++;
                }
            }
        } catch (const PatternScanError& e) {
            std::cout << "Error: " << e.what() << "\n";
        }

        std::cout << "\n";
    }
}

void analyzeMemoryContents(const Process& process) {
    std::cout << "Analyzing memory contents of readable regions...\n";
    std::cout << std::string(50, '-') << "\n";

    auto readable_regions = process.enumerateRegions(MemoryRegion::READ);
    size_t total_readable = 0;
    size_t total_executable = 0;
    size_t total_writable = 0;

    for (const auto& region : readable_regions) {
        total_readable += region.getSize();

        if (region.isExecutable()) {
            total_executable += region.getSize();
        }

        if (region.isWritable()) {
            total_writable += region.getSize();
        }

        // Sample some data from each region type
        if (region.getType() == MemoryRegion::CODE && region.getSize() >= 16) {
            std::cout << "Sample code from " << region.getTypeString() << " region at 0x"
                      << std::hex << region.getBaseAddress() << ": ";

            std::vector<uint8_t> sample(16);
            if (process.readMemory(region.getBaseAddress(), sample.data(), sample.size()) == sample.size()) {
                for (uint8_t byte : sample) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0')
                              << static_cast<int>(byte) << " ";
                }
            }
            std::cout << "\n";
        }
    }

    std::cout << "\nMemory statistics:\n";
    std::cout << "Total readable memory: " << std::dec << total_readable << " bytes\n";
    std::cout << "Total executable memory: " << total_executable << " bytes\n";
    std::cout << "Total writable memory: " << total_writable << " bytes\n";
    std::cout << "Number of readable regions: " << readable_regions.size() << "\n";
}

int main() {
    try {
        std::cout << "Memory Scanner Utility - Own Process Analysis Example\n";
        std::cout << "==================================================\n\n";

        // Create process handle for current process
        Process process;
        std::cout << "Analyzing current process: " << process.getName()
                  << " (PID: " << process.getPid() << ")\n\n";

        // Create pattern scanner
        PatternScanner scanner(process);

        // Print memory layout
        printMemoryRegions(process);

        // Scan for common patterns
        scanForPatterns(process, scanner);

        // Analyze memory contents
        analyzeMemoryContents(process);

        std::cout << "Analysis complete!\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
