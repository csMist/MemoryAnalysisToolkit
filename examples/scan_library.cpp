/**
 * @file scan_library.cpp
 * @brief Example program demonstrating library function pattern scanning
 *
 * This example shows how to scan loaded shared libraries for function signatures
 * and patterns, which is useful for reverse engineering and debugging.
 *
 * @author Memory Scanner Utility
 * @version 1.0.0
 * @date 2025
 */

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <algorithm>
#include "memscan/memscan.hpp"

using namespace memscan;

void findLibraries(const Process& process) {
    std::cout << "Scanning for loaded shared libraries...\n";
    std::cout << std::string(50, '-') << "\n";

    auto regions = process.enumerateRegions();

    // Find unique library pathnames
    std::vector<std::string> libraries;
    for (const auto& region : regions) {
        const std::string& pathname = region.getPathname();
        if (!pathname.empty() &&
            (pathname.find(".so") != std::string::npos ||
             pathname.find(".dll") != std::string::npos ||
             pathname.find(".dylib") != std::string::npos) &&
            std::find(libraries.begin(), libraries.end(), pathname) == libraries.end()) {
            libraries.push_back(pathname);
        }
    }

    std::cout << "Found " << libraries.size() << " shared libraries:\n";
    for (size_t i = 0; i < libraries.size(); ++i) {
        std::cout << std::setw(2) << i + 1 << ". " << libraries[i] << "\n";
    }
    std::cout << "\n";
}

void scanLibraryForFunctions(const Process& process, const PatternScanner& scanner,
                           const std::string& library_name) {
    std::cout << "Scanning " << library_name << " for function patterns...\n";
    std::cout << std::string(60, '-') << "\n";

    // Find all regions belonging to this library
    auto all_regions = process.enumerateRegions();
    std::vector<MemoryRegion> library_regions;

    for (const auto& region : all_regions) {
        if (region.getPathname().find(library_name) != std::string::npos) {
            library_regions.push_back(region);
        }
    }

    if (library_regions.empty()) {
        std::cout << "No regions found for library: " << library_name << "\n";
        return;
    }

    std::cout << "Found " << library_regions.size() << " memory regions for " << library_name << "\n";

    // Common function patterns to search for
    std::vector<std::pair<std::string, Pattern>> function_patterns = {
        {"Function prologue (push rbp; mov rbp, rsp)", Pattern("55 48 89 E5")},
        {"Function prologue (push rbx; ...)", Pattern("53 48 83 EC ??")},
        {"Common string operations (strcmp-like)", Pattern("48 39 C8 74 ??")},
        {"Memory operations (memcpy-like)", Pattern("48 8B 06 48 89 07")},
        {"Common system calls (syscall instruction)", Pattern("0F 05")},
        {"Return instruction (ret)", Pattern("C3")},
        {"Return instruction (retn)", Pattern("C2 ?? ??")},
    };

    PatternScanner::ScanConfig config;
    config.required_permissions = {static_cast<uint32_t>(MemoryRegion::READ)};
    config.max_results = 10; // Limit results per pattern

    for (const auto& [description, pattern] : function_patterns) {
        std::cout << "Searching for: " << description << "\n";

        try {
            auto results = scanner.scanRegions(pattern, library_regions, config);

            if (results.empty()) {
                std::cout << "  No matches found\n";
            } else {
                std::cout << "  Found " << results.size() << " matches:\n";
                for (const auto& result : results) {
                    std::cout << "    0x" << std::hex << std::setfill('0')
                              << std::setw(16) << result.address;

                    // Try to read some context around the match
                    std::vector<uint8_t> context(16);
                    if (process.readMemory(result.address - 8, context.data(), context.size()) == context.size()) {
                        std::cout << " |";
                        for (uint8_t byte : context) {
                            std::cout << " " << std::hex << std::setw(2) << std::setfill('0')
                                      << static_cast<int>(byte);
                        }
                        std::cout << "|";
                    }

                    std::cout << "\n";
                }
            }
        } catch (const PatternScanError& e) {
            std::cout << "  Error: " << e.what() << "\n";
        }

        std::cout << "\n";
    }
}

void analyzeLibraryMemoryLayout(const Process& process, const std::string& library_name) {
    std::cout << "Analyzing memory layout of " << library_name << "...\n";
    std::cout << std::string(50, '-') << "\n";

    auto all_regions = process.enumerateRegions();
    std::vector<MemoryRegion> library_regions;

    for (const auto& region : all_regions) {
        if (region.getPathname().find(library_name) != std::string::npos) {
            library_regions.push_back(region);
        }
    }

    if (library_regions.empty()) {
        std::cout << "Library not found: " << library_name << "\n";
        return;
    }

    // Sort regions by address
    std::sort(library_regions.begin(), library_regions.end(),
              [](const MemoryRegion& a, const MemoryRegion& b) {
                  return a.getBaseAddress() < b.getBaseAddress();
              });

    size_t total_size = 0;
    size_t code_size = 0;
    size_t data_size = 0;
    size_t readonly_size = 0;

    std::cout << "Memory regions for " << library_name << ":\n";
    std::cout << std::left << std::setw(18) << "Address Range"
              << std::setw(12) << "Size"
              << std::setw(10) << "Permissions"
              << "Type\n";
    std::cout << std::string(60, '-') << "\n";

    for (const auto& region : library_regions) {
        total_size += region.getSize();

        if (region.isExecutable()) {
            code_size += region.getSize();
        }

        if (region.isReadable() && !region.isExecutable()) {
            if (region.isWritable()) {
                data_size += region.getSize();
            } else {
                readonly_size += region.getSize();
            }
        }

        std::cout << "0x" << std::hex << std::setfill('0')
                  << std::setw(16) << region.getBaseAddress()
                  << "-0x" << std::setw(16) << region.getEndAddress()
                  << std::dec << std::setw(10) << region.getSize()
                  << std::setw(10) << region.getProtectionString().substr(0, 3)
                  << region.getTypeString() << "\n";
    }

    std::cout << "\nLibrary memory statistics:\n";
    std::cout << "Total mapped size: " << total_size << " bytes\n";
    std::cout << "Code sections: " << code_size << " bytes\n";
    std::cout << "Data sections: " << data_size << " bytes\n";
    std::cout << "Read-only sections: " << readonly_size << " bytes\n";
    std::cout << "Number of regions: " << library_regions.size() << "\n";
}

int main(int argc, char* argv[]) {
    try {
        std::cout << "Memory Scanner Utility - Library Analysis Example\n";
        std::cout << "===============================================\n\n";

        // Create process handle for current process
        Process process;
        std::cout << "Analyzing libraries in process: " << process.getName()
                  << " (PID: " << process.getPid() << ")\n\n";

        // Create pattern scanner
        PatternScanner scanner(process);

        // Find and list loaded libraries
        findLibraries(process);

        // Analyze specific libraries (try common ones)
        std::vector<std::string> libraries_to_analyze = {
            "libc.so",    // Linux
            "libstdc++.so", // Linux
            "libSystem",  // macOS
            "kernel32.dll", // Windows
            "msvcrt.dll"  // Windows
        };

        for (const auto& lib_name : libraries_to_analyze) {
            try {
                scanLibraryForFunctions(process, scanner, lib_name);
                analyzeLibraryMemoryLayout(process, lib_name);
                std::cout << "\n";
            } catch (const std::exception&) {
                // Library not found or not accessible, skip
            }
        }

        std::cout << "Library analysis complete!\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
