/**
 * @file memory_layout_analyzer.cpp
 * @brief Example program demonstrating comprehensive memory layout analysis
 *
 * This example shows how to perform detailed analysis of a process's memory
 * layout, including region classification, permission analysis, and entropy
 * calculation for security research and debugging purposes.
 *
 * @author Memory Scanner Utility
 * @version 1.0.0
 * @date 2025
 */

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <cmath>
#include "memscan/memscan.hpp"

using namespace memscan;

// Simple entropy calculation for memory analysis
double calculateEntropy(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return 0.0;
    }

    std::map<uint8_t, size_t> frequency;
    for (uint8_t byte : data) {
        frequency[byte]++;
    }

    double entropy = 0.0;
    double data_size = static_cast<double>(data.size());

    for (const auto& pair : frequency) {
        double probability = pair.second / data_size;
        entropy -= probability * std::log2(probability);
    }

    return entropy;
}

void analyzeMemoryPermissions(const Process& process) {
    std::cout << "Memory Permission Analysis\n";
    std::cout << std::string(40, '=') << "\n";

    auto regions = process.enumerateRegions();

    std::map<std::string, size_t> permission_counts;
    std::map<std::string, size_t> permission_sizes;

    for (const auto& region : regions) {
        std::string perms = region.getProtectionString().substr(0, 3); // rwx part
        permission_counts[perms]++;
        permission_sizes[perms] += region.getSize();
    }

    std::cout << std::left << std::setw(10) << "Permissions"
              << std::setw(8) << "Count"
              << std::setw(12) << "Total Size"
              << "Description\n";
    std::cout << std::string(50, '-') << "\n";

    for (const auto& [perms, count] : permission_counts) {
        std::string description;
        if (perms == "r--") description = "Read-only data";
        else if (perms == "rw-") description = "Read-write data";
        else if (perms == "r-x") description = "Executable code";
        else if (perms == "rwx") description = "Read-write-execute";
        else if (perms == "---") description = "No access";
        else description = "Other";

        std::cout << std::left << std::setw(10) << perms
                  << std::setw(8) << count
                  << std::setw(12) << permission_sizes[perms]
                  << description << "\n";
    }
    std::cout << "\n";
}

void analyzeMemoryTypes(const Process& process) {
    std::cout << "Memory Region Type Analysis\n";
    std::cout << std::string(35, '=') << "\n";

    auto regions = process.enumerateRegions();

    std::map<MemoryRegion::Type, size_t> type_counts;
    std::map<MemoryRegion::Type, size_t> type_sizes;

    for (const auto& region : regions) {
        MemoryRegion::Type type = region.getType();
        type_counts[type]++;
        type_sizes[type] += region.getSize();
    }

    std::cout << std::left << std::setw(15) << "Type"
              << std::setw(8) << "Count"
              << std::setw(12) << "Total Size"
              << "\n";
    std::cout << std::string(40, '-') << "\n";

    for (const auto& [type, count] : type_counts) {
        std::cout << std::left << std::setw(15) << MemoryRegion::typeToString(type)
                  << std::setw(8) << count
                  << std::setw(12) << type_sizes[type]
                  << "\n";
    }
    std::cout << "\n";
}

void analyzeMemoryEntropy(const Process& process) {
    std::cout << "Memory Entropy Analysis (Randomness Measure)\n";
    std::cout << std::string(45, '=') << "\n";

    auto regions = process.enumerateRegions(MemoryRegion::READ);
    const size_t SAMPLE_SIZE = 4096; // Sample 4KB from each region

    std::vector<std::tuple<std::string, double, uintptr_t>> entropy_samples;

    for (const auto& region : regions) {
        if (region.getSize() < SAMPLE_SIZE) {
            continue; // Skip regions too small to sample
        }

        std::vector<uint8_t> sample(SAMPLE_SIZE);
        size_t bytes_read = process.readMemory(region.getBaseAddress(),
                                             sample.data(), sample.size());

        if (bytes_read == sample.size()) {
            double entropy = calculateEntropy(sample);
            std::string region_desc = region.getTypeString();

            if (!region.getPathname().empty()) {
                // Extract filename from path
                size_t last_slash = region.getPathname().find_last_of("/\\");
                if (last_slash != std::string::npos) {
                    region_desc = region.getPathname().substr(last_slash + 1);
                } else {
                    region_desc = region.getPathname();
                }
            }

            entropy_samples.emplace_back(region_desc, entropy, region.getBaseAddress());
        }
    }

    // Sort by entropy (highest first)
    std::sort(entropy_samples.begin(), entropy_samples.end(),
              [](const auto& a, const auto& b) {
                  return std::get<1>(a) > std::get<1>(b);
              });

    std::cout << std::left << std::setw(20) << "Region"
              << std::setw(10) << "Entropy"
              << std::setw(18) << "Address"
              << "Description\n";
    std::cout << std::string(60, '-') << "\n";

    size_t count = 0;
    for (const auto& [region, entropy, address] : entropy_samples) {
        if (count >= 20) break; // Show top 20

        std::string entropy_desc;
        if (entropy < 2.0) entropy_desc = "Low (ordered)";
        else if (entropy < 6.0) entropy_desc = "Medium";
        else entropy_desc = "High (random)";

        std::cout << std::left << std::setw(20) << region.substr(0, 19)
                  << std::fixed << std::setprecision(2) << std::setw(10) << entropy
                  << "0x" << std::hex << std::setw(16) << std::setfill('0') << address
                  << std::dec << entropy_desc << "\n";
        count++;
    }
    std::cout << "\n";
}

void analyzeAddressSpaceLayout(const Process& process) {
    std::cout << "Address Space Layout Analysis\n";
    std::cout << std::string(35, '=') << "\n";

    auto regions = process.enumerateRegions();

    if (regions.empty()) {
        std::cout << "No memory regions found.\n";
        return;
    }

    // Sort by address
    std::sort(regions.begin(), regions.end(),
              [](const MemoryRegion& a, const MemoryRegion& b) {
                  return a.getBaseAddress() < b.getBaseAddress();
              });

    uintptr_t lowest_address = regions.front().getBaseAddress();
    uintptr_t highest_address = regions.back().getEndAddress();

    std::cout << "Address space range: 0x" << std::hex << lowest_address
              << " - 0x" << highest_address << "\n";
    std::cout << "Total span: " << std::dec
              << (highest_address - lowest_address) / (1024 * 1024) << " MB\n";

    // Calculate gaps between regions
    size_t total_gaps = 0;
    uintptr_t total_gap_size = 0;

    for (size_t i = 1; i < regions.size(); ++i) {
        uintptr_t gap_start = regions[i - 1].getEndAddress();
        uintptr_t gap_end = regions[i].getBaseAddress();

        if (gap_end > gap_start) {
            uintptr_t gap_size = gap_end - gap_start;
            total_gaps++;
            total_gap_size += gap_size;
        }
    }

    std::cout << "Unmapped gaps: " << total_gaps << " gaps, "
              << total_gap_size / 1024 << " KB total\n";

    // Analyze region size distribution
    std::vector<size_t> sizes;
    for (const auto& region : regions) {
        sizes.push_back(region.getSize());
    }

    std::sort(sizes.begin(), sizes.end());

    if (!sizes.empty()) {
        size_t median_size = sizes[sizes.size() / 2];
        size_t avg_size = 0;
        for (size_t size : sizes) {
            avg_size += size;
        }
        avg_size /= sizes.size();

        std::cout << "Region size statistics:\n";
        std::cout << "  Smallest: " << sizes.front() << " bytes\n";
        std::cout << "  Largest: " << sizes.back() << " bytes\n";
        std::cout << "  Median: " << median_size << " bytes\n";
        std::cout << "  Average: " << avg_size << " bytes\n";
    }

    std::cout << "\n";
}

void findSuspiciousPatterns(const Process& process, const PatternScanner& scanner) {
    std::cout << "Security Pattern Analysis\n";
    std::cout << std::string(30, '=') << "\n";

    // Patterns that might indicate security issues or interesting behavior
    std::vector<std::pair<std::string, Pattern>> security_patterns = {
        {"NOP sled (many NOPs)", Pattern("90 90 90 90 90")},
        {"Shellcode pattern (decoder)", Pattern("31 C0 31 DB 31 C9")},
        {"Format string vulnerability", Pattern("%25 73 25 73")},
        {"Stack canary pattern", Pattern("00 00 00 00 ?? ?? ?? ??")},
        {"Common encryption key pattern", Pattern("AES")},
    };

    PatternScanner::ScanConfig config;
    config.required_permissions = {static_cast<uint32_t>(MemoryRegion::READ)};
    config.max_results = 5; // Limit results

    for (const auto& [description, pattern] : security_patterns) {
        std::cout << "Checking for: " << description << "\n";

        try {
            auto results = scanner.scan(pattern, config);

            if (results.empty()) {
                std::cout << "  Not found\n";
            } else {
                std::cout << "  Found " << results.size() << " instances\n";
                for (const auto& result : results) {
                    std::cout << "    0x" << std::hex << result.address
                              << " in " << result.region->getTypeString() << " region\n";
                }
            }
        } catch (const PatternScanError& e) {
            std::cout << "  Error: " << e.what() << "\n";
        }

        std::cout << "\n";
    }
}

int main() {
    try {
        std::cout << "Memory Scanner Utility - Memory Layout Analyzer\n";
        std::cout << "==============================================\n\n";

        // Create process handle for current process
        Process process;
        std::cout << "Analyzing process: " << process.getName()
                  << " (PID: " << process.getPid() << ")\n\n";

        // Create pattern scanner
        PatternScanner scanner(process);

        // Perform various analyses
        analyzeMemoryPermissions(process);
        analyzeMemoryTypes(process);
        analyzeAddressSpaceLayout(process);
        analyzeMemoryEntropy(process);
        findSuspiciousPatterns(process, scanner);

        std::cout << "Memory layout analysis complete!\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
