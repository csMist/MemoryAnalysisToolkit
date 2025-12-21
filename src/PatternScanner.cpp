/**
 * @file PatternScanner.cpp
 * @brief Implementation of Pattern and PatternScanner classes
 *
 * @author Memory Scanner Utility
 * @version 1.0.0
 * @date 2025
 */

#include "memscan/PatternScanner.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <stdexcept>
#include <iterator>

namespace memscan {

// Pattern implementation

Pattern::Pattern() = default;

Pattern::Pattern(const std::string& pattern) {
    auto [bytes, mask] = parsePattern(pattern);
    bytes_ = std::move(bytes);
    mask_ = std::move(mask);
}

Pattern::Pattern(const std::vector<uint8_t>& bytes, const std::vector<bool>& mask)
    : bytes_(bytes), mask_(mask) {
    if (bytes_.size() != mask_.size()) {
        throw std::invalid_argument("Bytes and mask vectors must have the same size");
    }
}

const std::vector<uint8_t>& Pattern::getBytes() const {
    return bytes_;
}

const std::vector<bool>& Pattern::getMask() const {
    return mask_;
}

size_t Pattern::getLength() const {
    return bytes_.size();
}

bool Pattern::isEmpty() const {
    return bytes_.empty();
}

std::string Pattern::toString() const {
    if (bytes_.empty()) {
        return "";
    }

    std::stringstream ss;
    for (size_t i = 0; i < bytes_.size(); ++i) {
        if (i > 0) {
            ss << " ";
        }
        if (mask_[i]) {
            ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
               << static_cast<int>(bytes_[i]);
        } else {
            ss << "??";
        }
    }
    return ss.str();
}

std::pair<std::vector<uint8_t>, std::vector<bool>>
Pattern::parsePattern(const std::string& pattern) {
    std::vector<uint8_t> bytes;
    std::vector<bool> mask;

    std::istringstream iss(pattern);
    std::string token;

    while (iss >> token) {
        if (token == "??" || token == "??") {
            // Wildcard byte
            bytes.push_back(0);
            mask.push_back(false);
        } else {
            // Parse hex byte
            if (token.length() != 2) {
                throw std::invalid_argument("Invalid hex byte: " + token);
            }

            try {
                size_t pos;
                uint8_t byte = static_cast<uint8_t>(std::stoul(token, &pos, 16));
                if (pos != 2) {
                    throw std::invalid_argument("Invalid hex byte: " + token);
                }
                bytes.push_back(byte);
                mask.push_back(true);
            } catch (const std::exception&) {
                throw std::invalid_argument("Invalid hex byte: " + token);
            }
        }
    }

    return {bytes, mask};
}

// Boyer-Moore-Horspool implementation for pattern scanning
class BoyerMooreHorspool {
public:
    BoyerMooreHorspool(const Pattern& pattern) : pattern_(pattern) {
        buildBadCharacterTable();
    }

    std::vector<size_t> search(const uint8_t* data, size_t data_size) const {
        std::vector<size_t> results;
        if (pattern_.getLength() == 0 || pattern_.getLength() > data_size) {
            return results;
        }

        const auto& bytes = pattern_.getBytes();
        const auto& mask = pattern_.getMask();
        size_t pattern_len = pattern_.getLength();

        size_t i = 0;
        while (i <= data_size - pattern_len) {
            size_t j = pattern_len - 1;

            // Check pattern from right to left
            while (j >= 0 && (mask[j] == false || bytes[j] == data[i + j])) {
                if (j == 0) {
                    results.push_back(i);
                    break;
                }
                --j;
            }

            // Use bad character heuristic
            if (j < pattern_len && mask[j]) {
                uint8_t bad_char = data[i + j];
                auto it = bad_char_table_.find(bad_char);
                size_t shift = (it != bad_char_table_.end()) ? it->second : pattern_len;
                i += std::max(size_t(1), shift);
            } else {
                i += 1;
            }
        }

        return results;
    }

private:
    const Pattern& pattern_;
    std::unordered_map<uint8_t, size_t> bad_char_table_;

    void buildBadCharacterTable() {
        const auto& bytes = pattern_.getBytes();
        const auto& mask = pattern_.getMask();
        size_t pattern_len = pattern_.getLength();

        bad_char_table_.clear();

        // Only consider exact match bytes for bad character table
        for (size_t i = 0; i < pattern_len; ++i) {
            if (mask[i]) {
                bad_char_table_[bytes[i]] = pattern_len - 1 - i;
            }
        }
    }
};

// SIMD scanning implementations (stub implementations - would need platform-specific code)
class SIMDSSE2Scanner {
public:
    SIMDSSE2Scanner(const Pattern& pattern) : pattern_(pattern) {}

    std::vector<size_t> search(const uint8_t* data, size_t data_size) const {
        // For now, fall back to Boyer-Moore-Horspool
        BoyerMooreHorspool bmh(pattern_);
        return bmh.search(data, data_size);
    }

private:
    const Pattern& pattern_;
};

class SIMDAVX2Scanner {
public:
    SIMDAVX2Scanner(const Pattern& pattern) : pattern_(pattern) {}

    std::vector<size_t> search(const uint8_t* data, size_t data_size) const {
        // For now, fall back to Boyer-Moore-Horspool
        BoyerMooreHorspool bmh(pattern_);
        return bmh.search(data, data_size);
    }

private:
    const Pattern& pattern_;
};

// PatternScanner implementation

class PatternScanner::Impl {
public:
    explicit Impl(const Process& process) : process_(process) {}

    std::vector<ScanResult> scanPattern(const Pattern& pattern,
                                       const std::vector<MemoryRegion>& regions,
                                       const ScanConfig& config) const {
        std::vector<ScanResult> results;

        // Select scanning algorithm
        ScanAlgorithm algorithm = config.algorithm;
        if (algorithm == ScanAlgorithm::AUTO) {
            algorithm = selectBestAlgorithm(pattern);
        }

        // Create scanner instance
        std::unique_ptr<class ScannerBase> scanner = createScanner(pattern, algorithm);
        if (!scanner) {
            throw PatternScanError(Error::ALGORITHM_NOT_SUPPORTED);
        }

        // Scan each region
        for (const auto& region : regions) {
            if (!shouldScanRegion(region, config)) {
                continue;
            }

            auto region_results = scanRegionWithScanner(*scanner, region, config);
            results.insert(results.end(),
                          std::make_move_iterator(region_results.begin()),
                          std::make_move_iterator(region_results.end()));

            // Check result limit
            if (config.max_results > 0 && results.size() >= config.max_results) {
                results.resize(config.max_results);
                break;
            }
        }

        return results;
    }

    ScanResult findFirstPattern(const Pattern& pattern,
                               const std::vector<MemoryRegion>& regions,
                               const ScanConfig& config) const {
        ScanConfig single_config = config;
        single_config.max_results = 1;

        auto results = scanPattern(pattern, regions, single_config);
        return results.empty() ? ScanResult() : results[0];
    }

private:
    const Process& process_;

    class ScannerBase {
    public:
        virtual ~ScannerBase() = default;
        virtual std::vector<size_t> search(const uint8_t* data, size_t size) const = 0;
    };

    class BoyerMooreScanner : public ScannerBase {
    public:
        explicit BoyerMooreScanner(const Pattern& pattern) : bmh_(pattern) {}
        std::vector<size_t> search(const uint8_t* data, size_t size) const override {
            return bmh_.search(data, size);
        }
    private:
        BoyerMooreHorspool bmh_;
    };

    class SIMDSSE2ScannerWrapper : public ScannerBase {
    public:
        explicit SIMDSSE2ScannerWrapper(const Pattern& pattern) : scanner_(pattern) {}
        std::vector<size_t> search(const uint8_t* data, size_t size) const override {
            return scanner_.search(data, size);
        }
    private:
        SIMDSSE2Scanner scanner_;
    };

    class SIMDAVX2ScannerWrapper : public ScannerBase {
    public:
        explicit SIMDAVX2ScannerWrapper(const Pattern& pattern) : scanner_(pattern) {}
        std::vector<size_t> search(const uint8_t* data, size_t size) const override {
            return scanner_.search(data, size);
        }
    private:
        SIMDAVX2Scanner scanner_;
    };

    ScanAlgorithm selectBestAlgorithm(const Pattern& pattern) const {
        // For short patterns, naive might be faster due to overhead
        if (pattern.getLength() < 4) {
            return ScanAlgorithm::BOYER_MOORE_HORSPOOL;
        }

        // Check for SIMD support (simplified - would need actual CPU detection)
        // For now, default to Boyer-Moore-Horspool
        return ScanAlgorithm::BOYER_MOORE_HORSPOOL;
    }

    std::unique_ptr<ScannerBase> createScanner(const Pattern& pattern,
                                              ScanAlgorithm algorithm) const {
        switch (algorithm) {
            case ScanAlgorithm::BOYER_MOORE:
            case ScanAlgorithm::BOYER_MOORE_HORSPOOL:
                return std::make_unique<BoyerMooreScanner>(pattern);
            case ScanAlgorithm::SIMD_SSE2:
                return std::make_unique<SIMDSSE2ScannerWrapper>(pattern);
            case ScanAlgorithm::SIMD_AVX2:
                return std::make_unique<SIMDAVX2ScannerWrapper>(pattern);
            default:
                return nullptr;
        }
    }

    bool shouldScanRegion(const MemoryRegion& region, const ScanConfig& config) const {
        // Check permissions
        uint32_t required_perms = 0;
        for (uint32_t perm : config.required_permissions) {
            required_perms |= perm;
        }

        if ((region.getProtection() & required_perms) != required_perms) {
            return false;
        }

        // Check region type preferences
        auto region_type = region.getType();
        if (!config.include_shared_memory &&
            (region_type == MemoryRegion::Type::SHARED_MEMORY ||
             region.hasProtection(MemoryRegion::Protection::SHARED))) {
            return false;
        }

        if (!config.include_mapped_files &&
            region_type == MemoryRegion::Type::MAPPED_FILE) {
            return false;
        }

        // Skip regions that are too small
        if (region.getSize() < 1) {
            return false;
        }

        return true;
    }

    std::vector<ScanResult> scanRegionWithScanner(const ScannerBase& scanner,
                                                 const MemoryRegion& region,
                                                 const ScanConfig& config) const {
        std::vector<ScanResult> results;

        try {
            // Allocate buffer for region data
            std::vector<uint8_t> buffer(region.getSize());

            // Read region data
            size_t bytes_read = process_.readMemory(region.getBaseAddress(),
                                                   buffer.data(),
                                                   buffer.size());

            if (bytes_read != buffer.size()) {
                // Partial read - still try to scan what we got
                buffer.resize(bytes_read);
            }

            if (buffer.empty()) {
                return results;
            }

            // Scan the buffer
            auto offsets = scanner.search(buffer.data(), buffer.size());

            // Convert offsets to ScanResults
            for (size_t offset : offsets) {
                uintptr_t address = region.getBaseAddress() + offset;
                results.emplace_back(address, offset, &region);

                // Check result limit
                if (config.max_results > 0 && results.size() >= config.max_results) {
                    break;
                }
            }

        } catch (const std::exception&) {
            // Skip regions that can't be read
        }

        return results;
    }
};

PatternScanner::PatternScanner(const Process& process)
    : impl_(std::make_unique<Impl>(process)), last_error_(Error::SUCCESS) {
}

PatternScanner::~PatternScanner() = default;

PatternScanner::PatternScanner(PatternScanner&& other) noexcept = default;
PatternScanner& PatternScanner::operator=(PatternScanner&& other) noexcept = default;

std::vector<ScanResult> PatternScanner::scan(const Pattern& pattern,
                                           const ScanConfig& config) const {
    try {
        setLastError(Error::SUCCESS);
        auto regions = impl_->process_.enumerateRegions();
        return impl_->scanPattern(pattern, regions, config);
    } catch (const std::exception&) {
        setLastError(Error::MEMORY_READ_ERROR);
        return {};
    }
}

std::vector<ScanResult> PatternScanner::scanRegion(const Pattern& pattern,
                                                  const MemoryRegion& region,
                                                  const ScanConfig& config) const {
    try {
        setLastError(Error::SUCCESS);
        std::vector<MemoryRegion> regions = {region};
        return impl_->scanPattern(pattern, regions, config);
    } catch (const std::exception&) {
        setLastError(Error::MEMORY_READ_ERROR);
        return {};
    }
}

std::vector<ScanResult> PatternScanner::scanRegions(const Pattern& pattern,
                                                   const std::vector<MemoryRegion>& regions,
                                                   const ScanConfig& config) const {
    try {
        setLastError(Error::SUCCESS);
        return impl_->scanPattern(pattern, regions, config);
    } catch (const std::exception&) {
        setLastError(Error::MEMORY_READ_ERROR);
        return {};
    }
}

ScanResult PatternScanner::findFirst(const Pattern& pattern,
                                    const ScanConfig& config) const {
    try {
        setLastError(Error::SUCCESS);
        auto regions = impl_->process_.enumerateRegions();
        return impl_->findFirstPattern(pattern, regions, config);
    } catch (const std::exception&) {
        setLastError(Error::MEMORY_READ_ERROR);
        return ScanResult();
    }
}

uintptr_t PatternScanner::compilePattern(const Pattern& pattern,
                                       ScanAlgorithm algorithm) {
    // For now, just return a dummy handle
    // In a real implementation, this would cache compiled patterns
    static uintptr_t next_handle = 1;
    return next_handle++;
}

std::vector<ScanResult> PatternScanner::scanCompiled(uintptr_t compiled_pattern,
                                                   const ScanConfig& config) const {
    // For now, this is not implemented
    setLastError(Error::ALGORITHM_NOT_SUPPORTED);
    return {};
}

void PatternScanner::releaseCompiledPattern(uintptr_t compiled_pattern) {
    // For now, do nothing
}

std::vector<ScanAlgorithm> PatternScanner::getSupportedAlgorithms() {
    return {ScanAlgorithm::BOYER_MOORE_HORSPOOL, ScanAlgorithm::SIMD_SSE2};
}

bool PatternScanner::isAlgorithmSupported(ScanAlgorithm algorithm) {
    auto supported = getSupportedAlgorithms();
    return std::find(supported.begin(), supported.end(), algorithm) != supported.end();
}

PatternScanner::Error PatternScanner::getLastError() const {
    return last_error_;
}

std::string PatternScanner::getErrorMessage(Error error) {
    switch (error) {
        case Error::SUCCESS: return "Operation completed successfully";
        case Error::PATTERN_EMPTY: return "Pattern is empty";
        case Error::PATTERN_TOO_LONG: return "Pattern exceeds maximum supported length";
        case Error::NO_MEMORY_REGIONS: return "No memory regions available for scanning";
        case Error::SCAN_TIMEOUT: return "Scan operation timed out";
        case Error::MEMORY_READ_ERROR: return "Failed to read memory during scan";
        case Error::INVALID_CONFIG: return "Invalid scan configuration";
        case Error::ALGORITHM_NOT_SUPPORTED: return "Requested algorithm not supported on this platform";
        case Error::OUT_OF_MEMORY: return "Insufficient memory for scan operation";
        default: return "Unknown error";
    }
}

void PatternScanner::setLastError(Error error) const {
    last_error_ = error;
}

PatternScanError::PatternScanError(PatternScanner::Error error, const std::string& message)
    : std::system_error(static_cast<int>(error), std::generic_category(),
                       message.empty() ? PatternScanner::getErrorMessage(error) : message) {
}

} // namespace memscan
