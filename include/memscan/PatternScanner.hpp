/**
 * @file PatternScanner.hpp
 * @brief Memory pattern scanning and search algorithms
 *
 * This file provides the PatternScanner class for efficient byte pattern
 * scanning in memory regions, supporting wildcards and multiple algorithms.
 *
 * @author Memory Scanner Utility
 * @version 1.0.0
 * @date 2025
 *
 * @copyright For educational and debugging purposes only.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>

#include "Process.hpp"
#include "MemoryRegion.hpp"

namespace memscan {

/**
 * @brief Represents a memory pattern with optional wildcards
 *
 * A pattern consists of bytes and wildcard markers ('??') that match any byte.
 * Patterns are specified as hex strings like "48 89 ?? ?? 57" where ?? are wildcards.
 */
class Pattern {
public:
    /**
     * @brief Construct an empty pattern
     */
    Pattern();

    /**
     * @brief Construct a pattern from a hex string
     *
     * @param pattern Hex string with optional wildcards (e.g., "48 89 ?? ?? 57")
     * @throws std::invalid_argument if pattern format is invalid
     */
    explicit Pattern(const std::string& pattern);

    /**
     * @brief Construct a pattern from bytes and mask
     *
     * @param bytes Byte array
     * @param mask Boolean mask where true indicates the byte must match exactly
     */
    Pattern(const std::vector<uint8_t>& bytes, const std::vector<bool>& mask);

    /**
     * @brief Get the pattern bytes
     *
     * @return Const reference to byte vector
     */
    const std::vector<uint8_t>& getBytes() const;

    /**
     * @brief Get the pattern mask
     *
     * @return Const reference to mask vector (true = exact match, false = wildcard)
     */
    const std::vector<bool>& getMask() const;

    /**
     * @brief Get the pattern length
     *
     * @return Number of bytes in the pattern
     */
    size_t getLength() const;

    /**
     * @brief Check if the pattern is empty
     *
     * @return true if pattern is empty, false otherwise
     */
    bool isEmpty() const;

    /**
     * @brief Get the pattern as a hex string
     *
     * @return Hex string representation with wildcards
     */
    std::string toString() const;

    /**
     * @brief Parse a hex string pattern
     *
     * @param pattern Hex string with optional wildcards
     * @return Pair of bytes and mask vectors
     * @throws std::invalid_argument if pattern format is invalid
     */
    static std::pair<std::vector<uint8_t>, std::vector<bool>>
        parsePattern(const std::string& pattern);

private:
    std::vector<uint8_t> bytes_;  ///< Pattern bytes
    std::vector<bool> mask_;      ///< Mask indicating which bytes are wildcards
};

/**
 * @brief Result of a pattern scan operation
 */
struct ScanResult {
    uintptr_t address;      ///< Address where pattern was found
    size_t offset;          ///< Offset within the memory region
    const MemoryRegion* region;  ///< Memory region containing the match

    /**
     * @brief Construct a ScanResult
     *
     * @param addr Address of the match
     * @param off Offset within region
     * @param reg Pointer to the memory region
     */
    ScanResult(uintptr_t addr = 0, size_t off = 0,
               const MemoryRegion* reg = nullptr)
        : address(addr), offset(off), region(reg) {}
};

/**
 * @brief Pattern scanning algorithms
 */
enum class ScanAlgorithm {
    NAIVE,              ///< Simple linear search (slowest)
    BOYER_MOORE,        ///< Boyer-Moore algorithm (fast)
    BOYER_MOORE_HORSPOOL,  ///< Boyer-Moore-Horspool (fastest for most cases)
    SIMD_SSE2,          ///< SSE2 optimized scanning (if available)
    SIMD_AVX2,          ///< AVX2 optimized scanning (if available)
    AUTO                ///< Automatically choose best algorithm
};

/**
 * @brief Configuration for pattern scanning operations
 */
struct ScanConfig {
    ScanAlgorithm algorithm = ScanAlgorithm::AUTO;  ///< Scanning algorithm to use
    bool case_sensitive = true;     ///< Whether pattern matching is case-sensitive (unused for byte patterns)
    size_t max_results = 0;         ///< Maximum number of results (0 = unlimited)
    std::vector<uint32_t> required_permissions = {static_cast<uint32_t>(MemoryRegion::READ)};  ///< Required memory permissions
    bool include_shared_memory = false;  ///< Whether to scan shared memory regions
    bool include_mapped_files = true;    ///< Whether to scan memory-mapped files
};

/**
 * @brief Memory pattern scanner with multiple algorithms
 *
 * The PatternScanner class provides efficient byte pattern scanning across
 * process memory regions using various algorithms including Boyer-Moore-Horspool
 * and SIMD-optimized variants.
 */
class PatternScanner {
public:
    /**
     * @brief Error codes for scanning operations
     */
    enum class Error {
        SUCCESS = 0,                ///< Scan completed successfully
        PATTERN_EMPTY = 1,          ///< Pattern is empty
        PATTERN_TOO_LONG = 2,       ///< Pattern exceeds maximum supported length
        NO_MEMORY_REGIONS = 3,      ///< No memory regions available for scanning
        SCAN_TIMEOUT = 4,           ///< Scan operation timed out
        MEMORY_READ_ERROR = 5,      ///< Failed to read memory during scan
        INVALID_CONFIG = 6,         ///< Invalid scan configuration
        ALGORITHM_NOT_SUPPORTED = 7, ///< Requested algorithm not supported on this platform
        OUT_OF_MEMORY = 8           ///< Insufficient memory for scan operation
    };

    /**
     * @brief Construct a PatternScanner for a process
     *
     * @param process Process to scan (must remain valid during scanning)
     */
    explicit PatternScanner(const Process& process);

    /**
     * @brief Destructor
     */
    ~PatternScanner();

    // Delete copy operations
    PatternScanner(const PatternScanner&) = delete;
    PatternScanner& operator=(const PatternScanner&) = delete;

    // Allow move operations
    PatternScanner(PatternScanner&& other) noexcept;
    PatternScanner& operator=(PatternScanner&& other) noexcept;

    /**
     * @brief Scan for a pattern across all suitable memory regions
     *
     * @param pattern Pattern to search for
     * @param config Scan configuration
     * @return Vector of ScanResult objects containing match locations
     * @throws std::system_error if scanning fails
     */
    std::vector<ScanResult> scan(const Pattern& pattern,
                                const ScanConfig& config = ScanConfig{}) const;

    /**
     * @brief Scan for a pattern in a specific memory region
     *
     * @param pattern Pattern to search for
     * @param region Memory region to scan
     * @param config Scan configuration
     * @return Vector of ScanResult objects containing match locations
     * @throws std::system_error if scanning fails
     */
    std::vector<ScanResult> scanRegion(const Pattern& pattern,
                                      const MemoryRegion& region,
                                      const ScanConfig& config = ScanConfig{}) const;

    /**
     * @brief Scan for a pattern in multiple specific regions
     *
     * @param pattern Pattern to search for
     * @param regions Memory regions to scan
     * @param config Scan configuration
     * @return Vector of ScanResult objects containing match locations
     * @throws std::system_error if scanning fails
     */
    std::vector<ScanResult> scanRegions(const Pattern& pattern,
                                       const std::vector<MemoryRegion>& regions,
                                       const ScanConfig& config = ScanConfig{}) const;

    /**
     * @brief Find the first occurrence of a pattern
     *
     * @param pattern Pattern to search for
     * @param config Scan configuration
     * @return ScanResult with first match, or empty result if not found
     * @throws std::system_error if scanning fails
     */
    ScanResult findFirst(const Pattern& pattern,
                        const ScanConfig& config = ScanConfig{}) const;

    /**
     * @brief Precompile a pattern for repeated scanning
     *
     * @param pattern Pattern to precompile
     * @param algorithm Algorithm to use for scanning
     * @return Handle to the compiled pattern (use with scanCompiled)
     * @throws std::system_error if compilation fails
     */
    uintptr_t compilePattern(const Pattern& pattern,
                           ScanAlgorithm algorithm = ScanAlgorithm::AUTO);

    /**
     * @brief Scan using a precompiled pattern
     *
     * @param compiled_pattern Handle from compilePattern
     * @param config Scan configuration
     * @return Vector of ScanResult objects containing match locations
     * @throws std::system_error if scanning fails
     */
    std::vector<ScanResult> scanCompiled(uintptr_t compiled_pattern,
                                        const ScanConfig& config = ScanConfig{}) const;

    /**
     * @brief Release a compiled pattern
     *
     * @param compiled_pattern Handle to release
     */
    void releaseCompiledPattern(uintptr_t compiled_pattern);

    /**
     * @brief Get supported algorithms on this platform
     *
     * @return Vector of supported ScanAlgorithm values
     */
    static std::vector<ScanAlgorithm> getSupportedAlgorithms();

    /**
     * @brief Check if an algorithm is supported
     *
     * @param algorithm Algorithm to check
     * @return true if supported, false otherwise
     */
    static bool isAlgorithmSupported(ScanAlgorithm algorithm);

    /**
     * @brief Get the last error code
     *
     * @return Last error code
     */
    Error getLastError() const;

    /**
     * @brief Get a human-readable error message
     *
     * @param error Error code to convert to string
     * @return Error message string
     */
    static std::string getErrorMessage(Error error);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;  ///< Platform-specific implementation
    mutable Error last_error_;    ///< Last error that occurred

    /**
     * @brief Set the last error code
     *
     * @param error Error code to set
     */
    void setLastError(Error error) const;
};

/**
 * @brief Exception class for pattern scanning errors
 */
class PatternScanError : public std::system_error {
public:
    /**
     * @brief Construct a PatternScanError
     *
     * @param error Scanner-specific error code
     * @param message Additional error message
     */
    PatternScanError(PatternScanner::Error error, const std::string& message = "");
};

} // namespace memscan
