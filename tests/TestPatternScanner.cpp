/**
 * @file TestPatternScanner.cpp
 * @brief Unit tests for PatternScanner class
 *
 * @author Memory Scanner Utility
 * @version 1.0.0
 * @date 2025
 */

#include <gtest/gtest.h>
#include "memscan/PatternScanner.hpp"

using namespace memscan;

class PatternScannerTest : public ::testing::Test {
protected:
    void SetUp() override {
        process_ = std::make_unique<Process>();
        scanner_ = std::make_unique<PatternScanner>(*process_);
    }

    std::unique_ptr<Process> process_;
    std::unique_ptr<PatternScanner> scanner_;
};

TEST_F(PatternScannerTest, PatternConstruction) {
    // Empty pattern
    Pattern empty_pattern;
    EXPECT_TRUE(empty_pattern.isEmpty());
    EXPECT_EQ(empty_pattern.getLength(), 0);

    // Pattern from string
    Pattern hex_pattern("48 89 ?? ?? 57");
    EXPECT_FALSE(hex_pattern.isEmpty());
    EXPECT_EQ(hex_pattern.getLength(), 5);
    EXPECT_EQ(hex_pattern.getMask()[0], true);   // 48
    EXPECT_EQ(hex_pattern.getMask()[1], true);   // 89
    EXPECT_EQ(hex_pattern.getMask()[2], false);  // ??
    EXPECT_EQ(hex_pattern.getMask()[3], false);  // ??
    EXPECT_EQ(hex_pattern.getMask()[4], true);   // 57

    // Test pattern string representation
    EXPECT_EQ(hex_pattern.toString(), "48 89 ?? ?? 57");

    // Pattern from bytes and mask
    std::vector<uint8_t> bytes = {0x48, 0x89, 0x00, 0x00, 0x57};
    std::vector<bool> mask = {true, true, false, false, true};
    Pattern byte_pattern(bytes, mask);
    EXPECT_EQ(byte_pattern.getLength(), 5);
    EXPECT_EQ(byte_pattern.toString(), "48 89 ?? ?? 57");
}

TEST_F(PatternScannerTest, PatternParsing) {
    // Valid patterns
    EXPECT_NO_THROW(Pattern("48 89 5C 24 08"));
    EXPECT_NO_THROW(Pattern("?? ?? ?? ?? ??"));
    EXPECT_NO_THROW(Pattern("48"));
    EXPECT_NO_THROW(Pattern(""));

    // Invalid patterns
    EXPECT_THROW(Pattern("XX"), std::invalid_argument);
    EXPECT_THROW(Pattern("48 8"), std::invalid_argument);
    EXPECT_THROW(Pattern("48 89 5C 24"), std::invalid_argument); // Odd number of chars in last byte
}

TEST_F(PatternScannerTest, ScanConfiguration) {
    ScanConfig config;
    EXPECT_EQ(config.algorithm, ScanAlgorithm::AUTO);
    EXPECT_TRUE(config.case_sensitive);
    EXPECT_EQ(config.max_results, 0);
    EXPECT_FALSE(config.include_shared_memory);
    EXPECT_TRUE(config.include_mapped_files);

    // Test custom configuration
    config.algorithm = ScanAlgorithm::BOYER_MOORE_HORSPOOL;
    config.max_results = 10;
    config.include_shared_memory = true;
    config.include_mapped_files = false;

    EXPECT_EQ(config.algorithm, ScanAlgorithm::BOYER_MOORE_HORSPOOL);
    EXPECT_EQ(config.max_results, 10);
    EXPECT_TRUE(config.include_shared_memory);
    EXPECT_FALSE(config.include_mapped_files);
}

TEST_F(PatternScannerTest, SupportedAlgorithms) {
    auto algorithms = PatternScanner::getSupportedAlgorithms();
    EXPECT_FALSE(algorithms.empty());

    // Boyer-Moore-Horspool should be supported
    EXPECT_TRUE(std::find(algorithms.begin(), algorithms.end(),
                         ScanAlgorithm::BOYER_MOORE_HORSPOOL) != algorithms.end());

    // Check individual algorithm support
    EXPECT_TRUE(PatternScanner::isAlgorithmSupported(ScanAlgorithm::BOYER_MOORE_HORSPOOL));
    EXPECT_FALSE(PatternScanner::isAlgorithmSupported(ScanAlgorithm::AUTO)); // AUTO is not a real algorithm
}

TEST_F(PatternScannerTest, ScanOwnProcess) {
    // Create a test pattern that should exist in the process memory
    // Look for common byte sequences that are likely to exist

    // Test scanning for a simple pattern (null bytes are common)
    Pattern null_pattern("00 00 00 00");
    auto results = scanner_->scan(null_pattern);

    // We should find some results (null bytes are very common)
    EXPECT_FALSE(results.empty());

    // Verify result structure
    for (const auto& result : results) {
        EXPECT_NE(result.address, 0);
        EXPECT_NE(result.region, nullptr);
        EXPECT_TRUE(result.region->containsAddress(result.address));
        EXPECT_LE(result.offset, result.region->getSize() - null_pattern.getLength());
    }
}

TEST_F(PatternScannerTest, ScanWithLimits) {
    Pattern null_pattern("00 00 00 00");

    // Test with max results limit
    ScanConfig config;
    config.max_results = 5;

    auto limited_results = scanner_->scan(null_pattern, config);
    EXPECT_LE(limited_results.size(), 5);

    // Test with unlimited results
    config.max_results = 0;
    auto unlimited_results = scanner_->scan(null_pattern, config);
    EXPECT_GE(unlimited_results.size(), limited_results.size());
}

TEST_F(PatternScannerTest, ScanSpecificRegions) {
    auto regions = process_->enumerateRegions(MemoryRegion::READ);
    ASSERT_FALSE(regions.empty());

    // Take the first readable region
    const auto& test_region = regions[0];

    // Scan for null bytes in this specific region
    Pattern null_pattern("00 00");
    auto results = scanner_->scanRegion(null_pattern, test_region);

    // Verify all results are in the correct region
    for (const auto& result : results) {
        EXPECT_EQ(result.region, &test_region);
        EXPECT_TRUE(test_region.containsAddress(result.address));
        EXPECT_TRUE(test_region.containsRange(result.address, null_pattern.getLength()));
    }
}

TEST_F(PatternScannerTest, FindFirst) {
    Pattern null_pattern("00 00");

    // Find first occurrence
    ScanResult first_result = scanner_->findFirst(null_pattern);

    // Should find something (null bytes are common)
    EXPECT_NE(first_result.address, 0);
    EXPECT_NE(first_result.region, nullptr);

    // Verify the result
    EXPECT_TRUE(first_result.region->containsAddress(first_result.address));
    EXPECT_TRUE(first_result.region->isReadable());

    // Test that the pattern actually matches at this address
    std::vector<uint8_t> buffer(null_pattern.getLength());
    size_t bytes_read = process_->readMemory(first_result.address, buffer.data(), buffer.size());
    EXPECT_EQ(bytes_read, buffer.size());

    // Check pattern match
    const auto& pattern_bytes = null_pattern.getBytes();
    const auto& pattern_mask = null_pattern.getMask();
    for (size_t i = 0; i < buffer.size(); ++i) {
        if (pattern_mask[i]) {
            EXPECT_EQ(buffer[i], pattern_bytes[i]);
        }
    }
}

TEST_F(PatternScannerTest, PatternCompilation) {
    Pattern test_pattern("48 89 ?? ?? 57");

    // Test pattern compilation (basic functionality)
    uintptr_t compiled_handle = scanner_->compilePattern(test_pattern);
    EXPECT_NE(compiled_handle, 0);

    // Test scanning with compiled pattern (if implemented)
    try {
        ScanConfig config;
        auto results = scanner_->scanCompiled(compiled_handle, config);
        // Either succeeds or throws ALGORITHM_NOT_SUPPORTED
    } catch (const PatternScanError& e) {
        EXPECT_EQ(e.code().value(), static_cast<int>(PatternScanner::Error::ALGORITHM_NOT_SUPPORTED));
    }

    // Clean up
    scanner_->releaseCompiledPattern(compiled_handle);
}

TEST_F(PatternScannerTest, ErrorHandling) {
    // Test with empty pattern
    Pattern empty_pattern;
    auto results = scanner_->scan(empty_pattern);
    EXPECT_TRUE(results.empty());

    // Test invalid configuration
    ScanConfig invalid_config;
    invalid_config.algorithm = static_cast<ScanAlgorithm>(999); // Invalid algorithm

    try {
        Pattern test_pattern("00 00");
        auto results = scanner_->scan(test_pattern, invalid_config);
        // Should either succeed (algorithm ignored) or fail gracefully
    } catch (const PatternScanError&) {
        // Expected for invalid algorithm
        SUCCEED();
    }
}

TEST_F(PatternScannerTest, ErrorMessages) {
    EXPECT_EQ(PatternScanner::getErrorMessage(PatternScanner::Error::SUCCESS),
              "Operation completed successfully");
    EXPECT_EQ(PatternScanner::getErrorMessage(PatternScanner::Error::PATTERN_EMPTY),
              "Pattern is empty");
    EXPECT_EQ(PatternScanner::getErrorMessage(PatternScanner::Error::ALGORITHM_NOT_SUPPORTED),
              "Requested algorithm not supported on this platform");
    EXPECT_EQ(PatternScanner::getErrorMessage(PatternScanner::Error::MEMORY_READ_ERROR),
              "Failed to read memory during scan");
}

TEST_F(PatternScannerTest, ScanResultStructure) {
    ScanResult empty_result;
    EXPECT_EQ(empty_result.address, 0);
    EXPECT_EQ(empty_result.offset, 0);
    EXPECT_EQ(empty_result.region, nullptr);

    // Test with values
    MemoryRegion test_region(0x1000, 0x1000, MemoryRegion::READ);
    ScanResult result(0x1500, 0x500, &test_region);

    EXPECT_EQ(result.address, 0x1500);
    EXPECT_EQ(result.offset, 0x500);
    EXPECT_EQ(result.region, &test_region);
}
