/**
 * @file ScanBenchmarks.cpp
 * @brief Performance benchmarks for pattern scanning algorithms
 *
 * @author Memory Scanner Utility
 * @version 1.0.0
 * @date 2025
 */

#include <benchmark/benchmark.h>
#include <memscan/memscan.hpp>
#include <vector>
#include <random>
#include <algorithm>

using namespace memscan;

// Global test data
class BenchmarkData {
public:
    static BenchmarkData& getInstance() {
        static BenchmarkData instance;
        return instance;
    }

    const std::vector<uint8_t>& getSmallData() const { return small_data_; }
    const std::vector<uint8_t>& getMediumData() const { return medium_data_; }
    const std::vector<uint8_t>& getLargeData() const { return large_data_; }

    std::vector<Pattern> getTestPatterns() const { return test_patterns_; }

private:
    BenchmarkData() {
        // Generate test data of different sizes
        generateTestData();
        generateTestPatterns();
    }

    void generateTestData() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dist(0, 255);

        // Small data: 64KB
        small_data_.resize(64 * 1024);
        std::generate(small_data_.begin(), small_data_.end(), [&]() { return dist(gen); });

        // Medium data: 1MB
        medium_data_.resize(1024 * 1024);
        std::generate(medium_data_.begin(), medium_data_.end(), [&]() { return dist(gen); });

        // Large data: 16MB
        large_data_.resize(16 * 1024 * 1024);
        std::generate(large_data_.begin(), large_data_.end(), [&]() { return dist(gen); });

        // Insert some known patterns for testing
        insertTestPatterns(small_data_, 100);
        insertTestPatterns(medium_data_, 1000);
        insertTestPatterns(large_data_, 10000);
    }

    void generateTestPatterns() {
        // Various pattern types and lengths
        test_patterns_ = {
            Pattern("00"),                    // Single byte
            Pattern("00 00"),                 // Two bytes
            Pattern("00 00 00 00"),           // Four bytes
            Pattern("48 89"),                 // Common instruction prefix
            Pattern("48 89 ?? ??"),           // With wildcards
            Pattern("55 48 89 E5"),           // Function prologue
            Pattern("FF FF FF FF"),           // Four FF bytes
            Pattern("90 90 90 90"),           // NOP sled
            Pattern("00 00 ?? ?? 00 00"),     // Pattern with wildcards
            Pattern("48 8B ?? ?? ?? ?? ??"),   // Complex instruction
            Pattern("C3"),                    // Return instruction
            Pattern("48 31 C0 48 31 D2"),     // Zero registers
            Pattern("0F 05"),                 // syscall
            Pattern("CC CC CC CC"),           // Debug breakpoints
        };
    }

    void insertTestPatterns(std::vector<uint8_t>& data, size_t count) {
        std::random_device rd;
        std::mt19937 gen(rd());

        for (const auto& pattern : test_patterns_) {
            for (size_t i = 0; i < count; ++i) {
                std::uniform_int_distribution<size_t> pos_dist(0, data.size() - pattern.getLength());
                size_t pos = pos_dist(gen);

                const auto& bytes = pattern.getBytes();
                const auto& mask = pattern.getMask();

                for (size_t j = 0; j < pattern.getLength(); ++j) {
                    if (mask[j]) {  // Only overwrite exact match bytes
                        data[pos + j] = bytes[j];
                    }
                }
            }
        }
    }

    std::vector<uint8_t> small_data_;
    std::vector<uint8_t> medium_data_;
    std::vector<uint8_t> large_data_;
    std::vector<Pattern> test_patterns_;
};

// Mock memory scanner for benchmarking (simulates the interface)
class MockMemoryScanner {
public:
    std::vector<size_t> scanPattern(const Pattern& pattern, const uint8_t* data, size_t size) {
        std::vector<size_t> results;

        if (pattern.getLength() == 0 || pattern.getLength() > size) {
            return results;
        }

        const auto& bytes = pattern.getBytes();
        const auto& mask = pattern.getMask();
        size_t pattern_len = pattern.getLength();

        // Simple linear search (naive algorithm)
        for (size_t i = 0; i <= size - pattern_len; ++i) {
            bool match = true;
            for (size_t j = 0; j < pattern_len; ++j) {
                if (mask[j] && bytes[j] != data[i + j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                results.push_back(i);
            }
        }

        return results;
    }
};

// Boyer-Moore-Horspool implementation for benchmarking
class BMHScanner {
public:
    std::vector<size_t> scanPattern(const Pattern& pattern, const uint8_t* data, size_t size) {
        std::vector<size_t> results;

        if (pattern.getLength() == 0 || pattern.getLength() > size) {
            return results;
        }

        const auto& bytes = pattern.getBytes();
        const auto& mask = pattern.getMask();
        size_t pattern_len = pattern.getLength();

        // Build bad character table (only for exact match bytes)
        std::unordered_map<uint8_t, size_t> bad_char;
        for (size_t i = 0; i < pattern_len; ++i) {
            if (mask[i]) {
                bad_char[bytes[i]] = pattern_len - 1 - i;
            }
        }

        size_t i = 0;
        while (i <= size - pattern_len) {
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
                auto it = bad_char.find(data[i + j]);
                size_t shift = (it != bad_char.end()) ? it->second : pattern_len;
                i += std::max(size_t(1), shift);
            } else {
                i += 1;
            }
        }

        return results;
    }
};

// Benchmark fixture
class ScanBenchmark : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State& state) {
        data_size_ = static_cast<size_t>(state.range(0));
        const auto& data = getDataForSize(data_size_);
        data_.assign(data.begin(), data.end());
    }

    void TearDown(const ::benchmark::State& state) {}

    const std::vector<uint8_t>& getData() const { return data_; }
    const std::vector<Pattern>& getPatterns() const {
        return BenchmarkData::getInstance().getTestPatterns();
    }

private:
    const std::vector<uint8_t>& getDataForSize(size_t size) {
        const auto& instance = BenchmarkData::getInstance();
        if (size <= 64 * 1024) {
            return instance.getSmallData();
        } else if (size <= 1024 * 1024) {
            return instance.getMediumData();
        } else {
            return instance.getLargeData();
        }
    }

    std::vector<uint8_t> data_;
    size_t data_size_;
};

// Benchmark naive scanning
BENCHMARK_DEFINE_F(ScanBenchmark, NaiveScan)(benchmark::State& state) {
    MockMemoryScanner scanner;
    const auto& patterns = getPatterns();
    const auto& data = getData();

    for (auto _ : state) {
        for (const auto& pattern : patterns) {
            auto results = scanner.scanPattern(pattern, data.data(), data.size());
            benchmark::DoNotOptimize(results);
        }
    }

    state.SetItemsProcessed(patterns.size() * state.iterations());
}

// Benchmark Boyer-Moore-Horspool scanning
BENCHMARK_DEFINE_F(ScanBenchmark, BMHScan)(benchmark::State& state) {
    BMHScanner scanner;
    const auto& patterns = getPatterns();
    const auto& data = getData();

    for (auto _ : state) {
        for (const auto& pattern : patterns) {
            auto results = scanner.scanPattern(pattern, data.data(), data.size());
            benchmark::DoNotOptimize(results);
        }
    }

    state.SetItemsProcessed(patterns.size() * state.iterations());
}

// Register benchmarks with different data sizes
BENCHMARK_REGISTER_F(ScanBenchmark, NaiveScan)
    ->Arg(64 * 1024)      // 64KB
    ->Arg(1024 * 1024)    // 1MB
    ->Arg(16 * 1024 * 1024); // 16MB

BENCHMARK_REGISTER_F(ScanBenchmark, BMHScan)
    ->Arg(64 * 1024)      // 64KB
    ->Arg(1024 * 1024)    // 1MB
    ->Arg(16 * 1024 * 1024); // 16MB

// Benchmark pattern compilation time
static void BM_PatternCompilation(benchmark::State& state) {
    const auto& patterns = BenchmarkData::getInstance().getTestPatterns();
    std::vector<std::string> pattern_strings = {
        "00", "00 00", "00 00 00 00", "48 89 ?? ??", "55 48 89 E5",
        "FF FF FF FF", "90 90 90 90", "00 00 ?? ?? 00 00",
        "48 8B ?? ?? ?? ?? ??", "C3", "48 31 C0 48 31 D2"
    };

    for (auto _ : state) {
        for (const auto& pattern_str : pattern_strings) {
            Pattern pattern(pattern_str);
            benchmark::DoNotOptimize(pattern);
        }
    }

    state.SetItemsProcessed(pattern_strings.size() * state.iterations());
}
BENCHMARK(BM_PatternCompilation);

// Benchmark memory region enumeration
static void BM_MemoryRegionEnumeration(benchmark::State& state) {
    Process process;

    for (auto _ : state) {
        auto regions = process.enumerateRegions();
        benchmark::DoNotOptimize(regions);
    }
}
BENCHMARK(BM_MemoryRegionEnumeration);

// Benchmark memory reading
static void BM_MemoryRead(benchmark::State& state) {
    Process process;
    auto regions = process.enumerateRegions(MemoryRegion::READ);

    if (regions.empty()) {
        state.SkipWithError("No readable memory regions found");
        return;
    }

    const auto& region = regions[0];
    size_t read_size = std::min(static_cast<size_t>(state.range(0)),
                               region.getSize());
    std::vector<uint8_t> buffer(read_size);

    for (auto _ : state) {
        size_t bytes_read = process.readMemory(region.getBaseAddress(),
                                             buffer.data(), buffer.size());
        benchmark::DoNotOptimize(bytes_read);
    }

    state.SetBytesProcessed(read_size * state.iterations());
}
BENCHMARK(BM_MemoryRead)->Arg(1024)->Arg(4096)->Arg(16384);

// Benchmark different pattern types
static void BM_PatternTypes(benchmark::State& state) {
    const auto& data = BenchmarkData::getInstance().getLargeData();
    MockMemoryScanner scanner;

    std::vector<Pattern> patterns;
    switch (state.range(0)) {
        case 0: patterns = {Pattern("00")}; break;                    // Single byte
        case 1: patterns = {Pattern("00 00")}; break;                 // Two bytes
        case 2: patterns = {Pattern("00 00 00 00")}; break;           // Four bytes
        case 3: patterns = {Pattern("48 89 ?? ??")}; break;           // With wildcards
        case 4: patterns = {Pattern("55 48 89 E5")}; break;           // Function prologue
        case 5: patterns = {Pattern("00 00 ?? ?? 00 00")}; break;     // Complex with wildcards
        default: patterns = {Pattern("00")};
    }

    for (auto _ : state) {
        for (const auto& pattern : patterns) {
            auto results = scanner.scanPattern(pattern, data.data(), data.size());
            benchmark::DoNotOptimize(results);
        }
    }

    state.SetItemsProcessed(patterns.size() * state.iterations());
}
BENCHMARK(BM_PatternTypes)->DenseRange(0, 5);

// Benchmark scanning with different result limits
static void BM_ScanLimits(benchmark::State& state) {
    Process process;
    PatternScanner scanner(process);
    Pattern pattern("00 00 00 00");

    ScanConfig config;
    config.max_results = static_cast<size_t>(state.range(0));

    for (auto _ : state) {
        auto results = scanner.scan(pattern, config);
        benchmark::DoNotOptimize(results);
    }
}
BENCHMARK(BM_ScanLimits)->Arg(1)->Arg(10)->Arg(100)->Arg(0); // 0 = unlimited

BENCHMARK_MAIN();
