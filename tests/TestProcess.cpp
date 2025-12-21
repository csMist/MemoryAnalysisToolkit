/**
 * @file TestProcess.cpp
 * @brief Unit tests for Process class
 *
 * @author Memory Scanner Utility
 * @version 1.0.0
 * @date 2025
 */

#include <gtest/gtest.h>
#include "memscan/Process.hpp"

using namespace memscan;

class ProcessTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a process handle to the current process
        current_process_ = std::make_unique<Process>();
    }

    std::unique_ptr<Process> current_process_;
};

TEST_F(ProcessTest, CurrentProcessConstruction) {
    ASSERT_TRUE(current_process_);
    EXPECT_TRUE(current_process_->isRunning());
    EXPECT_NE(current_process_->getPid(), 0);

    // Name should be non-empty (though exact name depends on platform)
    std::string name = current_process_->getName();
    EXPECT_FALSE(name.empty());
}

TEST_F(ProcessTest, ProcessIdValidity) {
    uint32_t pid = current_process_->getPid();
    EXPECT_GT(pid, 0);

    // Test that we can create another Process with the same PID
    Process same_process(pid);
    EXPECT_EQ(same_process.getPid(), pid);
    EXPECT_TRUE(same_process.isRunning());
}

TEST_F(ProcessTest, MemoryRegionsEnumeration) {
    auto regions = current_process_->enumerateRegions();
    EXPECT_FALSE(regions.empty());

    // Verify that regions have valid properties
    for (const auto& region : regions) {
        EXPECT_GE(region.getBaseAddress(), 0);
        EXPECT_GT(region.getSize(), 0);
        EXPECT_LE(region.getBaseAddress() + region.getSize(), UINTPTR_MAX);

        // At least one permission should be set for committed regions
        EXPECT_NE(region.getProtection(), 0);
    }

    // Test filtered enumeration
    auto readable_regions = current_process_->enumerateRegions(MemoryRegion::READ);
    EXPECT_FALSE(readable_regions.empty());

    // All returned regions should be readable
    for (const auto& region : readable_regions) {
        EXPECT_TRUE(region.isReadable());
    }

    // Should have fewer or equal readable regions than total regions
    EXPECT_LE(readable_regions.size(), regions.size());
}

TEST_F(ProcessTest, MemoryReadOperations) {
    auto regions = current_process_->enumerateRegions(MemoryRegion::READ);
    ASSERT_FALSE(regions.empty());

    // Find a readable region with some data
    const MemoryRegion* test_region = nullptr;
    for (const auto& region : regions) {
        if (region.getSize() >= sizeof(uint32_t)) {
            test_region = &region;
            break;
        }
    }
    ASSERT_TRUE(test_region);

    // Test reading a uint32_t
    uint32_t value;
    bool success = current_process_->readMemory(test_region->getBaseAddress(), value);
    EXPECT_TRUE(success);

    // Test reading raw bytes
    std::vector<uint8_t> buffer(16);
    size_t bytes_read = current_process_->readMemory(test_region->getBaseAddress(),
                                                   buffer.data(), buffer.size());
    EXPECT_EQ(bytes_read, buffer.size());
}

TEST_F(ProcessTest, AddressValidation) {
    auto regions = current_process_->enumerateRegions();
    ASSERT_FALSE(regions.empty());

    // Test valid addresses within regions
    const auto& first_region = regions[0];
    EXPECT_TRUE(current_process_->isAddressValid(first_region.getBaseAddress()));
    EXPECT_TRUE(current_process_->isAddressValid(first_region.getBaseAddress(),
                                               first_region.getSize()));

    // Test address at region boundary
    EXPECT_TRUE(current_process_->isAddressValid(first_region.getBaseAddress(),
                                               first_region.getSize() - 1));

    // Test invalid addresses
    EXPECT_FALSE(current_process_->isAddressValid(0));
    EXPECT_FALSE(current_process_->isAddressValid(UINTPTR_MAX));
    EXPECT_FALSE(current_process_->isAddressValid(first_region.getEndAddress()));
}

TEST_F(ProcessTest, ErrorHandling) {
    // Test reading from invalid address
    uint32_t value;
    size_t bytes_read = current_process_->readMemory(0, &value, sizeof(value));
    EXPECT_EQ(bytes_read, 0);
    EXPECT_EQ(current_process_->getLastError(), Process::Error::INVALID_ADDRESS);

    // Test reading with null buffer
    bytes_read = current_process_->readMemory(current_process_->getPid(), nullptr, 0);
    EXPECT_EQ(bytes_read, 0);

    // Test zero-size read
    bytes_read = current_process_->readMemory(current_process_->getPid(), &value, 0);
    EXPECT_EQ(bytes_read, 0);
}

TEST_F(ProcessTest, ProcessLookup) {
    uint32_t current_pid = current_process_->getPid();

    // Test finding current process by PID
    Process found_by_pid(current_pid);
    EXPECT_EQ(found_by_pid.getPid(), current_pid);
    EXPECT_TRUE(found_by_pid.isRunning());

    // Test that process name lookup works (if supported on platform)
    std::string current_name = current_process_->getName();
    if (!current_name.empty()) {
        try {
            Process found_by_name(current_name);
            // This might fail if there are multiple processes with the same name
            // or if name lookup is not supported
            EXPECT_TRUE(found_by_name.isRunning());
        } catch (const ProcessError&) {
            // Name lookup might not be supported or might be ambiguous
            SUCCEED();
        }
    }
}

TEST_F(ProcessTest, InvalidProcessHandling) {
    // Test with non-existent PID
    EXPECT_THROW({
        Process invalid_process(999999);
    }, ProcessError);

    // Test with invalid process name
    EXPECT_THROW({
        Process invalid_process("non_existent_process_name_12345");
    }, ProcessError);
}

TEST_F(ProcessTest, ErrorMessages) {
    EXPECT_EQ(Process::getErrorMessage(Process::Error::SUCCESS), "Operation succeeded");
    EXPECT_EQ(Process::getErrorMessage(Process::Error::PROCESS_NOT_FOUND), "Process not found");
    EXPECT_EQ(Process::getErrorMessage(Process::Error::ACCESS_DENIED), "Access denied");
    EXPECT_EQ(Process::getErrorMessage(Process::Error::INVALID_ADDRESS), "Invalid memory address");
    EXPECT_EQ(Process::getErrorMessage(Process::Error::MEMORY_READ_FAILED), "Memory read failed");
    EXPECT_EQ(Process::getErrorMessage(Process::Error::MEMORY_WRITE_FAILED), "Memory write failed");
}
