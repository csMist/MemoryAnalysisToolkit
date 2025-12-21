/**
 * @file TestMemoryRegion.cpp
 * @brief Unit tests for MemoryRegion class
 *
 * @author Memory Scanner Utility
 * @version 1.0.0
 * @date 2025
 */

#include <gtest/gtest.h>
#include "memscan/MemoryRegion.hpp"

using namespace memscan;

class MemoryRegionTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test region at address 0x1000 with size 0x1000
        test_region_ = MemoryRegion(0x1000, 0x1000, MemoryRegion::READ | MemoryRegion::WRITE);
    }

    MemoryRegion test_region_;
};

TEST_F(MemoryRegionTest, Construction) {
    // Default construction
    MemoryRegion default_region;
    EXPECT_EQ(default_region.getBaseAddress(), 0);
    EXPECT_EQ(default_region.getSize(), 0);
    EXPECT_EQ(default_region.getProtection(), 0);

    // Parameterized construction
    MemoryRegion region(0x400000, 0x100000, MemoryRegion::READ | MemoryRegion::EXECUTE);
    EXPECT_EQ(region.getBaseAddress(), 0x400000);
    EXPECT_EQ(region.getSize(), 0x100000);
    EXPECT_EQ(region.getEndAddress(), 0x500000);
    EXPECT_EQ(region.getProtection(), MemoryRegion::READ | MemoryRegion::EXECUTE);
}

TEST_F(MemoryRegionTest, FullConstruction) {
    MemoryRegion region(0x1000, 0x2000, MemoryRegion::READ | MemoryRegion::WRITE,
                       "/usr/lib/libc.so.6", 0x1000, 0x08, 0x123456);
    EXPECT_EQ(region.getBaseAddress(), 0x1000);
    EXPECT_EQ(region.getSize(), 0x2000);
    EXPECT_EQ(region.getPathname(), "/usr/lib/libc.so.6");
    EXPECT_EQ(region.getOffset(), 0x1000);
    EXPECT_EQ(region.getDevice(), 0x08);
    EXPECT_EQ(region.getInode(), 0x123456);
}

TEST_F(MemoryRegionTest, AddressOperations) {
    EXPECT_EQ(test_region_.getBaseAddress(), 0x1000);
    EXPECT_EQ(test_region_.getEndAddress(), 0x2000);
    EXPECT_EQ(test_region_.getSize(), 0x1000);

    // Test address containment
    EXPECT_TRUE(test_region_.containsAddress(0x1000));
    EXPECT_TRUE(test_region_.containsAddress(0x1500));
    EXPECT_TRUE(test_region_.containsAddress(0x1FFF));
    EXPECT_FALSE(test_region_.containsAddress(0x0FFF));
    EXPECT_FALSE(test_region_.containsAddress(0x2000));
    EXPECT_FALSE(test_region_.containsAddress(0x2001));

    // Test range containment
    EXPECT_TRUE(test_region_.containsRange(0x1000, 0x100));
    EXPECT_TRUE(test_region_.containsRange(0x1500, 0x500));
    EXPECT_TRUE(test_region_.containsRange(0x1F00, 0x100));
    EXPECT_FALSE(test_region_.containsRange(0x0F00, 0x200));
    EXPECT_FALSE(test_region_.containsRange(0x1F00, 0x200));
    EXPECT_FALSE(test_region_.containsRange(0x2000, 0x100));
}

TEST_F(MemoryRegionTest, PermissionOperations) {
    MemoryRegion read_only(0x1000, 0x1000, MemoryRegion::READ);
    MemoryRegion write_only(0x1000, 0x1000, MemoryRegion::WRITE);
    MemoryRegion execute_only(0x1000, 0x1000, MemoryRegion::EXECUTE);
    MemoryRegion read_write(0x1000, 0x1000, MemoryRegion::READ | MemoryRegion::WRITE);
    MemoryRegion read_execute(0x1000, 0x1000, MemoryRegion::READ | MemoryRegion::EXECUTE);
    MemoryRegion full_access(0x1000, 0x1000, MemoryRegion::READ | MemoryRegion::WRITE | MemoryRegion::EXECUTE);

    // Test individual permissions
    EXPECT_TRUE(read_only.isReadable());
    EXPECT_FALSE(read_only.isWritable());
    EXPECT_FALSE(read_only.isExecutable());

    EXPECT_FALSE(write_only.isReadable());
    EXPECT_TRUE(write_only.isWritable());
    EXPECT_FALSE(write_only.isExecutable());

    EXPECT_TRUE(execute_only.isReadable());
    EXPECT_FALSE(execute_only.isWritable());
    EXPECT_TRUE(execute_only.isExecutable());

    EXPECT_TRUE(read_write.isReadable());
    EXPECT_TRUE(read_write.isWritable());
    EXPECT_FALSE(read_write.isExecutable());

    EXPECT_TRUE(read_execute.isReadable());
    EXPECT_FALSE(read_execute.isWritable());
    EXPECT_TRUE(read_execute.isExecutable());

    EXPECT_TRUE(full_access.isReadable());
    EXPECT_TRUE(full_access.isWritable());
    EXPECT_TRUE(full_access.isExecutable());

    // Test hasProtection
    EXPECT_TRUE(read_only.hasProtection(MemoryRegion::READ));
    EXPECT_FALSE(read_only.hasProtection(MemoryRegion::WRITE));
    EXPECT_TRUE(read_write.hasProtection(MemoryRegion::READ));
    EXPECT_TRUE(read_write.hasProtection(MemoryRegion::WRITE));
}

TEST_F(MemoryRegionTest, ProtectionString) {
    MemoryRegion none(0x1000, 0x1000, MemoryRegion::NONE);
    EXPECT_EQ(none.getProtectionString(), "---------");

    MemoryRegion read_only(0x1000, 0x1000, MemoryRegion::READ);
    EXPECT_EQ(read_only.getProtectionString(), "r--------");

    MemoryRegion read_write(0x1000, 0x1000, MemoryRegion::READ | MemoryRegion::WRITE);
    EXPECT_EQ(read_write.getProtectionString(), "rw-------");

    MemoryRegion read_execute(0x1000, 0x1000, MemoryRegion::READ | MemoryRegion::EXECUTE);
    EXPECT_EQ(read_execute.getProtectionString(), "r-x------");

    MemoryRegion full(0x1000, 0x1000, MemoryRegion::READ | MemoryRegion::WRITE | MemoryRegion::EXECUTE);
    EXPECT_EQ(full.getProtectionString(), "rwx------");

    MemoryRegion with_flags(0x1000, 0x1000,
                           MemoryRegion::READ | MemoryRegion::WRITE | MemoryRegion::EXECUTE |
                           MemoryRegion::GUARD | MemoryRegion::PRIVATE);
    EXPECT_EQ(with_flags.getProtectionString(), "rwxg--p--");
}

TEST_F(MemoryRegionTest, TypeInference) {
    // Test heap inference
    MemoryRegion heap_region(0x1000, 0x100000, MemoryRegion::READ | MemoryRegion::WRITE);
    heap_region = MemoryRegion(0x1000, 0x100000, MemoryRegion::READ | MemoryRegion::WRITE,
                              "[heap]", 0, 0, 0);
    EXPECT_EQ(heap_region.getType(), MemoryRegion::HEAP);

    // Test stack inference
    MemoryRegion stack_region(0x1000, 0x1000, MemoryRegion::READ | MemoryRegion::WRITE,
                             "[stack]", 0, 0, 0);
    EXPECT_EQ(stack_region.getType(), MemoryRegion::STACK);

    // Test code inference
    MemoryRegion code_region(0x400000, 0x1000, MemoryRegion::READ | MemoryRegion::EXECUTE,
                            "/usr/bin/test", 0, 0, 0);
    EXPECT_EQ(code_region.getType(), MemoryRegion::MAPPED_FILE);

    // Test data inference
    MemoryRegion data_region(0x600000, 0x1000, MemoryRegion::READ | MemoryRegion::WRITE,
                            "/usr/lib/libtest.so", 0, 0, 0);
    EXPECT_EQ(data_region.getType(), MemoryRegion::MAPPED_FILE);

    // Test library inference
    MemoryRegion lib_region(0x7F000000, 0x1000, MemoryRegion::READ | MemoryRegion::EXECUTE,
                           "/usr/lib/libc.so.6", 0, 0, 0);
    EXPECT_EQ(lib_region.getType(), MemoryRegion::MAPPED_FILE);
}

TEST_F(MemoryRegionTest, StaticMethods) {
    // Test protectionToString
    EXPECT_EQ(MemoryRegion::protectionToString(MemoryRegion::READ), "r--------");
    EXPECT_EQ(MemoryRegion::protectionToString(MemoryRegion::READ | MemoryRegion::WRITE), "rw-------");

    // Test typeToString
    EXPECT_EQ(MemoryRegion::typeToString(MemoryRegion::UNKNOWN), "unknown");
    EXPECT_EQ(MemoryRegion::typeToString(MemoryRegion::HEAP), "heap");
    EXPECT_EQ(MemoryRegion::typeToString(MemoryRegion::STACK), "stack");
    EXPECT_EQ(MemoryRegion::typeToString(MemoryRegion::CODE), "code");
    EXPECT_EQ(MemoryRegion::typeToString(MemoryRegion::DATA), "data");
    EXPECT_EQ(MemoryRegion::typeToString(MemoryRegion::MAPPED_FILE), "mapped_file");
    EXPECT_EQ(MemoryRegion::typeToString(MemoryRegion::SHARED_MEMORY), "shared_memory");
    EXPECT_EQ(MemoryRegion::typeToString(MemoryRegion::DEVICE_MEMORY), "device_memory");
}
