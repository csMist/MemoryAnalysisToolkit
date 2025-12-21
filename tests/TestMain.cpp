/**
 * @file TestMain.cpp
 * @brief Main test runner for memscan-util unit tests
 *
 * @author Memory Scanner Utility
 * @version 1.0.0
 * @date 2025
 */

#include <gtest/gtest.h>

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
