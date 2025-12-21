/**
 * @file Platform.hpp
 * @brief Platform detection and abstraction utilities
 *
 * This file provides platform detection macros and utilities for cross-platform
 * development support.
 *
 * @author Memory Scanner Utility
 * @version 1.0.0
 * @date 2025
 */

#pragma once

// Platform detection
#if defined(_WIN32) || defined(_WIN64)
    #define MEMSCAN_PLATFORM_WINDOWS 1
    #define MEMSCAN_PLATFORM_NAME "Windows"
#elif defined(__linux__) || defined(__gnu_linux__)
    #define MEMSCAN_PLATFORM_LINUX 1
    #define MEMSCAN_PLATFORM_NAME "Linux"
#elif defined(__APPLE__) && defined(__MACH__)
    #define MEMSCAN_PLATFORM_MACOS 1
    #define MEMSCAN_PLATFORM_NAME "macOS"
#else
    #error "Unsupported platform"
#endif

// Architecture detection
#if defined(_M_X64) || defined(__x86_64__) || defined(__amd64__)
    #define MEMSCAN_ARCH_X64 1
    #define MEMSCAN_ARCH_NAME "x64"
#elif defined(_M_IX86) || defined(__i386__) || defined(__i386)
    #define MEMSCAN_ARCH_X86 1
    #define MEMSCAN_ARCH_NAME "x86"
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define MEMSCAN_ARCH_ARM64 1
    #define MEMSCAN_ARCH_NAME "ARM64"
#elif defined(__arm__) || defined(_M_ARM)
    #define MEMSCAN_ARCH_ARM 1
    #define MEMSCAN_ARCH_NAME "ARM"
#else
    #define MEMSCAN_ARCH_UNKNOWN 1
    #define MEMSCAN_ARCH_NAME "Unknown"
#endif

// Compiler detection
#if defined(_MSC_VER)
    #define MEMSCAN_COMPILER_MSVC 1
    #define MEMSCAN_COMPILER_NAME "MSVC"
#elif defined(__clang__)
    #define MEMSCAN_COMPILER_CLANG 1
    #define MEMSCAN_COMPILER_NAME "Clang"
#elif defined(__GNUC__)
    #define MEMSCAN_COMPILER_GCC 1
    #define MEMSCAN_COMPILER_NAME "GCC"
#else
    #define MEMSCAN_COMPILER_UNKNOWN 1
    #define MEMSCAN_COMPILER_NAME "Unknown"
#endif

// Utility macros
#define MEMSCAN_STRINGIFY(x) #x
#define MEMSCAN_TOSTRING(x) MEMSCAN_STRINGIFY(x)

// Platform-specific includes and utilities
namespace memscan {
namespace platform {

/**
 * @brief Get the current platform name
 *
 * @return Platform name string
 */
inline const char* getPlatformName() {
    return MEMSCAN_PLATFORM_NAME;
}

/**
 * @brief Get the current architecture name
 *
 * @return Architecture name string
 */
inline const char* getArchitectureName() {
    return MEMSCAN_ARCH_NAME;
}

/**
 * @brief Get the current compiler name
 *
 * @return Compiler name string
 */
inline const char* getCompilerName() {
    return MEMSCAN_COMPILER_NAME;
}

} // namespace platform
} // namespace memscan
