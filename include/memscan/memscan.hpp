/**
 * @file memscan.hpp
 * @brief Main header for the Memory Scanner Utility library
 *
 * This is the main header file that includes all public interfaces
 * of the memscan-util library for cross-platform memory pattern scanning.
 *
 * @author Memory Scanner Utility
 * @version 1.0.0
 * @date 2025
 *
 * @copyright For educational and debugging purposes only.
 */

#pragma once

// Core classes
#include "Process.hpp"
#include "MemoryRegion.hpp"
#include "PatternScanner.hpp"

// Version information
#define MEMSCAN_VERSION_MAJOR 1
#define MEMSCAN_VERSION_MINOR 0
#define MEMSCAN_VERSION_PATCH 0
#define MEMSCAN_VERSION_STRING "1.0.0"

/**
 * @namespace memscan
 * @brief Main namespace for the Memory Scanner Utility library
 *
 * All classes, functions, and types are contained within this namespace.
 */
