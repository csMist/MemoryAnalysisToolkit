cmake_minimum_required(VERSION 3.16)
project(memscan-util VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build options
option(MEMSCAN_BUILD_TESTS "Build unit tests" ON)
option(MEMSCAN_BUILD_EXAMPLES "Build example programs" ON)
option(MEMSCAN_BUILD_BENCHMARKS "Build performance benchmarks" ON)
option(MEMSCAN_BUILD_SHARED "Build shared library" ON)
option(MEMSCAN_BUILD_STATIC "Build static library" ON)
option(MEMSCAN_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(MEMSCAN_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(MEMSCAN_ENABLE_TSAN "Enable ThreadSanitizer" OFF)

# Platform detection
if(WIN32)
    set(MEMSCAN_PLATFORM_WINDOWS TRUE)
    add_definitions(-DMEMSCAN_PLATFORM_WINDOWS)
elseif(UNIX AND NOT APPLE)
    set(MEMSCAN_PLATFORM_LINUX TRUE)
    add_definitions(-DMEMSCAN_PLATFORM_LINUX)
elseif(APPLE)
    set(MEMSCAN_PLATFORM_MACOS TRUE)
    add_definitions(-DMEMSCAN_PLATFORM_MACOS)
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

# Architecture detection
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    add_definitions(-DMEMSCAN_ARCH_X64)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i686")
    add_definitions(-DMEMSCAN_ARCH_X86)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64")
    add_definitions(-DMEMSCAN_ARCH_ARM64)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
    add_definitions(-DMEMSCAN_ARCH_ARM)
else()
    add_definitions(-DMEMSCAN_ARCH_UNKNOWN)
endif()

# Compiler-specific flags
if(MSVC)
    add_definitions(-DMEMSCAN_COMPILER_MSVC)
    # MSVC warnings
    add_compile_options(/W4 /permissive-)
    # MSVC release optimizations
    add_compile_options($<$<CONFIG:Release>:/O2>)
    add_compile_options($<$<CONFIG:Release>:/DNDEBUG>)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_definitions(-DMEMSCAN_COMPILER_CLANG)
    # Clang warnings
    add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)
    # Clang release optimizations
    add_compile_options($<$<CONFIG:Release>:-O3>)
    add_compile_options($<$<CONFIG:Release>:-DNDEBUG>)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    add_definitions(-DMEMSCAN_COMPILER_GCC)
    # GCC warnings
    add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)
    # GCC release optimizations
    add_compile_options($<$<CONFIG:Release>:-O3>)
    add_compile_options($<$<CONFIG:Release>:-DNDEBUG>)
endif()

# Sanitizers
if(MEMSCAN_ENABLE_ASAN)
    if(MSVC)
        add_compile_options(/fsanitize=address)
        add_link_options(/fsanitize=address)
    else()
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()
endif()

if(MEMSCAN_ENABLE_UBSAN)
    if(MSVC)
        add_compile_options(/fsanitize=undefined)
        add_link_options(/fsanitize=undefined)
    else()
        add_compile_options(-fsanitize=undefined)
        add_link_options(-fsanitize=undefined)
    endif()
endif()

if(MEMSCAN_ENABLE_TSAN)
    if(NOT MSVC)
        add_compile_options(-fsanitize=thread)
        add_link_options(-fsanitize=thread)
    endif()
endif()

# Platform-specific libraries
if(MEMSCAN_PLATFORM_WINDOWS)
    set(PLATFORM_LIBS psapi)
elseif(MEMSCAN_PLATFORM_LINUX)
    # Linux doesn't need special libraries for basic functionality
elseif(MEMSCAN_PLATFORM_MACOS)
    find_library(CORE_FOUNDATION CoreFoundation)
    set(PLATFORM_LIBS ${CORE_FOUNDATION})
endif()

# Library source files
set(MEMSCAN_SOURCES
    src/MemoryRegion.cpp
    src/Process.cpp
    src/PatternScanner.cpp
)

set(MEMSCAN_HEADERS
    include/memscan/memscan.hpp
    include/memscan/MemoryRegion.hpp
    include/memscan/Process.hpp
    include/memscan/PatternScanner.hpp
    include/memscan/Platform.hpp
)

# Create the library target(s)
if(MEMSCAN_BUILD_SHARED)
    add_library(memscan SHARED ${MEMSCAN_SOURCES} ${MEMSCAN_HEADERS})
    set_target_properties(memscan PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
    target_compile_definitions(memscan PRIVATE MEMSCAN_EXPORTS)
    if(WIN32)
        target_compile_definitions(memscan PRIVATE MEMSCAN_BUILD_SHARED)
    endif()
endif()

if(MEMSCAN_BUILD_STATIC)
    add_library(memscan-static STATIC ${MEMSCAN_SOURCES} ${MEMSCAN_HEADERS})
    set_target_properties(memscan-static PROPERTIES
        OUTPUT_NAME memscan
    )
    target_compile_definitions(memscan-static PUBLIC MEMSCAN_STATIC)
endif()

# Set include directories
foreach(target memscan memscan-static)
    if(TARGET ${target})
        target_include_directories(${target}
            PUBLIC
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                $<INSTALL_INTERFACE:include>
            PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/src
        )
        target_link_libraries(${target} PRIVATE ${PLATFORM_LIBS})
    endif()
endforeach()

# Tests
if(MEMSCAN_BUILD_TESTS)
    enable_testing()
    find_package(GTest REQUIRED)

    set(TEST_SOURCES
        tests/TestMemoryRegion.cpp
        tests/TestProcess.cpp
        tests/TestPatternScanner.cpp
        tests/TestMain.cpp
    )

    add_executable(memscan-tests ${TEST_SOURCES})
    target_link_libraries(memscan-tests
        PRIVATE
            memscan-static
            GTest::GTest
            GTest::Main
    )
    target_include_directories(memscan-tests PRIVATE include)

    add_test(NAME memscan-unit-tests COMMAND memscan-tests)
endif()

# Examples
if(MEMSCAN_BUILD_EXAMPLES)
    # Process memory scanner example
    add_executable(scan-own-process examples/scan_own_process.cpp)
    target_link_libraries(scan-own-process PRIVATE memscan-static)

    # Library pattern scanner example
    add_executable(scan-library examples/scan_library.cpp)
    target_link_libraries(scan-library PRIVATE memscan-static)

    # Memory layout analyzer example
    add_executable(memory-layout-analyzer examples/memory_layout_analyzer.cpp)
    target_link_libraries(memory-layout-analyzer PRIVATE memscan-static)
endif()

# Benchmarks
if(MEMSCAN_BUILD_BENCHMARKS)
    find_package(benchmark REQUIRED)

    set(BENCHMARK_SOURCES
        benchmarks/ScanBenchmarks.cpp
    )

    add_executable(memscan-benchmarks ${BENCHMARK_SOURCES})
    target_link_libraries(memscan-benchmarks
        PRIVATE
            memscan-static
            benchmark::benchmark
    )
endif()

# Installation
include(GNUInstallDirs)

# Install library
if(MEMSCAN_BUILD_SHARED)
    install(TARGETS memscan
        EXPORT memscan-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

if(MEMSCAN_BUILD_STATIC)
    install(TARGETS memscan-static
        EXPORT memscan-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()

# Install headers
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp"
)

# Install CMake config files
install(EXPORT memscan-targets
    FILE memscan-targets.cmake
    NAMESPACE memscan::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/memscan
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/memscan-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/memscan-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/memscan-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/memscan
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/memscan-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/memscan-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/memscan
)

# Create and install pkg-config file
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/memscan.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/memscan.pc
    @ONLY
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/memscan.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

# Create package config template
file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/cmake/memscan-config.cmake.in
"@PACKAGE_INIT@

set(MEMSCAN_VERSION @PROJECT_VERSION@)

include(\"\${CMAKE_CURRENT_LIST_DIR}/memscan-targets.cmake\")

set_and_check(MEMSCAN_INCLUDE_DIR \"\${PACKAGE_PREFIX_DIR}/@CMAKE_INSTALL_INCLUDEDIR@\")

check_required_components(memscan)
")

# Create pkg-config template
file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/cmake/memscan.pc.in
"prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=\${prefix}
libdir=\${exec_prefix}/@CMAKE_INSTALL_LIBDIR@
includedir=\${prefix}/@CMAKE_INSTALL_INCLUDEDIR@

Name: memscan-util
Description: Cross-platform memory pattern scanning utility library
Version: @PROJECT_VERSION@
Cflags: -I\${includedir}
Libs: -L\${libdir} -lmemscan
")
