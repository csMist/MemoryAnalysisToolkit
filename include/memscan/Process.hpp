/**
 * @file Process.hpp
 * @brief Cross-platform process memory access and enumeration
 *
 * This file provides the Process class for safely opening processes and
 * enumerating their memory regions across Windows, Linux, and macOS platforms.
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
#include <system_error>

#include "MemoryRegion.hpp"

namespace memscan {

/**
 * @brief Represents a process and provides memory access operations
 *
 * The Process class handles cross-platform process opening and memory region
 * enumeration. It provides safe memory reading with bounds checking and
 * comprehensive error reporting.
 */
class Process {
public:
    /**
     * @brief Process permissions for memory operations
     */
    enum class Permission {
        READ,      ///< Read access
        WRITE,     ///< Write access
        EXECUTE    ///< Execute access
    };

    /**
     * @brief Error codes specific to process operations
     */
    enum class Error {
        SUCCESS = 0,                    ///< Operation succeeded
        PROCESS_NOT_FOUND = 1,          ///< Process with given ID/name not found
        ACCESS_DENIED = 2,              ///< Insufficient permissions to access process
        INVALID_HANDLE = 3,             ///< Process handle is invalid
        MEMORY_READ_FAILED = 4,         ///< Failed to read process memory
        MEMORY_WRITE_FAILED = 5,        ///< Failed to write process memory
        INVALID_ADDRESS = 6,            ///< Invalid memory address specified
        BUFFER_TOO_SMALL = 7,           ///< Provided buffer is too small
        PLATFORM_NOT_SUPPORTED = 8,     ///< Operation not supported on this platform
        SYSTEM_ERROR = 9                ///< Generic system error
    };

    /**
     * @brief Construct a Process object for the current process
     */
    Process();

    /**
     * @brief Construct a Process object for a process by ID
     *
     * @param pid Process ID to open
     * @throws std::system_error if process cannot be opened
     */
    explicit Process(uint32_t pid);

    /**
     * @brief Construct a Process object for a process by name
     *
     * @param process_name Name of the process to open
     * @throws std::system_error if process cannot be opened or multiple processes found
     */
    explicit Process(const std::string& process_name);

    /**
     * @brief Destructor - closes process handle
     */
    ~Process();

    // Delete copy operations
    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;

    // Allow move operations
    Process(Process&& other) noexcept;
    Process& operator=(Process&& other) noexcept;

    /**
     * @brief Get the process ID
     *
     * @return Process ID
     */
    uint32_t getPid() const;

    /**
     * @brief Get the process name
     *
     * @return Process name
     */
    std::string getName() const;

    /**
     * @brief Check if the process is still running
     *
     * @return true if process is running, false otherwise
     */
    bool isRunning() const;

    /**
     * @brief Enumerate all memory regions in the process
     *
     * @return Vector of MemoryRegion objects representing all accessible memory regions
     * @throws std::system_error if enumeration fails
     */
    std::vector<MemoryRegion> enumerateRegions() const;

    /**
     * @brief Enumerate memory regions with specific permissions
     *
     * @param permissions Required permissions (bitwise OR of Permission flags)
     * @return Vector of MemoryRegion objects with matching permissions
     * @throws std::system_error if enumeration fails
     */
    std::vector<MemoryRegion> enumerateRegions(uint32_t permissions) const;

    /**
     * @brief Read memory from the process
     *
     * @param address Memory address to read from
     * @param buffer Buffer to store read data
     * @param size Number of bytes to read
     * @return Number of bytes actually read
     * @throws std::system_error if read operation fails
     */
    size_t readMemory(uintptr_t address, void* buffer, size_t size) const;

    /**
     * @brief Read memory from the process into a typed buffer
     *
     * @tparam T Type of data to read
     * @param address Memory address to read from
     * @param value Reference to store the read value
     * @return true if read succeeded, false otherwise
     * @throws std::system_error if read operation fails
     */
    template<typename T>
    bool readMemory(uintptr_t address, T& value) const {
        return readMemory(address, &value, sizeof(T)) == sizeof(T);
    }

    /**
     * @brief Write memory to the process (if permissions allow)
     *
     * @param address Memory address to write to
     * @param buffer Buffer containing data to write
     * @param size Number of bytes to write
     * @return Number of bytes actually written
     * @throws std::system_error if write operation fails or is not permitted
     */
    size_t writeMemory(uintptr_t address, const void* buffer, size_t size);

    /**
     * @brief Write typed data to process memory
     *
     * @tparam T Type of data to write
     * @param address Memory address to write to
     * @param value Value to write
     * @return true if write succeeded, false otherwise
     * @throws std::system_error if write operation fails
     */
    template<typename T>
    bool writeMemory(uintptr_t address, const T& value) {
        return writeMemory(address, &value, sizeof(T)) == sizeof(T);
    }

    /**
     * @brief Check if a memory address is valid and accessible
     *
     * @param address Memory address to check
     * @param size Size of the memory region to check
     * @return true if address is accessible, false otherwise
     */
    bool isAddressValid(uintptr_t address, size_t size = 1) const;

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
 * @brief Exception class for process-related errors
 */
class ProcessError : public std::system_error {
public:
    /**
     * @brief Construct a ProcessError
     *
     * @param error Process-specific error code
     * @param message Additional error message
     */
    ProcessError(Process::Error error, const std::string& message = "");
};

} // namespace memscan
