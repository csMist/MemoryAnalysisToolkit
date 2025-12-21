/**
 * @file MemoryRegion.hpp
 * @brief Memory region representation and utilities
 *
 * This file provides the MemoryRegion class for representing memory regions
 * with their addresses, sizes, permissions, and associated metadata.
 *
 * @author Memory Scanner Utility
 * @version 1.0.0
 * @date 2025
 *
 * @copyright For educational and debugging purposes only.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace memscan {

/**
 * @brief Represents a memory region in a process
 *
 * The MemoryRegion class encapsulates information about a contiguous block
 * of memory in a process, including its base address, size, permissions,
 * and associated metadata like pathname (for mapped files).
 */
class MemoryRegion {
public:
    /**
     * @brief Memory protection flags
     */
    enum Protection {
        NONE = 0,           ///< No access
        READ = 1 << 0,      ///< Read access
        WRITE = 1 << 1,     ///< Write access
        EXECUTE = 1 << 2,   ///< Execute access
        GUARD = 1 << 3,     ///< Guard page (Windows-specific)
        PRIVATE = 1 << 4,   ///< Private allocation
        SHARED = 1 << 5,    ///< Shared memory
    };

    /**
     * @brief Memory region type
     */
    enum Type {
        UNKNOWN,           ///< Unknown or unmapped memory
        HEAP,              ///< Process heap
        STACK,             ///< Thread stack
        CODE,              ///< Executable code (.text section)
        DATA,              ///< Data section (.data, .bss, .rdata)
        MAPPED_FILE,       ///< Memory-mapped file
        SHARED_MEMORY,     ///< Shared memory segment
        DEVICE_MEMORY,     ///< Device memory (GPU, etc.)
    };

    /**
     * @brief Construct an empty MemoryRegion
     */
    MemoryRegion();

    /**
     * @brief Construct a MemoryRegion with basic information
     *
     * @param base_address Base address of the region
     * @param size Size of the region in bytes
     * @param protection Memory protection flags
     */
    MemoryRegion(uintptr_t base_address, size_t size, uint32_t protection);

    /**
     * @brief Construct a MemoryRegion with full information
     *
     * @param base_address Base address of the region
     * @param size Size of the region in bytes
     * @param protection Memory protection flags
     * @param pathname Pathname associated with the region (e.g., mapped file)
     * @param offset Offset in the file (for mapped files)
     * @param device Device number (for device mappings)
     * @param inode Inode number (for file mappings)
     */
    MemoryRegion(uintptr_t base_address, size_t size, uint32_t protection,
                 const std::string& pathname = "", uint64_t offset = 0,
                 uint64_t device = 0, uint64_t inode = 0);

    /**
     * @brief Get the base address of the region
     *
     * @return Base address as uintptr_t
     */
    uintptr_t getBaseAddress() const;

    /**
     * @brief Get the end address of the region
     *
     * @return End address (base + size) as uintptr_t
     */
    uintptr_t getEndAddress() const;

    /**
     * @brief Get the size of the region
     *
     * @return Size in bytes
     */
    size_t getSize() const;

    /**
     * @brief Get the memory protection flags
     *
     * @return Protection flags as uint32_t
     */
    uint32_t getProtection() const;

    /**
     * @brief Check if the region has a specific protection flag
     *
     * @param protection Protection flag to check
     * @return true if the flag is set, false otherwise
     */
    bool hasProtection(Protection protection) const;

    /**
     * @brief Check if the region is readable
     *
     * @return true if readable, false otherwise
     */
    bool isReadable() const;

    /**
     * @brief Check if the region is writable
     *
     * @return true if writable, false otherwise
     */
    bool isWritable() const;

    /**
     * @brief Check if the region is executable
     *
     * @return true if executable, false otherwise
     */
    bool isExecutable() const;

    /**
     * @brief Get the pathname associated with the region
     *
     * @return Pathname string (empty for anonymous regions)
     */
    const std::string& getPathname() const;

    /**
     * @brief Get the file offset (for mapped files)
     *
     * @return File offset
     */
    uint64_t getOffset() const;

    /**
     * @brief Get the device number
     *
     * @return Device number
     */
    uint64_t getDevice() const;

    /**
     * @brief Get the inode number
     *
     * @return Inode number
     */
    uint64_t getInode() const;

    /**
     * @brief Get the inferred type of the memory region
     *
     * @return MemoryRegion::Type enum value
     */
    Type getType() const;

    /**
     * @brief Check if an address is within this region
     *
     * @param address Address to check
     * @return true if address is within [base, base+size), false otherwise
     */
    bool containsAddress(uintptr_t address) const;

    /**
     * @brief Check if a range of addresses is within this region
     *
     * @param address Start address of the range
     * @param size Size of the range
     * @return true if the entire range is within this region, false otherwise
     */
    bool containsRange(uintptr_t address, size_t size) const;

    /**
     * @brief Get a human-readable string representation of protection flags
     *
     * @return String like "rwx" or "r--" representing permissions
     */
    std::string getProtectionString() const;

    /**
     * @brief Get a human-readable string representation of the region type
     *
     * @return Type name as string
     */
    std::string getTypeString() const;

    /**
     * @brief Convert protection flags to string
     *
     * @param protection Protection flags to convert
     * @return Human-readable protection string
     */
    static std::string protectionToString(uint32_t protection);

    /**
     * @brief Convert type enum to string
     *
     * @param type Type enum value
     * @return Type name as string
     */
    static std::string typeToString(Type type);

private:
    uintptr_t base_address_;     ///< Base address of the region
    size_t size_;                ///< Size of the region in bytes
    uint32_t protection_;        ///< Memory protection flags
    std::string pathname_;       ///< Associated pathname (if any)
    uint64_t offset_;            ///< File offset (for mapped files)
    uint64_t device_;            ///< Device number
    uint64_t inode_;             ///< Inode number
    mutable Type type_;          ///< Cached region type (computed on demand)
    mutable bool type_cached_;   ///< Whether type has been computed

    /**
     * @brief Infer the region type based on pathname and protection
     *
     * @return Inferred Type enum value
     */
    Type inferType() const;
};

/**
 * @brief Overload for bitwise OR of Protection flags
 */
inline MemoryRegion::Protection operator|(MemoryRegion::Protection lhs,
                                         MemoryRegion::Protection rhs) {
    return static_cast<MemoryRegion::Protection>(
        static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}

/**
 * @brief Overload for bitwise AND of Protection flags
 */
inline MemoryRegion::Protection operator&(MemoryRegion::Protection lhs,
                                         MemoryRegion::Protection rhs) {
    return static_cast<MemoryRegion::Protection>(
        static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}

/**
 * @brief Overload for bitwise OR assignment of Protection flags
 */
inline MemoryRegion::Protection& operator|=(MemoryRegion::Protection& lhs,
                                           MemoryRegion::Protection rhs) {
    lhs = lhs | rhs;
    return lhs;
}

/**
 * @brief Overload for bitwise AND assignment of Protection flags
 */
inline MemoryRegion::Protection& operator&=(MemoryRegion::Protection& lhs,
                                           MemoryRegion::Protection rhs) {
    lhs = lhs & rhs;
    return lhs;
}

} // namespace memscan
