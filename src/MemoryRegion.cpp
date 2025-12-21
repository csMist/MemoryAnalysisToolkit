/**
 * @file MemoryRegion.cpp
 * @brief Implementation of the MemoryRegion class
 *
 * @author Memory Scanner Utility
 * @version 1.0.0
 * @date 2025
 */

#include "memscan/MemoryRegion.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace memscan {

// MemoryRegion implementation

MemoryRegion::MemoryRegion()
    : base_address_(0)
    , size_(0)
    , protection_(0)
    , offset_(0)
    , device_(0)
    , inode_(0)
    , type_(Type::UNKNOWN)
    , type_cached_(false) {
}

MemoryRegion::MemoryRegion(uintptr_t base_address, size_t size, uint32_t protection)
    : base_address_(base_address)
    , size_(size)
    , protection_(protection)
    , offset_(0)
    , device_(0)
    , inode_(0)
    , type_(Type::UNKNOWN)
    , type_cached_(false) {
}

MemoryRegion::MemoryRegion(uintptr_t base_address, size_t size, uint32_t protection,
                          const std::string& pathname, uint64_t offset,
                          uint64_t device, uint64_t inode)
    : base_address_(base_address)
    , size_(size)
    , protection_(protection)
    , pathname_(pathname)
    , offset_(offset)
    , device_(device)
    , inode_(inode)
    , type_(Type::UNKNOWN)
    , type_cached_(false) {
}

uintptr_t MemoryRegion::getBaseAddress() const {
    return base_address_;
}

uintptr_t MemoryRegion::getEndAddress() const {
    return base_address_ + size_;
}

size_t MemoryRegion::getSize() const {
    return size_;
}

uint32_t MemoryRegion::getProtection() const {
    return protection_;
}

bool MemoryRegion::hasProtection(Protection protection) const {
    return (protection_ & static_cast<uint32_t>(protection)) != 0;
}

bool MemoryRegion::isReadable() const {
    return hasProtection(Protection::READ);
}

bool MemoryRegion::isWritable() const {
    return hasProtection(Protection::WRITE);
}

bool MemoryRegion::isExecutable() const {
    return hasProtection(Protection::EXECUTE);
}

const std::string& MemoryRegion::getPathname() const {
    return pathname_;
}

uint64_t MemoryRegion::getOffset() const {
    return offset_;
}

uint64_t MemoryRegion::getDevice() const {
    return device_;
}

uint64_t MemoryRegion::getInode() const {
    return inode_;
}

MemoryRegion::Type MemoryRegion::getType() const {
    if (!type_cached_) {
        type_ = inferType();
        type_cached_ = true;
    }
    return type_;
}

bool MemoryRegion::containsAddress(uintptr_t address) const {
    return address >= base_address_ && address < getEndAddress();
}

bool MemoryRegion::containsRange(uintptr_t address, size_t size) const {
    if (size == 0) {
        return containsAddress(address);
    }
    return address >= base_address_ &&
           (address + size) <= getEndAddress() &&
           (address + size) >= address; // Check for overflow
}

std::string MemoryRegion::getProtectionString() const {
    return protectionToString(protection_);
}

std::string MemoryRegion::getTypeString() const {
    return typeToString(getType());
}

std::string MemoryRegion::protectionToString(uint32_t protection) {
    std::string result;
    result += (protection & static_cast<uint32_t>(Protection::READ)) ? 'r' : '-';
    result += (protection & static_cast<uint32_t>(Protection::WRITE)) ? 'w' : '-';
    result += (protection & static_cast<uint32_t>(Protection::EXECUTE)) ? 'x' : '-';
    result += (protection & static_cast<uint32_t>(Protection::GUARD)) ? 'g' : '-';
    result += (protection & static_cast<uint32_t>(Protection::PRIVATE)) ? 'p' : '-';
    result += (protection & static_cast<uint32_t>(Protection::SHARED)) ? 's' : '-';
    return result;
}

std::string MemoryRegion::typeToString(Type type) {
    switch (type) {
        case Type::UNKNOWN: return "unknown";
        case Type::HEAP: return "heap";
        case Type::STACK: return "stack";
        case Type::CODE: return "code";
        case Type::DATA: return "data";
        case Type::MAPPED_FILE: return "mapped_file";
        case Type::SHARED_MEMORY: return "shared_memory";
        case Type::DEVICE_MEMORY: return "device_memory";
        default: return "unknown";
    }
}

MemoryRegion::Type MemoryRegion::inferType() const {
    // Check pathname for clues
    if (!pathname_.empty()) {
        // Check for common library paths
        if (pathname_.find(".so") != std::string::npos ||
            pathname_.find(".dll") != std::string::npos ||
            pathname_.find(".dylib") != std::string::npos) {
            // Executable code in libraries
            if (isExecutable() && !isWritable()) {
                return Type::CODE;
            }
            // Read-only data in libraries
            if (isReadable() && !isWritable() && !isExecutable()) {
                return Type::DATA;
            }
            // Writable data in libraries
            if (isReadable() && isWritable() && !isExecutable()) {
                return Type::DATA;
            }
            return Type::MAPPED_FILE;
        }

        // Check for heap-related paths
        if (pathname_.find("[heap]") != std::string::npos) {
            return Type::HEAP;
        }

        // Check for stack-related paths
        if (pathname_.find("[stack") != std::string::npos) {
            return Type::STACK;
        }

        // Check for shared memory
        if (pathname_.find("/dev/shm") != std::string::npos ||
            pathname_.find("SharedMemory") != std::string::npos) {
            return Type::SHARED_MEMORY;
        }

        // Device memory
        if (pathname_.find("/dev/") != std::string::npos ||
            pathname_.find("\\Device\\") != std::string::npos) {
            return Type::DEVICE_MEMORY;
        }

        // General mapped file
        return Type::MAPPED_FILE;
    }

    // No pathname - infer from permissions and size
    if (isReadable() && isWritable() && !isExecutable()) {
        // Could be heap or data
        if (size_ > 1024 * 1024) { // > 1MB
            return Type::HEAP;
        }
        return Type::DATA;
    }

    if (isReadable() && !isWritable() && isExecutable()) {
        return Type::CODE;
    }

    if (isReadable() && !isWritable() && !isExecutable()) {
        return Type::DATA;
    }

    return Type::UNKNOWN;
}

} // namespace memscan
