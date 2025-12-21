/**
 * @file Process.cpp
 * @brief Implementation of the Process class
 *
 * @author Memory Scanner Utility
 * @version 1.0.0
 * @date 2025
 */

#include "memscan/Process.hpp"
#include "memscan/Platform.hpp"

#include <algorithm>
#include <iterator>
#include <system_error>

// Platform-specific implementations
#ifdef MEMSCAN_PLATFORM_WINDOWS
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#elif defined(MEMSCAN_PLATFORM_LINUX)
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cstring>
#include <cstdio>
#include <cerrno>
#elif defined(MEMSCAN_PLATFORM_MACOS)
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>
#include <libproc.h>
#endif

namespace memscan {

// Forward declarations for platform-specific implementations
class Process::Impl {
public:
    virtual ~Impl() = default;

    virtual uint32_t getPid() const = 0;
    virtual std::string getName() const = 0;
    virtual bool isRunning() const = 0;
    virtual std::vector<MemoryRegion> enumerateRegions() const = 0;
    virtual size_t readMemory(uintptr_t address, void* buffer, size_t size) const = 0;
    virtual size_t writeMemory(uintptr_t address, const void* buffer, size_t size) = 0;
    virtual bool isAddressValid(uintptr_t address, size_t size) const = 0;

protected:
    uint32_t pid_ = 0;
    mutable Error last_error_ = Error::SUCCESS;

    void setLastError(Error error) const {
        last_error_ = error;
    }
};

#ifdef MEMSCAN_PLATFORM_WINDOWS

class Process::WindowsImpl : public Process::Impl {
public:
    explicit WindowsImpl(uint32_t pid) : handle_(nullptr) {
        pid_ = pid;
        handle_ = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!handle_) {
            throw ProcessError(Error::ACCESS_DENIED, "Failed to open process");
        }
    }

    WindowsImpl(const std::string& process_name) : handle_(nullptr) {
        pid_ = findProcessByName(process_name);
        if (pid_ == 0) {
            throw ProcessError(Error::PROCESS_NOT_FOUND, "Process not found: " + process_name);
        }
        handle_ = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, pid_);
        if (!handle_) {
            throw ProcessError(Error::ACCESS_DENIED, "Failed to open process: " + process_name);
        }
    }

    ~WindowsImpl() override {
        if (handle_) {
            CloseHandle(handle_);
        }
    }

    uint32_t getPid() const override {
        return pid_;
    }

    std::string getName() const override {
        if (cached_name_.empty()) {
            cached_name_ = getProcessNameFromPid(pid_);
        }
        return cached_name_;
    }

    bool isRunning() const override {
        DWORD exit_code;
        return GetExitCodeProcess(handle_, &exit_code) && exit_code == STILL_ACTIVE;
    }

    std::vector<MemoryRegion> enumerateRegions() const override {
        std::vector<MemoryRegion> regions;

        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t address = 0;

        while (VirtualQueryEx(handle_, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT) {
                uint32_t protection = 0;

                // Convert Windows protection flags to our enum
                if (mbi.Protect & PAGE_READONLY) protection |= static_cast<uint32_t>(MemoryRegion::READ);
                if (mbi.Protect & PAGE_READWRITE) protection |= static_cast<uint32_t>(MemoryRegion::READ) | static_cast<uint32_t>(MemoryRegion::WRITE);
                if (mbi.Protect & PAGE_EXECUTE) protection |= static_cast<uint32_t>(MemoryRegion::EXECUTE);
                if (mbi.Protect & PAGE_EXECUTE_READ) protection |= static_cast<uint32_t>(MemoryRegion::READ) | static_cast<uint32_t>(MemoryRegion::EXECUTE);
                if (mbi.Protect & PAGE_EXECUTE_READWRITE) protection |= static_cast<uint32_t>(MemoryRegion::READ) | static_cast<uint32_t>(MemoryRegion::WRITE) | static_cast<uint32_t>(MemoryRegion::EXECUTE);
                if (mbi.Protect & PAGE_EXECUTE_WRITECOPY) protection |= static_cast<uint32_t>(MemoryRegion::READ) | static_cast<uint32_t>(MemoryRegion::WRITE) | static_cast<uint32_t>(MemoryRegion::EXECUTE);
                if (mbi.Protect & PAGE_WRITECOPY) protection |= static_cast<uint32_t>(MemoryRegion::READ) | static_cast<uint32_t>(MemoryRegion::WRITE);
                if (mbi.Protect & PAGE_GUARD) protection |= static_cast<uint32_t>(MemoryRegion::GUARD);

                // Get pathname if available
                std::string pathname;
                if (mbi.Type == MEM_MAPPED || mbi.Type == MEM_IMAGE) {
                    char path[MAX_PATH];
                    if (GetMappedFileNameA(handle_, mbi.BaseAddress, path, MAX_PATH) > 0) {
                        pathname = path;
                    }
                }

                regions.emplace_back(
                    reinterpret_cast<uintptr_t>(mbi.BaseAddress),
                    mbi.RegionSize,
                    protection,
                    pathname
                );
            }

            address += mbi.RegionSize;
            if (address >= reinterpret_cast<uintptr_t>(UINTPTR_MAX) - mbi.RegionSize) {
                break; // Prevent overflow
            }
        }

        return regions;
    }

    size_t readMemory(uintptr_t address, void* buffer, size_t size) const override {
        SIZE_T bytes_read = 0;
        if (ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(address), buffer, size, &bytes_read)) {
            return static_cast<size_t>(bytes_read);
        }
        setLastError(Error::MEMORY_READ_FAILED);
        return 0;
    }

    size_t writeMemory(uintptr_t address, const void* buffer, size_t size) override {
        SIZE_T bytes_written = 0;
        if (WriteProcessMemory(handle_, reinterpret_cast<LPVOID>(address), buffer, size, &bytes_written)) {
            return static_cast<size_t>(bytes_written);
        }
        setLastError(Error::MEMORY_WRITE_FAILED);
        return 0;
    }

    bool isAddressValid(uintptr_t address, size_t size) const override {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(handle_, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == sizeof(mbi)) {
            return mbi.State == MEM_COMMIT &&
                   address >= reinterpret_cast<uintptr_t>(mbi.BaseAddress) &&
                   (address + size) <= (reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize);
        }
        return false;
    }

private:
    HANDLE handle_;
    mutable std::string cached_name_;

    static uint32_t findProcessByName(const std::string& process_name) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return 0;
        }

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);

        if (Process32First(snapshot, &pe)) {
            do {
                std::string exe_name = pe.szExeFile;
                // Case-insensitive comparison
                std::transform(exe_name.begin(), exe_name.end(), exe_name.begin(), ::tolower);
                std::string search_name = process_name;
                std::transform(search_name.begin(), search_name.end(), search_name.begin(), ::tolower);

                if (exe_name == search_name) {
                    CloseHandle(snapshot);
                    return pe.th32ProcessID;
                }
            } while (Process32Next(snapshot, &pe));
        }

        CloseHandle(snapshot);
        return 0;
    }

    static std::string getProcessNameFromPid(uint32_t pid) {
        HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!handle) {
            return "";
        }

        char buffer[MAX_PATH];
        if (GetModuleBaseNameA(handle, nullptr, buffer, MAX_PATH) > 0) {
            CloseHandle(handle);
            return buffer;
        }

        CloseHandle(handle);
        return "";
    }
};

#elif defined(MEMSCAN_PLATFORM_LINUX)

class Process::LinuxImpl : public Process::Impl {
public:
    explicit LinuxImpl(uint32_t pid) {
        pid_ = pid;
        if (access(getProcPath(""), F_OK) != 0) {
            throw ProcessError(Error::PROCESS_NOT_FOUND, "Process not found");
        }
    }

    LinuxImpl(const std::string& process_name) {
        pid_ = findProcessByName(process_name);
        if (pid_ == 0) {
            throw ProcessError(Error::PROCESS_NOT_FOUND, "Process not found: " + process_name);
        }
    }

    ~LinuxImpl() override = default;

    uint32_t getPid() const override {
        return pid_;
    }

    std::string getName() const override {
        if (cached_name_.empty()) {
            cached_name_ = readProcessName();
        }
        return cached_name_;
    }

    bool isRunning() const override {
        return access(getProcPath(""), F_OK) == 0;
    }

    std::vector<MemoryRegion> enumerateRegions() const override {
        std::vector<MemoryRegion> regions;

        std::string maps_path = getProcPath("maps");
        FILE* maps_file = fopen(maps_path.c_str(), "r");
        if (!maps_file) {
            setLastError(Error::SYSTEM_ERROR);
            return regions;
        }

        char line[1024];
        while (fgets(line, sizeof(line), maps_file)) {
            uintptr_t start_addr, end_addr;
            char perms[5];
            uint64_t offset;
            unsigned int dev_major, dev_minor;
            uint64_t inode;
            char pathname[256] = {0};

            int parsed = sscanf(line, "%lx-%lx %4s %lx %x:%x %lu %255s",
                              &start_addr, &end_addr, perms, &offset,
                              &dev_major, &dev_minor, &inode, pathname);

            if (parsed < 7) {
                continue; // Skip malformed lines
            }

            size_t size = end_addr - start_addr;
            uint32_t protection = 0;

            // Parse permissions string
            if (perms[0] == 'r') protection |= static_cast<uint32_t>(MemoryRegion::READ);
            if (perms[1] == 'w') protection |= static_cast<uint32_t>(MemoryRegion::WRITE);
            if (perms[2] == 'x') protection |= static_cast<uint32_t>(MemoryRegion::EXECUTE);
            if (perms[3] == 's') protection |= static_cast<uint32_t>(MemoryRegion::SHARED);
            else if (perms[3] == 'p') protection |= static_cast<uint32_t>(MemoryRegion::PRIVATE);

            std::string path_str = (parsed >= 8) ? pathname : "";

            regions.emplace_back(start_addr, size, protection, path_str,
                               offset, (static_cast<uint64_t>(dev_major) << 32) | dev_minor, inode);
        }

        fclose(maps_file);
        return regions;
    }

    size_t readMemory(uintptr_t address, void* buffer, size_t size) const override {
        struct iovec local_iov = {buffer, size};
        struct iovec remote_iov = {reinterpret_cast<void*>(address), size};

        ssize_t result = process_vm_readv(pid_, &local_iov, 1, &remote_iov, 1, 0);
        if (result < 0) {
            setLastError(Error::MEMORY_READ_FAILED);
            return 0;
        }
        return static_cast<size_t>(result);
    }

    size_t writeMemory(uintptr_t address, const void* buffer, size_t size) override {
        struct iovec local_iov = {const_cast<void*>(buffer), size};
        struct iovec remote_iov = {reinterpret_cast<void*>(address), size};

        ssize_t result = process_vm_writev(pid_, &local_iov, 1, &remote_iov, 1, 0);
        if (result < 0) {
            setLastError(Error::MEMORY_WRITE_FAILED);
            return 0;
        }
        return static_cast<size_t>(result);
    }

    bool isAddressValid(uintptr_t address, size_t size) const override {
        auto regions = enumerateRegions();
        for (const auto& region : regions) {
            if (region.containsRange(address, size)) {
                return true;
            }
        }
        return false;
    }

private:
    mutable std::string cached_name_;

    std::string getProcPath(const std::string& file) const {
        return "/proc/" + std::to_string(pid_) + "/" + file;
    }

    std::string readProcessName() const {
        std::string stat_path = getProcPath("stat");
        FILE* stat_file = fopen(stat_path.c_str(), "r");
        if (!stat_file) {
            return "";
        }

        char buffer[1024];
        if (fgets(buffer, sizeof(buffer), stat_file)) {
            // Parse the stat file format: pid (comm) state ...
            char* comm_start = strchr(buffer, '(');
            char* comm_end = strrchr(buffer, ')');
            if (comm_start && comm_end && comm_start < comm_end) {
                *comm_end = '\0';
                fclose(stat_file);
                return comm_start + 1;
            }
        }

        fclose(stat_file);
        return "";
    }

    static uint32_t findProcessByName(const std::string& process_name) {
        DIR* proc_dir = opendir("/proc");
        if (!proc_dir) {
            return 0;
        }

        struct dirent* entry;
        while ((entry = readdir(proc_dir)) != nullptr) {
            // Check if entry is a PID directory
            char* endptr;
            uint32_t pid = static_cast<uint32_t>(strtol(entry->d_name, &endptr, 10));
            if (*endptr != '\0') {
                continue; // Not a PID directory
            }

            // Read process name
            std::string stat_path = std::string("/proc/") + entry->d_name + "/stat";
            FILE* stat_file = fopen(stat_path.c_str(), "r");
            if (stat_file) {
                char buffer[1024];
                if (fgets(buffer, sizeof(buffer), stat_file)) {
                    char* comm_start = strchr(buffer, '(');
                    char* comm_end = strrchr(buffer, ')');
                    if (comm_start && comm_end && comm_start < comm_end) {
                        *comm_end = '\0';
                        std::string comm = comm_start + 1;
                        if (comm == process_name) {
                            fclose(stat_file);
                            closedir(proc_dir);
                            return pid;
                        }
                    }
                }
                fclose(stat_file);
            }
        }

        closedir(proc_dir);
        return 0;
    }
};

#elif defined(MEMSCAN_PLATFORM_MACOS)

class Process::MacOSImpl : public Process::Impl {
public:
    explicit MacOSImpl(uint32_t pid) : task_(MACH_PORT_NULL) {
        pid_ = pid;
        kern_return_t kr = task_for_pid(mach_task_self(), pid, &task_);
        if (kr != KERN_SUCCESS) {
            throw ProcessError(Error::ACCESS_DENIED, "Failed to get task port for process");
        }
    }

    MacOSImpl(const std::string& process_name) : task_(MACH_PORT_NULL) {
        pid_ = findProcessByName(process_name);
        if (pid_ == 0) {
            throw ProcessError(Error::PROCESS_NOT_FOUND, "Process not found: " + process_name);
        }
        kern_return_t kr = task_for_pid(mach_task_self(), pid, &task_);
        if (kr != KERN_SUCCESS) {
            throw ProcessError(Error::ACCESS_DENIED, "Failed to get task port for process: " + process_name);
        }
    }

    ~MacOSImpl() override {
        if (task_ != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), task_);
        }
    }

    uint32_t getPid() const override {
        return pid_;
    }

    std::string getName() const override {
        if (cached_name_.empty()) {
            cached_name_ = getProcessNameFromPid(pid_);
        }
        return cached_name_;
    }

    bool isRunning() const override {
        // Simple check - if we can get task info, process is running
        struct task_basic_info info;
        mach_msg_type_number_t count = TASK_BASIC_INFO_COUNT;
        kern_return_t kr = task_info(task_, TASK_BASIC_INFO,
                                   reinterpret_cast<task_info_t>(&info), &count);
        return kr == KERN_SUCCESS;
    }

    std::vector<MemoryRegion> enumerateRegions() const override {
        std::vector<MemoryRegion> regions;

        mach_vm_address_t address = 0;
        mach_vm_size_t size;
        natural_t depth = 0;
        vm_region_submap_info_data_64_t info;

        while (true) {
            mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
            kern_return_t kr = mach_vm_region_recurse(task_, &address, &size, &depth,
                                                    reinterpret_cast<vm_region_recurse_info_t>(&info), &count);

            if (kr != KERN_SUCCESS) {
                break;
            }

            uint32_t protection = 0;
            if (info.protection & VM_PROT_READ) protection |= static_cast<uint32_t>(MemoryRegion::READ);
            if (info.protection & VM_PROT_WRITE) protection |= static_cast<uint32_t>(MemoryRegion::WRITE);
            if (info.protection & VM_PROT_EXECUTE) protection |= static_cast<uint32_t>(MemoryRegion::EXECUTE);
            if (info.share_mode != SM_PRIVATE) protection |= static_cast<uint32_t>(MemoryRegion::SHARED);

            // Get pathname if available (simplified - would need more work for full implementation)
            std::string pathname;

            regions.emplace_back(address, size, protection, pathname);

            address += size;
        }

        return regions;
    }

    size_t readMemory(uintptr_t address, void* buffer, size_t size) const override {
        mach_vm_size_t bytes_read;
        kern_return_t kr = mach_vm_read_overwrite(task_, address, size,
                                                reinterpret_cast<mach_vm_address_t>(buffer), &bytes_read);
        if (kr != KERN_SUCCESS) {
            setLastError(Error::MEMORY_READ_FAILED);
            return 0;
        }
        return static_cast<size_t>(bytes_read);
    }

    size_t writeMemory(uintptr_t address, const void* buffer, size_t size) override {
        kern_return_t kr = mach_vm_write(task_, address,
                                       reinterpret_cast<vm_offset_t>(buffer), size);
        if (kr != KERN_SUCCESS) {
            setLastError(Error::MEMORY_WRITE_FAILED);
            return 0;
        }
        return size;
    }

    bool isAddressValid(uintptr_t address, size_t size) const override {
        mach_vm_address_t region_address = address;
        mach_vm_size_t region_size;
        natural_t depth = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;

        kern_return_t kr = mach_vm_region_recurse(task_, &region_address, &region_size,
                                                &depth, reinterpret_cast<vm_region_recurse_info_t>(&info), &count);

        if (kr != KERN_SUCCESS) {
            return false;
        }

        return address >= region_address &&
               (address + size) <= (region_address + region_size) &&
               (info.protection & VM_PROT_READ);
    }

private:
    task_t task_;
    mutable std::string cached_name_;

    static uint32_t findProcessByName(const std::string& process_name) {
        int num_processes = proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
        if (num_processes <= 0) {
            return 0;
        }

        std::vector<pid_t> pids(num_processes);
        num_processes = proc_listpids(PROC_ALL_PIDS, 0, pids.data(),
                                    static_cast<int>(pids.size() * sizeof(pid_t)));

        for (int i = 0; i < num_processes; ++i) {
            char name[1024];
            if (proc_name(pids[i], name, sizeof(name)) > 0) {
                if (process_name == name) {
                    return static_cast<uint32_t>(pids[i]);
                }
            }
        }

        return 0;
    }

    static std::string getProcessNameFromPid(uint32_t pid) {
        char name[1024];
        if (proc_name(pid, name, sizeof(name)) > 0) {
            return name;
        }
        return "";
    }
};

#endif

// Process class implementation

Process::Process() {
#ifdef MEMSCAN_PLATFORM_WINDOWS
    impl_ = std::make_unique<WindowsImpl>(GetCurrentProcessId());
#elif defined(MEMSCAN_PLATFORM_LINUX) || defined(MEMSCAN_PLATFORM_MACOS)
    impl_ = std::make_unique<LinuxImpl>(getpid());
#endif
}

Process::Process(uint32_t pid) {
#ifdef MEMSCAN_PLATFORM_WINDOWS
    impl_ = std::make_unique<WindowsImpl>(pid);
#elif defined(MEMSCAN_PLATFORM_LINUX)
    impl_ = std::make_unique<LinuxImpl>(pid);
#elif defined(MEMSCAN_PLATFORM_MACOS)
    impl_ = std::make_unique<MacOSImpl>(pid);
#endif
}

Process::Process(const std::string& process_name) {
#ifdef MEMSCAN_PLATFORM_WINDOWS
    impl_ = std::make_unique<WindowsImpl>(process_name);
#elif defined(MEMSCAN_PLATFORM_LINUX)
    impl_ = std::make_unique<LinuxImpl>(process_name);
#elif defined(MEMSCAN_PLATFORM_MACOS)
    impl_ = std::make_unique<MacOSImpl>(process_name);
#endif
}

Process::~Process() = default;

Process::Process(Process&& other) noexcept = default;
Process& Process::operator=(Process&& other) noexcept = default;

uint32_t Process::getPid() const {
    return impl_->getPid();
}

std::string Process::getName() const {
    return impl_->getName();
}

bool Process::isRunning() const {
    return impl_->isRunning();
}

std::vector<MemoryRegion> Process::enumerateRegions() const {
    return impl_->enumerateRegions();
}

std::vector<MemoryRegion> Process::enumerateRegions(uint32_t permissions) const {
    auto all_regions = enumerateRegions();
    std::vector<MemoryRegion> filtered_regions;

    std::copy_if(all_regions.begin(), all_regions.end(),
                std::back_inserter(filtered_regions),
                [permissions](const MemoryRegion& region) {
                    return (region.getProtection() & permissions) == permissions;
                });

    return filtered_regions;
}

size_t Process::readMemory(uintptr_t address, void* buffer, size_t size) const {
    if (size == 0) {
        return 0;
    }

    if (!isAddressValid(address, size)) {
        setLastError(Error::INVALID_ADDRESS);
        return 0;
    }

    size_t bytes_read = impl_->readMemory(address, buffer, size);
    if (bytes_read == 0) {
        setLastError(Error::MEMORY_READ_FAILED);
    }
    return bytes_read;
}

size_t Process::writeMemory(uintptr_t address, const void* buffer, size_t size) {
    if (size == 0) {
        return 0;
    }

    if (!isAddressValid(address, size)) {
        setLastError(Error::INVALID_ADDRESS);
        return 0;
    }

    size_t bytes_written = impl_->writeMemory(address, buffer, size);
    if (bytes_written == 0) {
        setLastError(Error::MEMORY_WRITE_FAILED);
    }
    return bytes_written;
}

bool Process::isAddressValid(uintptr_t address, size_t size) const {
    return impl_->isAddressValid(address, size);
}

Process::Error Process::getLastError() const {
    return impl_->last_error_;
}

std::string Process::getErrorMessage(Error error) {
    switch (error) {
        case Error::SUCCESS: return "Operation succeeded";
        case Error::PROCESS_NOT_FOUND: return "Process not found";
        case Error::ACCESS_DENIED: return "Access denied";
        case Error::INVALID_HANDLE: return "Invalid process handle";
        case Error::MEMORY_READ_FAILED: return "Memory read failed";
        case Error::MEMORY_WRITE_FAILED: return "Memory write failed";
        case Error::INVALID_ADDRESS: return "Invalid memory address";
        case Error::BUFFER_TOO_SMALL: return "Buffer too small";
        case Error::PLATFORM_NOT_SUPPORTED: return "Platform not supported";
        case Error::SYSTEM_ERROR: return "System error";
        default: return "Unknown error";
    }
}

void Process::setLastError(Error error) const {
    impl_->setLastError(error);
}

ProcessError::ProcessError(Process::Error error, const std::string& message)
    : std::system_error(static_cast<int>(error), std::generic_category(),
                       message.empty() ? Process::getErrorMessage(error) : message) {
}

} // namespace memscan
