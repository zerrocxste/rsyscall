#ifndef REMOTE_SYSCALL_H
#define REMOTE_SYSCALL_H

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <linux/limits.h>
#include <cstring>

namespace remote_syscall
{
    /*
    mov [rsp], rax
    mov [rsp-0x8], rbx
    mov [rsp-0x10], rcx
    mov [rsp-0x18], rdx
    mov [rsp-0x20], rsi
    mov [rsp-0x28], rdi
    mov [rsp-0x30], r8
    mov [rsp-0x38], r9
    mov [rsp-0x40], r10
    sub rsp, 0x4000

    mov rdi, [rsp+0x8] # rsyscall_args::arg0
    mov rsi, [rsp+0x10] # rsyscall_args::arg1
    mov rdx, [rsp+0x18] # rsyscall_args::arg2
    mov r10, [rsp+0x20] # rsyscall_args::arg3
    mov r8, [rsp+0x28] # rsyscall_args::arg4
    mov r9, [rsp+0x30] #rsyscall_args::arg5
    mov rax, [rsp] #rsyscall_args::syscall_nr
    syscall
    mov [rsp+0x38], rax # shell_args::mmap_ret

    lea rdi, [rsp+0x4a] # shell_args::path
    mov rsi, 2
    mov rax, 2        # syscall open
    syscall
    mov r10, rax # save fd

    mov rdi, r10
    mov rsi, [rsp+0x40] # shell_args::prologue_shellcode
    xor rdx, rdx
    mov rax, 8
    syscall

    mov rdi, r10
    lea rsi, [rsp+0x48] # shell_args::jmp_inifinite
    mov rdx, 2
    mov rax, 1       # syscall write
    syscall

    add rsp, 0x4000
    mov r10, [rsp-0x40]
    mov r9, [rsp-0x38]
    mov r8, [rsp-0x30]
    mov rdi, [rsp-0x28]
    mov rsi, [rsp-0x20]
    mov rdx, [rsp-0x18]
    mov rcx, [rsp-0x10]
    mov rbx, [rsp-0x8]
    mov rax, [rsp]
    jmp [rsp-0x4000+0x40] #args::shellcode_prologue
    */

    unsigned char code[] = {
        "\x48\x89\x04\x24"             //     mov [rsp], rax
        "\x48\x89\x5c\x24\xf8"         //     mov [rsp-0x8], rbx
        "\x48\x89\x4c\x24\xf0"         //     mov [rsp-0x10], rcx
        "\x48\x89\x54\x24\xe8"         //     mov [rsp-0x18], rdx
        "\x48\x89\x74\x24\xe0"         //     mov [rsp-0x20], rsi
        "\x48\x89\x7c\x24\xd8"         //     mov [rsp-0x28], rdi
        "\x4c\x89\x44\x24\xd0"         //     mov [rsp-0x30], r8
        "\x4c\x89\x4c\x24\xc8"         //     mov [rsp-0x38], r9
        "\x4c\x89\x54\x24\xc0"         //     mov [rsp-0x40], r10
        "\x48\x81\xec\x00\x40\x00\x00" //     sub rsp, 0x4000
        "\x48\x8b\x7c\x24\x08"         //     mov rdi, [rsp+0x8] # rsyscall_args::arg0
        "\x48\x8b\x74\x24\x10"         //     mov rsi, [rsp+0x10] # rsyscall_args::arg1
        "\x48\x8b\x54\x24\x18"         //     mov rdx, [rsp+0x18] # rsyscall_args::arg2
        "\x4c\x8b\x54\x24\x20"         //     mov r10, [rsp+0x20] # rsyscall_args::arg3
        "\x4c\x8b\x44\x24\x28"         //     mov r8, [rsp+0x28] # rsyscall_args::arg4
        "\x4c\x8b\x4c\x24\x30"         //     mov r9, [rsp+0x30] #rsyscall_args::arg5
        "\x48\x8b\x04\x24"             //     mov rax, [rsp] #rsyscall_args::syscall_nr
        "\x0f\x05"                     //     syscall
        "\x48\x89\x44\x24\x38"         //     mov [rsp+0x38], rax # shell_args::mmap_ret
        "\x48\x8d\x7c\x24\x4a"         //     lea rdi, [rsp+0x4a] # shell_args::path
        "\x48\xc7\xc6\x02\x00\x00\x00" //     mov rsi, 2
        "\x48\xc7\xc0\x02\x00\x00\x00" //     mov rax, 2        # syscall open
        "\x0f\x05"                     //     syscall
        "\x49\x89\xc2"                 //     mov r10, rax # save fd
        "\x4c\x89\xd7"                 //     mov rdi, r10
        "\x48\x8b\x74\x24\x40"         //     mov rsi, [rsp+0x40] # shell_args::prologue_shellcode
        "\x48\x31\xd2"                 //     xor rdx, rdx
        "\x48\xc7\xc0\x08\x00\x00\x00" //     mov rax, 8
        "\x0f\x05"                     //     syscall
        "\x4c\x89\xd7"                 //     mov rdi, r10
        "\x48\x8d\x74\x24\x48"         //     lea rsi, [rsp+0x48] # shell_args::jmp_inifinite
        "\x48\xc7\xc2\x02\x00\x00\x00" //     mov rdx, 2
        "\x48\xc7\xc0\x01\x00\x00\x00" //     mov rax, 1       # syscall write
        "\x0f\x05"                     //     syscall
        "\x48\x81\xc4\x00\x40\x00\x00" //     add rsp, 0x4000
        "\x4c\x8b\x54\x24\xc0"         //     mov r10, [rsp-0x40]
        "\x4c\x8b\x4c\x24\xc8"         //     mov r9, [rsp-0x38]
        "\x4c\x8b\x44\x24\xd0"         //     mov r8, [rsp-0x30]
        "\x48\x8b\x7c\x24\xd8"         //     mov rdi, [rsp-0x28]
        "\x48\x8b\x74\x24\xe0"         //     mov rsi, [rsp-0x20]
        "\x48\x8b\x54\x24\xe8"         //     mov rdx, [rsp-0x18]
        "\x48\x8b\x4c\x24\xf0"         //     mov rcx, [rsp-0x10]
        "\x48\x8b\x5c\x24\xf8"         //     mov rbx, [rsp-0x8]
        "\x48\x8b\x04\x24"             //     mov rax, [rsp]
        "\xff\xa4\x24\x40\xc0\xff\xff" //     jmp [rsp-0x4000+0x40] #args::shellcode_prologue
    };

    namespace detail
    {
        constexpr auto MAX_STRING_BUFFER = PATH_MAX;

#pragma pack(push, 1)
        char *copy_string(char *dst, const char *src)
        {
            char *ppos = dst;
            while (*src)
                *ppos++ = *src++;
            *ppos = '\0';
            return dst;
        }

        template <typename... Args>
        struct packed_args;

        template <>
        struct packed_args<>
        {
        };

        template <typename T, typename... Rest>
        struct packed_args<T, Rest...>
        {
            constexpr static bool value_is_address = false;
            T value;
            packed_args<Rest...> rest;
            packed_args(T val, Rest... rest_vals) : value(val), rest(rest_vals...) {}
        };

        template <typename T, typename... Rest>
        struct packed_args<T *, Rest...>
        {
            constexpr static bool value_is_address = true;
            T value;
            packed_args<Rest...> rest;
            packed_args(T *val, Rest... rest_vals) : value(*val), rest(rest_vals...) {}
        };

        template <typename... Rest>
        struct packed_args<const char *, Rest...>
        {
            constexpr static bool value_is_address = true;
            char value[MAX_STRING_BUFFER];
            packed_args<Rest...> rest;
            packed_args(const char *buffer, Rest... rest_vals) : rest(rest_vals...)
            {
                copy_string(value, buffer);
            }
        };
#pragma pack(pop)

#pragma pack(push, 1)
        template <std::size_t N>
        struct rsyscall_args
        {
            long syscall_nr;                           // 0x0
            long arg0;                                 // 0x8
            long arg1;                                 // 0x10
            long arg2;                                 // 0x18
            long arg3;                                 // 0x20
            long arg4;                                 // 0x28
            long arg5;                                 // 0x30
            long syscall_ret;                          // 0x38
            unsigned long prologue_shellcode;          // 0x40
            unsigned char jmp_infinite[2]{0xeb, 0xfe}; // 0x48
            char path[15]{"/proc/self/mem"};           // 0x4a
            std::uint8_t args_buffer[N];
        };
#pragma pack(pop)

        inline ssize_t read_memory(const int fd, std::uintptr_t addr, void *buffer, const std::size_t length)
        {
            if (auto lseek_ret = lseek64(fd, (loff_t)addr, SEEK_SET); lseek_ret < 0)
                return -errno;

            auto ret = read(fd, buffer, length);
            return ret < 0 ? -errno : ret;
        }

        inline ssize_t write_memory(const int fd, const std::uintptr_t addr, const void *buffer, const std::size_t length)
        {
            if (auto lseek_ret = lseek64(fd, (loff_t)addr, SEEK_SET); lseek_ret < 0)
                return -errno;

            auto ret = write(fd, buffer, length);
            return ret < 0 ? -errno : ret;
        }

        inline ssize_t swap_memory(const int fd, const std::uintptr_t addr, void *backup, void *buffer, const std::size_t length)
        {
            auto ret = read_memory(fd, addr, backup, length);
            if (ret < 0)
                return ret;
            ret = write_memory(fd, addr, buffer, length);
            if (ret < 0)
                return ret;
            return 0;
        }

        bool is_process_paused(char *path_stat)
        {
            int fd_stat = open(path_stat, O_RDONLY);
            char temp[1024]{};
            read(fd_stat, temp, sizeof(temp));
            for (int i = 0, sc = 0; i < 50; i++)
            {
                if (temp[i] == ' ' && ++sc == 2)
                {
                    if (temp[i + 1] == 'T' || temp[i + 1] == 't')
                    {
                        close(fd_stat);
                        return true;
                    }
                }
            }
            close(fd_stat);
            return false;
        }

        struct pair_rsp_rip
        {
            int read_ret;
            std::uintptr_t rsp, rip;
        };

        pair_rsp_rip parse_procfs_syscall(int fd_syscall)
        {
            int sysnr{};
            std::uintptr_t regs[8]{};
            char buffer[512]{};

            int read_ret = read(fd_syscall, buffer, sizeof(buffer));
            if (read_ret < 0)
                return {-errno};

            sscanf(buffer, "%d %lx %lx %lx %lx %lx %lx %lx %lx",
                   &sysnr,
                   &regs[0], &regs[1], &regs[2], &regs[3], &regs[4], &regs[5], &regs[6], &regs[7]);

            for (int i = (sizeof(regs) / sizeof(regs[0])) - 1; i != -1; i--)
            {
                if (regs[i] != 0)
                    return {read_ret, regs[i - 1], regs[i]};
            }
            return {-ENXIO};
        }

        constexpr int MAX_TRY_COUNT = 10000;

        pair_rsp_rip pause_process(int pid, char *path_syscall)
        {
            int fd_syscall;
            int try_count{};
            char path_stat[256]{};

            sprintf(path_stat, "/proc/%d/stat", pid);

            kill(pid, SIGSTOP);
            while (try_count < MAX_TRY_COUNT)
            {
                if (is_process_paused(path_stat))
                    break;

                try_count++;
                usleep(1000);
            }
            if (try_count >= MAX_TRY_COUNT)
                return {-ENOENT};

            fd_syscall = open(path_syscall, O_RDONLY);
            if (fd_syscall <= 0)
                return {-ESRCH};

            detail::pair_rsp_rip proc_syscall = detail::parse_procfs_syscall(fd_syscall);
            close(fd_syscall);

            if (!proc_syscall.rsp || !proc_syscall.rip)
                proc_syscall.read_ret = -EAGAIN;

            return proc_syscall;
        }

        template <std::size_t N>
        long patch_process_and_execute(int pid, char *path_syscall, pair_rsp_rip &proc_syscall, rsyscall_args<N> &args, std::uintptr_t args_address)
        {
            int fd_syscall;
            int try_count{};
            unsigned char backup[sizeof(code)];
            char path_mem[256]{};

            sprintf(path_mem, "/proc/%d/mem", pid);
            int fd_mem = open(path_mem, O_RDWR);
            if (fd_mem < 0)
                return -errno;

            detail::swap_memory(fd_mem, proc_syscall.rip, backup, code, sizeof(backup));
            detail::write_memory(fd_mem, args_address, &args, sizeof(args));

            kill(pid, SIGCONT);
            while (try_count < detail::MAX_TRY_COUNT)
            {
                unsigned char patch[2]{};
                detail::read_memory(fd_mem, proc_syscall.rip, patch, 2);
                if (!memcmp(patch, args.jmp_infinite, 2))
                    break;
                try_count++;
                usleep(1000);
            }
            if (try_count >= detail::MAX_TRY_COUNT)
            {
                close(fd_mem);
                return -EINTR;
            }

            while (true)
            {
                fd_syscall = open(path_syscall, O_RDONLY);
                if (fd_syscall <= 0)
                    return -ESRCH;
                kill(pid, SIGSTOP);
                proc_syscall = detail::parse_procfs_syscall(fd_syscall);
                if (proc_syscall.rip == args.prologue_shellcode)
                    break;
                kill(pid, SIGCONT);
                close(fd_syscall);
                usleep(1000);
            }

            detail::read_memory(fd_mem, args_address, &args, sizeof(args));
            detail::write_memory(fd_mem, proc_syscall.rip, backup, sizeof(backup));
            kill(pid, SIGCONT);

            close(fd_syscall);
            close(fd_mem);

            return 0;
        }
    } // namespace

    template <class... _Args>
    long rsyscall(int pid, int sysnr, _Args... args)
    {
        constexpr int NOT_INITIALIZED = -1000;

        char path_syscall[256]{};
        sprintf(path_syscall, "/proc/%d/syscall", pid);

        detail::pair_rsp_rip proc_syscall = detail::pause_process(pid, path_syscall);
        if (proc_syscall.read_ret < 0)
            return proc_syscall.read_ret;

        std::uintptr_t args_address = proc_syscall.rsp - 0x4000;

        detail::packed_args<_Args...> pack{args...};
        detail::rsyscall_args<sizeof(pack)> rsyscall_args{};
        rsyscall_args.syscall_nr = sysnr;
        if constexpr (sizeof...(args) > 0)
        {
            auto &node = pack;
            rsyscall_args.arg0 =
                !node.value_is_address
                    ? (long)node.value
                    : args_address + ((std::uintptr_t)&rsyscall_args.args_buffer - (std::uintptr_t)&rsyscall_args) + ((std::uintptr_t)&node.value - (std::uintptr_t)&pack);
        }
        if constexpr (sizeof...(args) > 1)
        {
            auto &node = pack.rest;
            rsyscall_args.arg1 =
                !node.value_is_address
                    ? (long)node.value
                    : args_address + ((std::uintptr_t)&rsyscall_args.args_buffer - (std::uintptr_t)&rsyscall_args) + ((std::uintptr_t)&node.value - (std::uintptr_t)&pack);
        }
        if constexpr (sizeof...(args) > 2)
        {
            auto &node = pack.rest.rest;
            rsyscall_args.arg2 = !node.value_is_address
                                     ? (long)node.value
                                     : (args_address + ((std::uintptr_t)&rsyscall_args.args_buffer - (std::uintptr_t)&rsyscall_args) + ((std::uintptr_t)&node.value - (std::uintptr_t)&pack));
        }
        if constexpr (sizeof...(args) > 3)
        {
            auto &node = pack.rest.rest.rest;
            rsyscall_args.arg3 = !node.value_is_address
                                     ? (long)node.value
                                     : (args_address + ((std::uintptr_t)&rsyscall_args.args_buffer - (std::uintptr_t)&rsyscall_args) + ((std::uintptr_t)&node.value - (std::uintptr_t)&pack));
        }
        if constexpr (sizeof...(args) > 4)
        {
            auto &node = pack.rest.rest.rest.rest;
            rsyscall_args.arg4 = !node.value_is_address
                                     ? (long)node.value
                                     : (args_address + ((std::uintptr_t)&rsyscall_args.args_buffer - (std::uintptr_t)&rsyscall_args) + ((std::uintptr_t)&node.value - (std::uintptr_t)&pack));
        }
        if constexpr (sizeof...(args) > 5)
        {
            auto &node = pack.rest.rest.rest.rest.rest;
            rsyscall_args.arg5 = !node.value_is_address
                                     ? (long)node.value
                                     : (args_address + ((std::uintptr_t)&rsyscall_args.args_buffer - (std::uintptr_t)&rsyscall_args) + ((std::uintptr_t)&node.value - (std::uintptr_t)&pack));
        }
        rsyscall_args.syscall_ret = NOT_INITIALIZED;
        rsyscall_args.prologue_shellcode = proc_syscall.rip;
        std::memcpy((void *)rsyscall_args.args_buffer, (void *)&pack, sizeof(pack));

        long ret = detail::patch_process_and_execute(pid, path_syscall, proc_syscall, rsyscall_args, args_address);
        if (ret < 0)
            return ret;

        return rsyscall_args.syscall_ret == NOT_INITIALIZED ? -EIO : rsyscall_args.syscall_ret;
    }
} // namespace remote_syscall
#endif // REMOTE_SYSCALL_H