#ifndef REMOTE_SYSCALL_H
#define REMOTE_SYSCALL_H

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mman.h>

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
    sub rsp, 0x1000

    mov rdi, [rsp] # shell_args::addr
    mov rsi, [rsp+0x8] # shell_args::size
    mov rdx, [rsp+0x10] # shell_args::prot
    mov r10, [rsp+0x18] # shell_args::flags
    mov r8, [rsp+0x20] # shell_args::fd
    mov r9, [rsp+0x28] #shell_args::offset
    mov rax, 9            # syscall mmap
    syscall
    mov [rsp+0x30], rax # shell_args::mmap_ret

    lea rdi, [rsp+0x42] # shell_args::path
    mov rsi, 2
    mov rax, 2        # syscall open
    syscall
    mov r10, rax # save fd

    mov rdi, r10
    mov rsi, [rsp+0x38] # shell_args::prologue_shellcode
    xor rdx, rdx
    mov rax, 8
    syscall

    mov rdi, r10
    lea rsi, [rsp+0x40] # shell_args::jmp_inifinite
    mov rdx, 2
    mov rax, 1       # syscall write
    syscall

    add rsp, 0x1000
    mov r10, [rsp-0x40]
    mov r9, [rsp-0x38]
    mov r8, [rsp-0x30]
    mov rdi, [rsp-0x28]
    mov rsi, [rsp-0x20]
    mov rdx, [rsp-0x18]
    mov rcx, [rsp-0x10]
    mov rbx, [rsp-0x8]
    mov rax, [rsp]
    jmp [rsp-0x1000+0x38] #args::shellcode_prologue
    */

    unsigned char code[] = {
        "\x48\x89\x04\x24"             // mov [rsp], rax
        "\x48\x89\x5c\x24\xf8"         // mov [rsp-0x8], rbx
        "\x48\x89\x4c\x24\xf0"         // mov [rsp-0x10], rcx
        "\x48\x89\x54\x24\xe8"         // mov [rsp-0x18], rdx
        "\x48\x89\x74\x24\xe0"         // mov [rsp-0x20], rsi
        "\x48\x89\x7c\x24\xd8"         // mov [rsp-0x28], rdi
        "\x4c\x89\x44\x24\xd0"         // mov [rsp-0x30], r8
        "\x4c\x89\x4c\x24\xc8"         // mov [rsp-0x38], r9
        "\x4c\x89\x54\x24\xc0"         // mov [rsp-0x40], r10
        "\x48\x81\xec\x00\x10\x00\x00" // sub rsp, 0x1000
        "\x48\x8b\x3c\x24"             // mov rdi, [rsp] # shell_args::addr
        "\x48\x8b\x74\x24\x08"         // mov rsi, [rsp+0x8] # shell_args::size
        "\x48\x8b\x54\x24\x10"         // mov rdx, [rsp+0x10] # shell_args::prot
        "\x4c\x8b\x54\x24\x18"         // mov r10, [rsp+0x18] # shell_args::flags
        "\x4c\x8b\x44\x24\x20"         // mov r8, [rsp+0x20] # shell_args::fd
        "\x4c\x8b\x4c\x24\x28"         // mov r9, [rsp+0x28] #shell_args::offset
        "\x48\xc7\xc0\x09\x00\x00\x00" // mov rax, 9            # syscall mmap
        "\x0f\x05"                     // syscall
        "\x48\x89\x44\x24\x30"         // mov [rsp+0x30], rax # shell_args::mmap_ret
        "\x48\x8d\x7c\x24\x42"         // lea rdi, [rsp+0x42] # shell_args::path
        "\x48\xc7\xc6\x02\x00\x00\x00" // mov rsi, 2
        "\x48\xc7\xc0\x02\x00\x00\x00" // mov rax, 2        # syscall open
        "\x0f\x05"                     // syscall
        "\x49\x89\xc2"                 // mov r10, rax # save fd
        "\x4c\x89\xd7"                 // mov rdi, r10
        "\x48\x8b\x74\x24\x38"         // mov rsi, [rsp+0x38] # shell_args::prologue_shellcode
        "\x48\x31\xd2"                 // xor rdx, rdx
        "\x48\xc7\xc0\x08\x00\x00\x00" // mov rax, 8
        "\x0f\x05"                     // syscall
        "\x4c\x89\xd7"                 // mov rdi, r10
        "\x48\x8d\x74\x24\x40"         // lea rsi, [rsp+0x40] # shell_args::jmp_inifinite
        "\x48\xc7\xc2\x02\x00\x00\x00" // mov rdx, 2
        "\x48\xc7\xc0\x01\x00\x00\x00" // mov rax, 1       # syscall write
        "\x0f\x05"                     // syscall
        "\x48\x81\xc4\x00\x10\x00\x00" // add rsp, 0x1000
        "\x4c\x8b\x54\x24\xc0"         // mov r10, [rsp-0x40]
        "\x4c\x8b\x4c\x24\xc8"         // mov r9, [rsp-0x38]
        "\x4c\x8b\x44\x24\xd0"         // mov r8, [rsp-0x30]
        "\x48\x8b\x7c\x24\xd8"         // mov rdi, [rsp-0x28]
        "\x48\x8b\x74\x24\xe0"         // mov rsi, [rsp-0x20]
        "\x48\x8b\x54\x24\xe8"         // mov rdx, [rsp-0x18]
        "\x48\x8b\x4c\x24\xf0"         // mov rcx, [rsp-0x10]
        "\x48\x8b\x5c\x24\xf8"         // mov rbx, [rsp-0x8]
        "\x48\x8b\x04\x24"             // mov rax, [rsp]
        "\xff\xa4\x24\x38\xf0\xff\xff" // jmp [rsp-0x1000+0x18] #args::shellcode_prologue
    };

    namespace detail
    {
#pragma pack(push, 1)
        struct shell_args
        {
            long addr;                                 // 0x0
            long size;                                 // 0x8
            long prot;                                 // 0x10
            long flags;                                // 0x18
            long fd;                                   // 0x20
            long offset;                               // 0x28
            long mmap_ret;                             // 0x30
            unsigned long prologue_shellcode;          // 0x38
            unsigned char jmp_infinite[2]{0xeb, 0xfe}; // 0x40
            char path[15]{"/proc/self/mem"};           // 0x42
        };
#pragma pack(pop)

        inline ssize_t read_memory(const int fd, const std::uintptr_t addr, void *buffer, const std::size_t length)
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
            std::uintptr_t regs[8];
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
    } // namespace

    long mmap(int pid, void *address, size_t length, int prot, int flags, int fd, off_t offset)
    {
        constexpr int MAX_TRY_COUNT = 10000;
        constexpr int NOT_INITIALIZED = -1000;

        int fd_syscall, fd_mem;
        char path_stat[256]{}, path_syscall[256]{}, path_mem[256]{};
        unsigned char backup[sizeof(code)];
        int try_count;

        sprintf(path_stat, "/proc/%d/stat", pid);
        sprintf(path_syscall, "/proc/%d/syscall", pid);
        sprintf(path_mem, "/proc/%d/mem", pid);

        kill(pid, SIGSTOP);

        try_count = 0;
        while (try_count < MAX_TRY_COUNT)
        {
            if (detail::is_process_paused(path_stat))
                break;

            try_count++;
            usleep(1000);
        }
        if (try_count >= MAX_TRY_COUNT)
            return -ENOENT;

        fd_syscall = open(path_syscall, O_RDONLY);
        if (fd_syscall <= 0)
            return -ESRCH;

        auto proc_syscall = detail::parse_procfs_syscall(fd_syscall);

        if (proc_syscall.read_ret < 0)
            return proc_syscall.read_ret;

        if (!proc_syscall.rsp || !proc_syscall.rip)
            return -EAGAIN;

        fd_mem = open(path_mem, O_RDWR);

        detail::read_memory(fd_mem, proc_syscall.rip, backup, sizeof(backup));
        detail::write_memory(fd_mem, proc_syscall.rip, code, sizeof(code));

        detail::shell_args args{};
        args.addr = 0;
        args.size = 0x1000;
        args.prot = prot;
        args.flags = flags;
        args.fd = fd;
        args.offset = offset;
        args.mmap_ret = NOT_INITIALIZED;
        args.prologue_shellcode = proc_syscall.rip;
        std::uintptr_t shell_address = proc_syscall.rsp - 0x1000;
        detail::write_memory(fd_mem, shell_address, &args, sizeof(args));

        kill(pid, SIGCONT);

        try_count = 0;
        while (try_count < MAX_TRY_COUNT)
        {
            unsigned char patch[2]{};
            detail::read_memory(fd_mem, proc_syscall.rip, patch, 2);
            if (!memcmp(patch, args.jmp_infinite, 2))
                break;
            try_count++;
            usleep(1000);
        }
        if (try_count >= MAX_TRY_COUNT)
        {
            close(fd_syscall);
            close(fd_mem);
            return -EINTR;
        }

        close(fd_syscall);
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

        detail::read_memory(fd_mem, shell_address, &args, sizeof(args));
        detail::write_memory(fd_mem, proc_syscall.rip, backup, sizeof(backup));
        kill(pid, SIGCONT);

        close(fd_syscall);
        close(fd_mem);
        return args.mmap_ret == NOT_INITIALIZED ? -EIO : args.mmap_ret;
    }
} // namespace remote_syscall
#endif // REMOTE_SYSCALL_H