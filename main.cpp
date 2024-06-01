#include <stdio.h>
#include <string.h>
#include <iostream>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

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
mov rdx, 0x7            # (PROT_READ | PROT_EXEC | PROT_WRITE)
mov r10, 0x22           # (MAP_PRIVATE | MAP_ANON)
mov r8, -1            # fd = -1
xor r9, r9              # off = 0
mov rax, 9            # syscall mmap
syscall
mov [rsp+0x10], rax # shell_args::mmap_ret

lea rdi, [rsp+0x22] # shell_args::path
mov rsi, 2
mov rax, 2        # syscall open
syscall
mov r10, rax # save fd

mov rdi, r10
mov rsi, [rsp+0x18] # shell_args::prologue_shellcode
xor rdx, rdx
mov rax, 8
syscall

mov rdi, r10
lea rsi, [rsp+0x20] # shell_args::jmp_inifinite
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
jmp [rsp-0x1000+0x18]*/

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
    "\x48\xc7\xc2\x07\x00\x00\x00" // mov rdx, 0x7            # (PROT_READ | PROT_EXEC | PROT_WRITE)
    "\x49\xc7\xc2\x22\x00\x00\x00" // mov r10, 0x22           # (MAP_PRIVATE | MAP_ANON)
    "\x49\xc7\xc0\xff\xff\xff\xff" // mov r8, -1            # fd = -1
    "\x4d\x31\xc9"                 // xor r9, r9              # off = 0
    "\x48\xc7\xc0\x09\x00\x00\x00" // mov rax, 9            # syscall mmap
    "\x0f\x05"                     // syscall
    "\x48\x89\x44\x24\x10"         // mov [rsp+0x10], rax # shell_args::mmap_ret
    "\x48\x8d\x7c\x24\x22"         // lea rdi, [rsp+0x22] # shell_args::path
    "\x48\xc7\xc6\x02\x00\x00\x00" // mov rsi, 2
    "\x48\xc7\xc0\x02\x00\x00\x00" // mov rax, 2        # syscall open
    "\x0f\x05"                     // syscall
    "\x49\x89\xc2"                 // mov r10, rax # save fd
    "\x4c\x89\xd7"                 // mov rdi, r10
    "\x48\x8b\x74\x24\x18"         // mov rsi, [rsp+0x18] # shell_args::prologue_shellcode
    "\x48\x31\xd2"                 // xor rdx, rdx
    "\x48\xc7\xc0\x08\x00\x00\x00" // mov rax, 8
    "\x0f\x05"                     // syscall
    "\x4c\x89\xd7"                 // mov rdi, r10
    "\x48\x8d\x74\x24\x20"         // lea rsi, [rsp+0x20] # shell_args::jmp_inifinite
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
    "\xff\xa4\x24\x18\xf0\xff\xff" // jmp [rsp-0x1000+0x18]
};

#pragma pack(push, 1)
struct shell_args
{
    long addr;                                 // 0x0
    long size;                                 // 0x8
    long mmap_ret;                             // 0x10
    unsigned long prologue_shellcode;          // 0x18
    unsigned char jmp_infinite[2]{0xeb, 0xfe}; // 0x20
    char path[15]{"/proc/self/mem"};           // 0x22
};
#pragma pack(pop)

inline auto read_memory(const int fd, const std::uintptr_t addr, void *buffer, const std::size_t length)
{
    if (auto lseek_ret = lseek64(fd, (loff_t)addr, SEEK_SET); lseek_ret < 0)
        return lseek_ret;

    auto ret = read(fd, buffer, length);
    return ret < 0 ? -errno : ret;
}

inline auto write_memory(const int fd, const std::uintptr_t addr, const void *buffer, const std::size_t length)
{
    if (auto lseek_ret = lseek64(fd, (loff_t)addr, SEEK_SET); lseek_ret < 0)
        return lseek_ret;

    auto ret = write(fd, buffer, length);
    return ret < 0 ? -errno : ret;
}

int get_pid(const char *process)
{
    char pid_buffer[256];
    snprintf(pid_buffer, sizeof(pid_buffer), "pidof -s %s", process);
    auto pipe = popen(pid_buffer, "r");
    if (pipe == 0)
        return -errno;
    fgets(pid_buffer, sizeof(pid_buffer), pipe);
    return (pclose(pipe) != 0)
               ? -ESRCH
               : strtoul(pid_buffer, NULL, 10);
}

long remote_mmap(int pid, void *address, size_t len)
{
    constexpr int MAX_TRY_COUNT = 10000;

    int fd;
    char buffer[4096]{};
    int sysnr{};
    std::uintptr_t regs[8];
    std::uintptr_t rsp, rip;
    unsigned char backup[sizeof(code)];

    kill(pid, SIGSTOP);

    sprintf(buffer, "/proc/%d/stat", pid);

    int try_count = 0;
    while (try_count < MAX_TRY_COUNT)
    {
        auto is_paused = [&]()
        {
            fd = open(buffer, O_RDONLY);

            char temp[1024]{};
            read(fd, temp, sizeof(temp));
            for (int i = 0, sc = 0; i < 50; i++)
            {
                if (temp[i] == ' ' && ++sc == 2)
                {
                    if (temp[i + 1] == 'T' || temp[i + 1] == 't')
                    {
                        close(fd);
                        return true;
                    }
                }
            }
            close(fd);
            return false;
        };

        if (is_paused())
            break;

        try_count++;
        usleep(1000);
    }

    if (try_count >= MAX_TRY_COUNT)
        return -ENOENT;

    sprintf(buffer, "/proc/%d/syscall", pid);
    fd = open(buffer, O_RDONLY);
    if (fd <= 0)
        return -ESRCH;

    if (read(fd, buffer, sizeof(buffer)) < 0)
        return -errno;

    close(fd);

    sscanf(buffer, "%d %lx %lx %lx %lx %lx %lx %lx %lx",
           &sysnr,
           &regs[0], &regs[1], &regs[2], &regs[3], &regs[4], &regs[5], &regs[6], &regs[7]);

    for (int i = (sizeof(regs) / sizeof(regs[0])) - 1; i != -1; i--)
    {
        if (regs[i] != 0)
        {
            rsp = regs[i - 1];
            rip = regs[i];
            break;
        }
    }

    if (!rsp || !rip)
        return -EAGAIN;

    sprintf(buffer, "/proc/%d/mem", pid);
    fd = open(buffer, O_RDWR);

    read_memory(fd, rip, backup, sizeof(backup));
    write_memory(fd, rip, code, sizeof(code));

    shell_args args{};
    args.addr = 0;
    args.size = 0x1000;
    args.mmap_ret = -100;
    args.prologue_shellcode = rip;
    std::uintptr_t shell_address = rsp - 0x1000;
    write_memory(fd, shell_address, &args, sizeof(args));

    kill(pid, SIGCONT);
    try_count = 0;
    while (try_count < MAX_TRY_COUNT)
    {
        unsigned char patch[2]{};
        read_memory(fd, rip, patch, 2);
        if (!memcmp(patch, args.jmp_infinite, 2))
            break;
        try_count++;
        usleep(1000);
    }

    if (try_count >= MAX_TRY_COUNT)
    {
        close(fd);
        return -EINTR;
    }

    read_memory(fd, shell_address, &args, sizeof(args));
    write_memory(fd, rip, backup, sizeof(backup));

    close(fd);
    return args.mmap_ret == -100 ? -EIO : args.mmap_ret;
}

int main(int argc, char **argv)
{
    if (argc < 2 || !*argv[1])
    {
        std::printf("[-] usage: remote_syscall_linux <process>\n");
        return 1;
    }

    auto pid = get_pid(argv[1]);
    if (pid <= 0)
    {
        std::printf("not founded\n");
        return 1;
    }

    auto ret = remote_mmap(pid, 0, 4096);
    if (ret < 0)
    {
        std::printf("[-] failed. error code: %ld\n", ret);
    }
    else
    {
        std::printf("[+] success. address: %p\n", (void *)ret);
    }
}