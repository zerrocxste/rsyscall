#include "remote_syscall.h"

#include <sys/syscall.h>
#include <chrono>

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

void test_open(int pid)
{
    unsigned long ret = remote_syscall::rsyscall<SYS_open>(pid, "/home/zerrocxste/test_file", O_RDONLY);

    if (ret < 0)
    {
        std::printf("[-] %s error: %lx\n", __func__, ret);
    }
    else
    {
        std::printf("[+] %s success: %p\n", __func__, (void *)ret);
    }
}

void test_mmap(int pid)
{
    unsigned long ret = remote_syscall::rsyscall<SYS_mmap>(pid, 0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);

    if (ret < 0)
    {
        std::printf("[-] %s error: %lx\n", __func__, ret);
    }
    else
    {
        std::printf("[+] %s success: %p\n", __func__, (void *)ret);
    }
}

int main(int argc, char **argv)
{
    int pid = get_pid("hde_test");

    if (pid <= 0)
    {
        std::printf("tester not found\n");
        return 1;
    }

    test_open(pid);
    test_mmap(pid);

    return 0;
}