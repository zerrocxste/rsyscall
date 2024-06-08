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

int main(int argc, char **argv)
{
    int pid = get_pid("hde_test");

    if (pid <= 0)
    {
        std::printf("tester not found\n");
        return 1;
    }

    unsigned long ret = remote_syscall::rsyscall(pid, SYS_open, "/home/zerrocxste/test_file", O_RDONLY);

    if (ret < 0)
    {
        std::printf("[-] error: %lx\n", ret);
    }
    else
    {
        std::printf("[+] success: %p\n", (void *)ret);
    }

    return ret;
}