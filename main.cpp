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

    unsigned long ret = remote_syscall::rsyscall(pid, SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);

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