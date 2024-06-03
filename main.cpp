#include "remote_syscall.h"

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

    auto ts = std::chrono::system_clock::now();

    auto ret = remote_syscall::mmap(pid, 0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);

    std::printf("[!] execution time: %ld ms\n",
                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - ts).count());

    if (ret < 0)
        std::printf("[-] failed. error code: %ld\n", ret);
    else
        std::printf("[+] success. address: %p\n", (void *)ret);
}