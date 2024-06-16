#include "remote_syscall.h"

#include <sys/syscall.h>
#include <chrono>
#include <sys/stat.h>
#include <linux/limits.h>
#include <sys/mman.h>

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

void test_open_and_read(int pid)
{
    const int read_size = 16384;

    char buffer_remote[read_size]{'1'};
    char buffer_this[read_size]{'2'};
    unsigned long fd_remote = remote_syscall::rsyscall<SYS_open>(pid, "/home/zerrocxste/test_file", O_RDONLY);

    if (fd_remote < 0)
    {
        std::printf("[-] %s error: %ld\n", __func__, fd_remote);
        return;
    }

    std::printf("[+] %s success: %ld\n", __func__, fd_remote);

    int fd_this = open("/home/zerrocxste/test_file", O_RDONLY);

    long read_ret_remote = remote_syscall::rsyscall<SYS_read>(pid, fd_remote, buffer_remote, read_size);
    long read_ret_this = read(fd_this, buffer_this, read_size);
    if (read_ret_remote != read_ret_this)
    {
        std::printf("[-] failed. read remote(%ld) this(%ld)\n", read_ret_remote, read_ret_this);
        return;
    }
    if (std::memcmp(buffer_remote, buffer_this, sizeof(read_size)) != 0)
    {
        std::printf("[-] faied. buffers not equal\n");
        return;
    }
    std::printf("[+] success read %ld\n", read_ret_remote);
}

void test_mmap(int pid)
{
    unsigned long ret = remote_syscall::rsyscall<SYS_mmap>(pid, 0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);

    if (ret < 0)
    {
        std::printf("[-] %s error: %ld\n", __func__, ret);
    }
    else
    {
        std::printf("[+] %s success: %p\n", __func__, (void *)ret);
    }
}

void test_stat(int pid)
{
    struct stat st, this_st;
    std::memset(&st, 0, sizeof(st));
    std::memset(&this_st, 0, sizeof(this_st));

    long ret = remote_syscall::rsyscall<SYS_stat>(pid, "/home/zerrocxste/test_file", &st);

    if (ret < 0)
    {
        std::printf("[-] %s error: %lx\n", __func__, ret);
    }
    else
    {
        std::printf("[+] %s success: %ld\n"
                    "\tst_dev: %ld\n"
                    "\tst_ino: %ld\n"
                    "\tst_nlink: %ld\n"
                    "\tst_mode: %u\n"
                    "\tst_uid: %u\n"
                    "\tst_gid: %u\n"
                    "\tst_rdev: %ld\n"
                    "\tst_size: %ld\n"
                    "\tst_blksize: %ld\n"
                    "\tst_blocks: %ld\n",
                    __func__, ret,
                    st.st_dev,
                    st.st_ino,
                    st.st_nlink,
                    st.st_mode,
                    st.st_uid,
                    st.st_gid,
                    st.st_rdev,
                    st.st_size,
                    st.st_blksize,
                    st.st_blocks);

        stat("/home/zerrocxste/test_file", &this_st);
        if (std::memcmp(&st, &this_st, sizeof(st)) != 0)
        {
            std::printf("\n[-] %s not equal, from this process:\n"
                        "\tst_dev: %ld\n"
                        "\tst_ino: %ld\n"
                        "\tst_nlink: %ld\n"
                        "\tst_mode: %u\n"
                        "\tst_uid: %u\n"
                        "\tst_gid: %u\n"
                        "\tst_rdev: %ld\n"
                        "\tst_size: %ld\n"
                        "\tst_blksize: %ld\n"
                        "\tst_blocks: %ld\n",
                        __func__,
                        this_st.st_dev,
                        this_st.st_ino,
                        this_st.st_nlink,
                        this_st.st_mode,
                        this_st.st_uid,
                        this_st.st_gid,
                        this_st.st_rdev,
                        this_st.st_size,
                        this_st.st_blksize,
                        this_st.st_blocks);
        }
    }
}

void test_getcwd(int pid)
{
    char buffer[PATH_MAX]{};
    long ret = remote_syscall::rsyscall<SYS_getcwd>(pid, buffer, sizeof(buffer));

    if (ret < 0)
    {
        std::printf("[-] %s error: %ld\n", __func__, ret);
    }
    else
    {
        std::printf("[+] %s success: %ld (%s)\n", __func__, ret, buffer);
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

    test_open_and_read(pid);
    test_mmap(pid);
    test_stat(pid);
    test_getcwd(pid);

    return 0;
}