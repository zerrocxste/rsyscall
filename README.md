# remote_syscalls_linux
(PoC) системные вызововы Linux для удаленного процесса, без использования ptrace, что позволяет обходить детекцию дебага, если такая имеется (ptrace самого себя, /proc/self/status, т.д).

# Функционал
Пока что реализован системный вызов mmap, что позволяет проворачивать всякие цыганские фокусы (хехе).
В дальнейшем, возможно, будет релизована возможность делать все системные вызовы.
