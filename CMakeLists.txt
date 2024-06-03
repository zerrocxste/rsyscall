cmake_minimum_required(VERSION 3.0.0)
project(remote_syscalls_linux VERSION 0.1.0 LANGUAGES C CXX)

file(GLOB REMOTE_SYSCALL "*")

add_executable(remote_syscalls_linux ${REMOTE_SYSCALL})

