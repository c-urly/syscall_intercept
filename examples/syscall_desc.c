/*
 * Copyright 2017, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *     * Neither the name of the copyright holder nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "syscall_desc.h"

#include <stddef.h>
#include <syscall.h>
#include <fcntl.h>

#define SARGS(name, r, ...) \
	[SYS_##name] = {#name, r, {__VA_ARGS__, }}

/* Linux syscalls on X86_64 */
static const struct syscall_desc table[] = {
#ifdef SYS_read
    SARGS(read, rdec, arg_fd, arg_, arg_),
#endif
#ifdef SYS_write
    SARGS(write, rdec, arg_fd, arg_, arg_),
#endif
#ifdef SYS_open
    SARGS(open, rdec, arg_cstr, arg_open_flags, arg_mode),
#endif
#ifdef SYS_close
    SARGS(close, rdec, arg_fd),
#endif
#ifdef SYS_stat
    SARGS(stat, rdec, arg_cstr, arg_),
#endif
#ifdef SYS_fstat
    SARGS(fstat, rdec, arg_fd, arg_),
#endif
#ifdef SYS_lstat
    SARGS(lstat, rdec, arg_cstr, arg_),
#endif
#ifdef SYS_poll
    SARGS(poll, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_lseek
    SARGS(lseek, rdec, arg_fd, arg_, arg_),
#endif
#ifdef SYS_mmap
    SARGS(mmap, rhex, arg_, arg_, arg_, arg_, arg_fd, arg_),
#endif
#ifdef SYS_mprotect
    SARGS(mprotect, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_munmap
    SARGS(munmap, rdec, arg_, arg_, arg_, arg_, arg_fd, arg_),
#endif
#ifdef SYS_brk
    SARGS(brk, rdec, arg_),
#endif
#ifdef SYS_rt_sigaction
    SARGS(rt_sigaction, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_rt_sigprocmask
    SARGS(rt_sigprocmask, rdec, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_rt_sigreturn
    SARGS(rt_sigreturn, rnoreturn, arg_none),
#endif
#ifdef SYS_ioctl
    SARGS(ioctl, rdec, arg_fd, arg_, arg_),
#endif
#ifdef SYS_pread64
    SARGS(pread64, rdec, arg_fd, arg_, arg_, arg_),
#endif
#ifdef SYS_pwrite64
    SARGS(pwrite64, rdec, arg_fd, arg_, arg_, arg_),
#endif
#ifdef SYS_readv
    SARGS(readv, rdec, arg_fd, arg_, arg_),
#endif
#ifdef SYS_writev
    SARGS(writev, rdec, arg_fd, arg_, arg_),
#endif
#ifdef SYS_access
    SARGS(access, rdec, arg_cstr, arg_mode),
#endif
#ifdef SYS_pipe
    SARGS(pipe, rdec, arg_),
#endif
#ifdef SYS_select
    SARGS(select, rdec, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_sched_yield
    SARGS(sched_yield, rdec, arg_none),
#endif
#ifdef SYS_mremap
    SARGS(mremap, rhex, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_msync
    SARGS(msync, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_mincore
    SARGS(mincore, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_madvise
    SARGS(madvise, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_shmget
    SARGS(shmget, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_shmat
    SARGS(shmat, rhex, arg_, arg_, arg_),
#endif
#ifdef SYS_shmctl
    SARGS(shmctl, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_dup
    SARGS(dup, rdec, arg_fd),
#endif
#ifdef SYS_dup2
    SARGS(dup2, rdec, arg_fd, arg_fd),
#endif
#ifdef SYS_pause
    SARGS(pause, rdec, arg_none),
#endif
#ifdef SYS_nanosleep
    SARGS(nanosleep, rdec, arg_, arg_),
#endif
#ifdef SYS_getitimer
    SARGS(getitimer, rdec, arg_, arg_),
#endif
#ifdef SYS_alarm
    SARGS(alarm, runsigned, arg_),
#endif
#ifdef SYS_setitimer
    SARGS(setitimer, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_getpid
    SARGS(getpid, rdec, arg_none),
#endif
#ifdef SYS_sendfile
    SARGS(sendfile, rdec, arg_fd, arg_fd, arg_, arg_),
#endif
#ifdef SYS_socket
    SARGS(socket, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_connect
    SARGS(connect, rdec, arg_fd, arg_, arg_),
#endif
#ifdef SYS_accept
    SARGS(accept, rdec, arg_fd, arg_, arg_),
#endif
#ifdef SYS_sendto
    SARGS(sendto, rdec, arg_fd, arg_, arg_, arg_),
#endif
#ifdef SYS_recvfrom
    SARGS(recvfrom, rdec, arg_fd, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_sendmsg
    SARGS(sendmsg, rdec, arg_fd, arg_, arg_),
#endif
#ifdef SYS_recvmsg
    SARGS(recvmsg, rdec, arg_fd, arg_, arg_),
#endif
#ifdef SYS_shutdown
    SARGS(shutdown, rdec, arg_fd, arg_),
#endif
#ifdef SYS_bind
    SARGS(bind, rdec, arg_fd, arg_, arg_),
#endif
#ifdef SYS_listen
    SARGS(listen, rdec, arg_fd, arg_),
#endif
#ifdef SYS_getsockname
    SARGS(getsockname, rdec, arg_fd, arg_, arg_),
#endif
#ifdef SYS_getpeername
    SARGS(getpeername, rdec, arg_fd, arg_, arg_),
#endif
#ifdef SYS_socketpair
    SARGS(socketpair, rdec, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_setsockopt
    SARGS(setsockopt, rdec, arg_fd, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_getsockopt
    SARGS(getsockopt, rdec, arg_fd, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_clone
    SARGS(clone, rdec, arg_, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_fork
    SARGS(fork, rdec, arg_none),
#endif
#ifdef SYS_vfork
    SARGS(vfork, rdec, arg_none),
#endif
#ifdef SYS_execve
    SARGS(execve, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_exit
    SARGS(exit, rnoreturn, arg_),
#endif
#ifdef SYS_wait4
    SARGS(wait4, rdec, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_kill
    SARGS(kill, rdec, arg_, arg_),
#endif
#ifdef SYS_uname
    SARGS(uname, rdec, arg_),
#endif
#ifdef SYS_semget
    SARGS(semget, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_semop
    SARGS(semop, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_semctl
    SARGS(semctl, rdec, arg_, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_shmdt
    SARGS(shmdt, rdec, arg_),
#endif
#ifdef SYS_msgget
    SARGS(msgget, rdec, arg_, arg_),
#endif
#ifdef SYS_msgsnd
    SARGS(msgsnd, rdec, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_msgrcv
    SARGS(msgrcv, rdec, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_msgctl
    SARGS(msgctl, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_fcntl
    SARGS(fcntl, rdec, arg_fd, arg_, arg_),
#endif
#ifdef SYS_flock
    SARGS(flock, rdec, arg_fd, arg_),
#endif
#ifdef SYS_fsync
    SARGS(fsync, rdec, arg_fd),
#endif
#ifdef SYS_fdatasync
    SARGS(fdatasync, rdec, arg_fd),
#endif
#ifdef SYS_truncate
    SARGS(truncate, rdec, arg_cstr, arg_),
#endif
#ifdef SYS_ftruncate
    SARGS(ftruncate, rdec, arg_fd, arg_),
#endif
#ifdef SYS_getdents
    SARGS(getdents, rdec, arg_fd, arg_, arg_),
#endif
#ifdef SYS_getcwd
    SARGS(getcwd, rdec, arg_, arg_),
#endif
#ifdef SYS_chdir
    SARGS(chdir, rdec, arg_cstr),
#endif
#ifdef SYS_fchdir
    SARGS(fchdir, rdec, arg_fd),
#endif
#ifdef SYS_rename
    SARGS(rename, rdec, arg_cstr, arg_cstr),
#endif
#ifdef SYS_mkdir
    SARGS(mkdir, rdec, arg_cstr, arg_mode),
#endif
#ifdef SYS_rmdir
    SARGS(rmdir, rdec, arg_cstr),
#endif
#ifdef SYS_creat
    SARGS(creat, rdec, arg_cstr, arg_mode),
#endif
#ifdef SYS_link
    SARGS(link, rdec, arg_cstr, arg_cstr),
#endif
#ifdef SYS_unlink
    SARGS(unlink, rdec, arg_cstr),
#endif
#ifdef SYS_symlink
    SARGS(symlink, rdec, arg_cstr, arg_cstr),
#endif
#ifdef SYS_readlink
    SARGS(readlink, rdec, arg_cstr, arg_, arg_),
#endif
#ifdef SYS_chmod
    SARGS(chmod, rdec, arg_cstr, arg_mode),
#endif
#ifdef SYS_fchmod
    SARGS(fchmod, rdec, arg_fd, arg_mode),
#endif
#ifdef SYS_chown
    SARGS(chown, rdec, arg_cstr, arg_, arg_),
#endif
#ifdef SYS_fchown
    SARGS(fchown, rdec, arg_fd, arg_, arg_),
#endif
#ifdef SYS_lchown
    SARGS(lchown, rdec, arg_cstr, arg_, arg_),
#endif
#ifdef SYS_umask
    SARGS(umask, rmode, arg_mode),
#endif
#ifdef SYS_gettimeofday
    SARGS(gettimeofday, rdec, arg_, arg_),
#endif
#ifdef SYS_getrlimit
    SARGS(getrlimit, rdec, arg_, arg_),
#endif
#ifdef SYS_getrusage
    SARGS(getrusage, rdec, arg_, arg_),
#endif
#ifdef SYS_sysinfo
    SARGS(sysinfo, rdec, arg_, arg_),
#endif
#ifdef SYS_times
    SARGS(times, rdec, arg_),
#endif
#ifdef SYS_ptrace
    SARGS(ptrace, rhex, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_getuid
    SARGS(getuid, rdec, arg_none),
#endif
#ifdef SYS_syslog
    SARGS(syslog, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_getgid
    SARGS(getgid, rdec, arg_none),
#endif
#ifdef SYS_setuid
    SARGS(setuid, rdec, arg_),
#endif
#ifdef SYS_setgid
    SARGS(setgid, rdec, arg_),
#endif
#ifdef SYS_geteuid
    SARGS(geteuid, rdec, arg_none),
#endif
#ifdef SYS_getegid
    SARGS(getegid, rdec, arg_none),
#endif
#ifdef SYS_setpgid
    SARGS(setpgid, rdec, arg_none),
#endif
#ifdef SYS_getpgrp
    SARGS(getpgrp, rdec, arg_none),
#endif
#ifdef SYS_setsid
    SARGS(setsid, rdec, arg_none),
#endif
#ifdef SYS_setreuid
    SARGS(setreuid, rdec, arg_, arg_),
#endif
#ifdef SYS_setregid
    SARGS(setregid, rdec, arg_, arg_),
#endif
#ifdef SYS_getgroups
    SARGS(getgroups, rdec, arg_, arg_),
#endif
#ifdef SYS_setgroups
    SARGS(setgroups, rdec, arg_, arg_),
#endif
#ifdef SYS_setresuid
    SARGS(setresuid, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_getresuid
    SARGS(getresuid, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_setresgid
    SARGS(setresgid, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_getresgid
    SARGS(getresgid, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_getpgid
    SARGS(getpgid, rdec, arg_),
#endif
#ifdef SYS_setfsuid
    SARGS(setfsuid, rdec, arg_),
#endif
#ifdef SYS_setfsgid
    SARGS(setfsgid, rdec, arg_),
#endif
#ifdef SYS_getsid
    SARGS(getsid, rdec, arg_),
#endif
#ifdef SYS_capget
    SARGS(capget, rdec, arg_, arg_),
#endif
#ifdef SYS_capset
    SARGS(capset, rdec, arg_, arg_),
#endif
#ifdef SYS_rt_sigpending
    SARGS(rt_sigpending, rdec, arg_),
#endif
#ifdef SYS_rt_sigtimedwait
    SARGS(rt_sigtimedwait, rdec, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_rt_sigqueueinfo
    SARGS(rt_sigqueueinfo, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_rt_sigsuspend
    SARGS(rt_sigsuspend, rdec, arg_, arg_),
#endif
#ifdef SYS_sigaltstack
    SARGS(sigaltstack, rdec, arg_, arg_),
#endif
#ifdef SYS_utime
    SARGS(utime, rdec, arg_cstr, arg_),
#endif
#ifdef SYS_mknod
    SARGS(mknod, rdec, arg_cstr, arg_, arg_),
#endif
#ifdef SYS_uselib
    SARGS(uselib, rdec, arg_cstr),
#endif
#ifdef SYS_personality
    SARGS(personality, rdec, arg_),
#endif
#ifdef SYS_ustat
    SARGS(ustat, rdec, arg_, arg_),
#endif
#ifdef SYS_statfs
    SARGS(statfs, rdec, arg_cstr, arg_),
#endif
#ifdef SYS_fstatfs
    SARGS(fstatfs, rdec, arg_fd, arg_),
#endif
#ifdef SYS_sysfs
    SARGS(sysfs, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_getpriority
    SARGS(getpriority, rdec, arg_, arg_),
#endif
#ifdef SYS_setpriority
    SARGS(setpriority, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_sched_setparam
    SARGS(sched_setparam, rdec, arg_, arg_),
#endif
#ifdef SYS_sched_getparam
    SARGS(sched_getparam, rdec, arg_, arg_),
#endif
#ifdef SYS_sched_setscheduler
    SARGS(sched_setscheduler, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_sched_getscheduler
    SARGS(sched_getscheduler, rdec, arg_),
#endif
#ifdef SYS_sched_get_priority_max
    SARGS(sched_get_priority_max, rdec, arg_),
#endif
#ifdef SYS_sched_get_priority_min
    SARGS(sched_get_priority_min, rdec, arg_),
#endif
#ifdef SYS_sched_rr_get_interval
    SARGS(sched_rr_get_interval, rdec, arg_, arg_),
#endif
#ifdef SYS_mlock
    SARGS(mlock, rdec, arg_, arg_),
#endif
#ifdef SYS_munlock
    SARGS(munlock, rdec, arg_, arg_),
#endif
#ifdef SYS_mlockall
    SARGS(mlockall, rdec, arg_),
#endif
#ifdef SYS_munlockall
    SARGS(munlockall, rdec, arg_none),
#endif
#ifdef SYS_vhangup
    SARGS(vhangup, rdec, arg_none),
#endif
#ifdef SYS_modify_ldt
    SARGS(modify_ldt, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_pivot_root
    SARGS(pivot_root, rdec, arg_cstr, arg_),
#endif
#ifdef SYS__sysctl
    SARGS(_sysctl, rdec, arg_),
#endif
#ifdef SYS_prctl
    SARGS(prctl, rdec, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_arch_prctl
    SARGS(arch_prctl, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_adjtimex
    SARGS(adjtimex, rdec, arg_),
#endif
#ifdef SYS_setrlimit
    SARGS(setrlimit, rdec, arg_, arg_),
#endif
#ifdef SYS_chroot
    SARGS(chroot, rdec, arg_cstr),
#endif
#ifdef SYS_sync
    SARGS(sync, rdec, arg_none),
#endif
#ifdef SYS_acct
    SARGS(acct, rdec, arg_cstr),
#endif
#ifdef SYS_settimeofday
    SARGS(settimeofday, rdec, arg_, arg_),
#endif
#ifdef SYS_mount
    SARGS(mount, rdec, arg_cstr, arg_cstr, arg_, arg_, arg_),
#endif
#ifdef SYS_umount2
    SARGS(umount2, rdec, arg_cstr, arg_),
#endif
#ifdef SYS_swapon
    SARGS(swapon, rdec, arg_cstr, arg_),
#endif
#ifdef SYS_swapoff
    SARGS(swapoff, rdec, arg_cstr),
#endif
#ifdef SYS_reboot
    SARGS(reboot, rdec, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_sethostname
    SARGS(sethostname, rdec, arg_, arg_),
#endif
#ifdef SYS_setdomainname
    SARGS(setdomainname, rdec, arg_, arg_),
#endif
#ifdef SYS_iopl
    SARGS(iopl, rdec, arg_),
#endif
#ifdef SYS_ioperm
    SARGS(ioperm, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_gettid
    SARGS(gettid, rdec, arg_none),
#endif
#ifdef SYS_readahead
    SARGS(readahead, rdec, arg_fd, arg_, arg_),
#endif
#ifdef SYS_setxattr
    SARGS(setxattr, rdec, arg_cstr, arg_cstr, arg_, arg_, arg_),
#endif
#ifdef SYS_lsetxattr
    SARGS(lsetxattr, rdec, arg_cstr, arg_cstr, arg_, arg_, arg_),
#endif
#ifdef SYS_fsetxattr
    SARGS(fsetxattr, rdec, arg_fd, arg_cstr, arg_, arg_, arg_),
#endif
#ifdef SYS_getxattr
    SARGS(getxattr, rdec, arg_cstr, arg_cstr, arg_, arg_),
#endif
#ifdef SYS_lgetxattr
    SARGS(lgetxattr, rdec, arg_cstr, arg_cstr, arg_, arg_),
#endif
#ifdef SYS_fgetxattr
    SARGS(fgetxattr, rdec, arg_fd, arg_cstr, arg_, arg_),
#endif
#ifdef SYS_listxattr
    SARGS(listxattr, rdec, arg_cstr, arg_, arg_),
#endif
#ifdef SYS_llistxattr
    SARGS(llistxattr, rdec, arg_cstr, arg_, arg_),
#endif
#ifdef SYS_flistxattr
    SARGS(flistxattr, rdec, arg_cstr, arg_, arg_),
#endif
#ifdef SYS_removexattr
    SARGS(removexattr, rdec, arg_cstr, arg_cstr),
#endif
#ifdef SYS_lremovexattr
    SARGS(lremovexattr, rdec, arg_cstr, arg_cstr),
#endif
#ifdef SYS_fremovexattr
    SARGS(fremovexattr, rdec, arg_fd, arg_cstr),
#endif
#ifdef SYS_tkill
    SARGS(tkill, rdec, arg_, arg_),
#endif
#ifdef SYS_time
    SARGS(time, rdec, arg_),
#endif
#ifdef SYS_futex
    SARGS(futex, rdec, arg_, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_sched_setaffinity
    SARGS(sched_setaffinity, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_sched_getaffinity
    SARGS(sched_getaffinity, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_set_thread_area
    SARGS(set_thread_area, rdec, arg_),
#endif
#ifdef SYS_io_setup
    SARGS(io_setup, rdec, arg_, arg_),
#endif
#ifdef SYS_io_destroy
    SARGS(io_destroy, rdec, arg_),
#endif
#ifdef SYS_io_getevents
    SARGS(io_getevents, rdec, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_io_submit
    SARGS(io_submit, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_io_cancel
    SARGS(io_cancel, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_get_thread_area
    SARGS(get_thread_area, rdec, arg_),
#endif
#ifdef SYS_lookup_dcookie
    SARGS(lookup_dcookie, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_epoll_create
    SARGS(epoll_create, rdec, arg_),
#endif
#ifdef SYS_getdents64
    SARGS(getdents64, rdec, arg_fd, arg_, arg_),
#endif
#ifdef SYS_set_tid_address
    SARGS(set_tid_address, rdec, arg_),
#endif
#ifdef SYS_semtimedop
    SARGS(semtimedop, rdec, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_fadvise64
    SARGS(fadvise64, rdec, arg_fd, arg_, arg_, arg_),
#endif
#ifdef SYS_timer_create
    SARGS(timer_create, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_timer_settime
    SARGS(timer_settime, rdec, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_timer_gettime
    SARGS(timer_gettime, rdec, arg_, arg_),
#endif
#ifdef SYS_timer_getoverrun
    SARGS(timer_getoverrun, rdec, arg_),
#endif
#ifdef SYS_timer_delete
    SARGS(timer_delete, rdec, arg_),
#endif
#ifdef SYS_clock_settime
    SARGS(clock_settime, rdec, arg_, arg_),
#endif
#ifdef SYS_clock_gettime
    SARGS(clock_gettime, rdec, arg_, arg_),
#endif
#ifdef SYS_clock_getres
    SARGS(clock_getres, rdec, arg_, arg_),
#endif
#ifdef SYS_clock_nanosleep
    SARGS(clock_nanosleep, rdec, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_exit_group
    SARGS(exit_group, rnoreturn, arg_),
#endif
#ifdef SYS_epoll_wait
    SARGS(epoll_wait, rdec, arg_fd, arg_, arg_, arg_),
#endif
#ifdef SYS_epoll_ctl
    SARGS(epoll_ctl, rdec, arg_fd, arg_, arg_fd, arg_),
#endif
#ifdef SYS_tgkill
    SARGS(tgkill, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_utimes
    SARGS(utimes, rdec, arg_cstr, arg_),
#endif
#ifdef SYS_mbind
    SARGS(mbind, rdec, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_set_mempolicy
    SARGS(set_mempolicy, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_get_mempolicy
    SARGS(get_mempolicy, rdec, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_mq_open
    SARGS(mq_open, rdec, arg_cstr, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_mq_unlink
    SARGS(mq_unlink, rdec, arg_cstr),
#endif
#ifdef SYS_mq_timedsend
    SARGS(mq_timedsend, rdec, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_mq_timedreceive
    SARGS(mq_timedreceive, rdec, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_mq_notify
    SARGS(mq_notify, rdec, arg_, arg_),
#endif
#ifdef SYS_mq_getsetattr
    SARGS(mq_getsetattr, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_kexec_load
    SARGS(kexec_load, rdec, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_waitid
    SARGS(waitid, rdec, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_add_key
    SARGS(add_key, rdec, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_request_key
    SARGS(request_key, rdec, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_keyctl
    SARGS(keyctl, rdec, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_ioprio_set
    SARGS(ioprio_set, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_ioprio_get
    SARGS(ioprio_get, rdec, arg_, arg_),
#endif
#ifdef SYS_inotify_init
    SARGS(inotify_init, rdec, arg_none),
#endif
#ifdef SYS_inotify_add_watch
    SARGS(inotify_add_watch, rdec, arg_fd, arg_cstr, arg_),
#endif
#ifdef SYS_inotify_rm_watch
    SARGS(inotify_rm_watch, rdec, arg_fd, arg_),
#endif
#ifdef SYS_migrate_pages
    SARGS(migrate_pages, rdec, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_openat
    SARGS(openat, rdec, arg_atfd, arg_cstr, arg_open_flags, arg_mode),
#endif
#ifdef SYS_mkdirat
    SARGS(mkdirat, rdec, arg_atfd, arg_cstr, arg_mode),
#endif
#ifdef SYS_mknodat
    SARGS(mknodat, rdec, arg_atfd, arg_cstr, arg_mode, arg_),
#endif
#ifdef SYS_fchownat
    SARGS(fchownat, rdec, arg_atfd, arg_cstr, arg_, arg_, arg_),
#endif
#ifdef SYS_futimesat
    SARGS(futimesat, rdec, arg_atfd, arg_cstr, arg_),
#endif
#ifdef SYS_newfstatat
    SARGS(newfstatat, rdec, arg_atfd, arg_cstr, arg_, arg_),
#endif
#ifdef SYS_unlinkat
    SARGS(unlinkat, rdec, arg_atfd, arg_cstr, arg_),
#endif
#ifdef SYS_renameat
    SARGS(renameat, rdec, arg_atfd, arg_cstr, arg_atfd, arg_cstr),
#endif
#ifdef SYS_linkat
    SARGS(linkat, rdec, arg_atfd, arg_cstr, arg_atfd, arg_cstr, arg_),
#endif
#ifdef SYS_symlinkat
    SARGS(symlinkat, rdec, arg_atfd, arg_cstr, arg_cstr),
#endif
#ifdef SYS_readlinkat
    SARGS(readlinkat, rdec, arg_atfd, arg_cstr, arg_, arg_),
#endif
#ifdef SYS_fchmodat
    SARGS(fchmodat, rdec, arg_atfd, arg_cstr, arg_mode),
#endif
#ifdef SYS_faccessat
    SARGS(faccessat, rdec, arg_atfd, arg_cstr, arg_mode),
#endif
#ifdef SYS_pselect6
    SARGS(pselect6, rdec, arg_, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_ppoll
    SARGS(ppoll, rdec, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_unshare
    SARGS(unshare, rdec, arg_),
#endif
#ifdef SYS_set_robust_list
    SARGS(set_robust_list, rdec, arg_, arg_),
#endif
#ifdef SYS_get_robust_list
    SARGS(get_robust_list, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_splice
    SARGS(splice, rdec, arg_fd, arg_, arg_fd, arg_, arg_, arg_),
#endif
#ifdef SYS_tee
    SARGS(tee, rdec, arg_fd, arg_fd, arg_, arg_),
#endif
#ifdef SYS_sync_file_range
    SARGS(sync_file_range, rdec, arg_fd, arg_, arg_, arg_),
#endif
#ifdef SYS_vmsplice
    SARGS(vmsplice, rdec, arg_fd, arg_, arg_, arg_),
#endif
#ifdef SYS_move_pages
    SARGS(move_pages, rdec, arg_, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_utimensat
    SARGS(utimensat, rdec, arg_atfd, arg_cstr, arg_, arg_),
#endif
#ifdef SYS_epoll_pwait
    SARGS(epoll_pwait, rdec, arg_fd, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_signalfd
    SARGS(signalfd, rdec, arg_fd, arg_, arg_),
#endif
#ifdef SYS_timerfd_create
    SARGS(timerfd_create, rdec, arg_, arg_),
#endif
#ifdef SYS_eventfd
    SARGS(eventfd, rdec, arg_),
#endif
#ifdef SYS_fallocate
    SARGS(fallocate, rdec, arg_fd, arg_, arg_, arg_),
#endif
#ifdef SYS_timerfd_settime
    SARGS(timerfd_settime, rdec, arg_fd, arg_, arg_, arg_),
#endif
#ifdef SYS_timerfd_gettime
    SARGS(timerfd_gettime, rdec, arg_fd, arg_),
#endif
#ifdef SYS_accept4
    SARGS(accept4, rdec, arg_fd, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_signalfd4
    SARGS(signalfd4, rdec, arg_fd, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_eventfd2
    SARGS(eventfd2, rdec, arg_, arg_),
#endif
#ifdef SYS_epoll_create1
    SARGS(epoll_create1, rdec, arg_),
#endif
#ifdef SYS_dup3
    SARGS(dup3, rdec, arg_fd, arg_fd, arg_),
#endif
#ifdef SYS_pipe2
    SARGS(pipe2, rdec, arg_, arg_),
#endif
#ifdef SYS_inotify_init1
    SARGS(inotify_init1, rdec, arg_),
#endif
#ifdef SYS_preadv
    SARGS(preadv, rdec, arg_fd, arg_, arg_, arg_),
#endif
#ifdef SYS_pwritev
    SARGS(pwritev, rdec, arg_fd, arg_, arg_, arg_),
#endif
#ifdef SYS_rt_tgsigqueueinfo
    SARGS(rt_tgsigqueueinfo, rdec, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_perf_event_open
    SARGS(perf_event_open, rdec, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_recvmmsg
    SARGS(recvmmsg, rdec, arg_fd, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_fanotify_init
    SARGS(fanotify_init, rdec, arg_, arg_),
#endif
#ifdef SYS_fanotify_mark
    SARGS(fanotify_mark, rdec, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_prlimit64
    SARGS(prlimit64, rdec, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_name_to_handle_at
    SARGS(name_to_handle_at, rdec, arg_atfd, arg_cstr, arg_, arg_, arg_),
#endif
#ifdef SYS_open_by_handle_at
    SARGS(open_by_handle_at, rdec, arg_atfd, arg_cstr, arg_),
#endif
#ifdef SYS_clock_adjtime
    SARGS(clock_adjtime, rdec, arg_, arg_),
#endif
#ifdef SYS_syncfs
    SARGS(syncfs, rdec, arg_fd),
#endif
#ifdef SYS_sendmmsg
    SARGS(sendmmsg, rdec, arg_fd, arg_, arg_, arg_),
#endif
#ifdef SYS_setns
    SARGS(setns, rdec, arg_fd, arg_),
#endif
#ifdef SYS_getcpu
    SARGS(getcpu, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_process_vm_readv
    SARGS(process_vm_readv, rdec, arg_, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_process_vm_writev
    SARGS(process_vm_writev, rdec, arg_, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_kcmp
    SARGS(kcmp, rdec, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_finit_module
    SARGS(finit_module, rdec, arg_fd, arg_, arg_),
#endif
#ifdef SYS_sched_setattr
    SARGS(sched_setattr, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_sched_getattr
    SARGS(sched_getattr, rdec, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_renameat2
    SARGS(renameat2, rdec, arg_atfd, arg_cstr, arg_atfd, arg_cstr, arg_),
#endif
#ifdef SYS_seccomp
    SARGS(seccomp, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_getrandom
    SARGS(getrandom, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_memfd_create
    SARGS(memfd_create, rdec, arg_cstr, arg_),
#endif
#ifdef SYS_kexec_file_load
    SARGS(kexec_file_load, rdec, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_bpf
    SARGS(bpf, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_execveat
    SARGS(execveat, rdec, arg_atfd, arg_cstr, arg_, arg_, arg_),
#endif
#ifdef SYS_userfaultfd
    SARGS(userfaultfd, rdec, arg_),
#endif
#ifdef SYS_membarrier
    SARGS(membarrier, rdec, arg_, arg_),
#endif
#ifdef SYS_mlock2
    SARGS(mlock2, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_copy_file_range
    SARGS(copy_file_range, rdec, arg_fd, arg_, arg_fd, arg_, arg_, arg_),
#endif
#ifdef SYS_preadv2
    SARGS(preadv2, rdec, arg_fd, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_pwritev2
    SARGS(pwritev2, rdec, arg_fd, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_pkey_mprotect
    SARGS(pkey_mprotect, rdec, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_pkey_alloc
    SARGS(pkey_alloc, rdec, arg_, arg_),
#endif
#ifdef SYS_pkey_free
    SARGS(pkey_free, rdec, arg_),
#endif
};

#undef SARGS

static const struct syscall_desc open_without_mode = {
	.name = "open",
	.return_type = rdec,
	.args = {arg_cstr, arg_open_flags, }
};

static const struct syscall_desc openat_without_mode = {
	.name = "openat",
	.return_type = rdec,
	.args = {arg_atfd, arg_cstr, arg_open_flags, }
};

const struct syscall_desc *
get_syscall_desc(long syscall_number, const long args[6])
{
	if (syscall_number < 0)
		return NULL;

	if ((size_t)syscall_number >= (sizeof(table) / sizeof(table[0])))
		return NULL;
	
	if (syscall_number == SYS_openat && (args[1] & O_CREAT) == 0)
		return &open_without_mode;

	if (syscall_number == SYS_openat && (args[2] & O_CREAT) == 0)
		return &openat_without_mode;

	return table + syscall_number;
}
