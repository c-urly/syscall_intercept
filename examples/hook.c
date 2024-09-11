#include "libsyscall_intercept_hook_point.h"
#include <syscall.h>
#include <errno.h>
#include <stdio.h>


// Manual implementation of strlen
int my_strlen(const char *str) {
    int length = 0;
    while (str[length] != '\0') {
        length++;
    }
    return length;
}

// Manual implementation of memcpy
void my_memcpy(char *dest, const char *src, int len) {
    for (int i = 0; i < len; i++) {
        dest[i] = src[i];
    }
}

// Function to log a message using syscall_no_intercept
void log_syscall(int log_fd, const char *message) {
    int msg_len = my_strlen(message);
    syscall_no_intercept(SYS_write, log_fd, message, msg_len);
}

// Add a string to the log buffer
void add_to_log(char *log_message, int *log_length, const char *msg) {
    int msg_len = my_strlen(msg);
    if (*log_length + msg_len < 256) {  // Assuming log_message buffer size is 256
        my_memcpy(&log_message[*log_length], msg, msg_len);
        *log_length += msg_len;
    }
}

// Reset the log_message buffer after logging
void reset_log_message(char *log_message, int *log_length) {
    *log_length = 0;
    for (int i = 0; i < 256; i++) {
        log_message[i] = '\0';  // Clear the buffer
    }
}

static int hook(long syscall_number,
                long arg0, long arg1,
                long arg2, long arg3,
                long arg4, long arg5,
                long *result)
{
    char log_message[256];    // Buffer to store log messages
    int log_fd = 1;           // File descriptor for logging, e.g., STDOUT (1)
    int log_length = 0;       // Length of the message to be logged

    // Perform the system call interception
    switch (syscall_number) {
        case SYS_getdents64:
            reset_log_message(log_message, &log_length);
            add_to_log(log_message, &log_length, "Intercepted SYS_getdents64\n");
            log_syscall(log_fd, log_message);
            break;
        case SYS_fsopen:
            reset_log_message(log_message, &log_length);
            add_to_log(log_message, &log_length, "Intercepted SYS_fsopen\n");
            log_syscall(log_fd, log_message);
            break;
        case SYS_read:
            reset_log_message(log_message, &log_length);
            add_to_log(log_message, &log_length, "Intercepted SYS_read\n");
            log_syscall(log_fd, log_message);
            break;
        case SYS_write: {
            char buffer[0x1000];
            size_t size = (size_t)arg2;

            if (size > sizeof(buffer)) {
                size = sizeof(buffer);
            }

            // Manually copy data from arg1 to buffer
            for (size_t i = 0; i < size; i++) {
                buffer[i] = ((char *)arg1)[i];
            }

            // Manually compare the first part of the buffer to "Hello from "
            int match = 1;
            const char *hello = "Hello from ";
            for (int i = 0; i < 11; i++) {
                if (buffer[i] != hello[i]) {
                    match = 0;
                    break;
                }
            }

            if (match) {
                const char *interceptStr = "Intercepted ";
                int interceptStrLen = my_strlen(interceptStr);
                int remainingSize = size - 11;

                // Check if the buffer has enough space for the intercepted string
                if (size + interceptStrLen < sizeof(buffer)) {
                    // Shift the rest of the buffer to the right
                    for (int i = size - 1; i >= 11; i--) {
                        buffer[i + interceptStrLen] = buffer[i];
                    }

                    // Insert "Intercepted " after "Hello from "
                    for (int i = 0; i < interceptStrLen; i++) {
                        buffer[11 + i] = interceptStr[i];
                    }

                    size += interceptStrLen;
                }
                *result = syscall_no_intercept(SYS_write, arg0, buffer, size);
                return 0;
            }

            // Log the intercepted SYS_write call
            reset_log_message(log_message, &log_length);
            add_to_log(log_message, &log_length, "Intercepted SYS_write\n");
            log_syscall(log_fd, log_message);           
            break;
        }
        case SYS_close:
            reset_log_message(log_message, &log_length);
            add_to_log(log_message, &log_length, "Intercepted SYS_close\n");
            log_syscall(log_fd, log_message);
            break;
        case SYS_clone:
            reset_log_message(log_message, &log_length);
            add_to_log(log_message, &log_length, "Intercepted SYS_clone\n");
            log_syscall(log_fd, log_message);
            break;
        case SYS_execve:
            reset_log_message(log_message, &log_length);
            add_to_log(log_message, &log_length, "Intercepted SYS_execve\n");
            log_syscall(log_fd, log_message);
            break;
        case SYS_wait4:
            reset_log_message(log_message, &log_length);
            add_to_log(log_message, &log_length, "Intercepted SYS_wait4\n");
            log_syscall(log_fd, log_message);
            break;
        case SYS_getpid:
            reset_log_message(log_message, &log_length);
            add_to_log(log_message, &log_length, "Intercepted SYS_getpid\n");
            log_syscall(log_fd, log_message);
            break;
        case SYS_kill:
            reset_log_message(log_message, &log_length);
            add_to_log(log_message, &log_length, "Intercepted SYS_kill\n");
            log_syscall(log_fd, log_message);
            break;
        case SYS_mmap:
            reset_log_message(log_message, &log_length);
            add_to_log(log_message, &log_length, "Intercepted SYS_mmap\n");
            log_syscall(log_fd, log_message);
            break;
        case SYS_munmap:
            reset_log_message(log_message, &log_length);
            add_to_log(log_message, &log_length, "Intercepted SYS_munmap\n");
            log_syscall(log_fd, log_message);
            break;
        case SYS_socket:
            reset_log_message(log_message, &log_length);
            add_to_log(log_message, &log_length, "Intercepted SYS_socket\n");
            log_syscall(log_fd, log_message);
            break;
        case SYS_bind:
            reset_log_message(log_message, &log_length);
            add_to_log(log_message, &log_length, "Intercepted SYS_bind\n");
            log_syscall(log_fd, log_message);
            break;
        case SYS_listen:
            reset_log_message(log_message, &log_length);
            add_to_log(log_message, &log_length, "Intercepted SYS_listen\n");
            log_syscall(log_fd, log_message);
            break;
        case SYS_accept:
            reset_log_message(log_message, &log_length);
            add_to_log(log_message, &log_length, "Intercepted SYS_accept\n");
            log_syscall(log_fd, log_message);
            break;
        case SYS_openat:
            reset_log_message(log_message, &log_length);
            add_to_log(log_message, &log_length, "Intercepted SYS_open\n");
            log_syscall(log_fd, log_message);
            break;
        default:
            return 1; // Pass other syscalls to the kernel
    }

    return 1;
}



static __attribute__((constructor)) void
init(void)
{
	// Set up the callback function
	intercept_hook_point = &hook;
    // intercept_hook_point_clone_child = child_hook;
}

