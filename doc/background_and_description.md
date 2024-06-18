# Syscall Intercept for RISC-V
**Author:** Rishikesh Bhatt

## Abstract
Syscall Intercept libraries for x86 systems offer an advanced mechanism for safely intercepting system calls, surpassing the capabilities of traditional library interception methods like LD\_PRELOAD. Originally developed by Intel for x86 architectures, these libraries play a crucial role in various adhoc file systems, such as DAOS, and GekkoFS. Although the community has made significant efforts to port these libraries to ARM and PowerPC architectures, there remains a need for a similar port for the RISC-V architecture. This work is essential to extend the benefits of syscall interception to a broader range of hardware platforms(particularly RISC-V).

## Introduction

In the realm of software and operating system development, robust debugging capabilities are paramount. Effective debugging tools are indispensable for identifying and rectifying bugs, optimizing performance, and ensuring system stability. Among the various techniques employed, function and library interception, as well as tracing mechanisms like **ptrace** and **strace**, play a critical role. These tools provide deep insights into program execution, enabling developers to monitor system calls, signal handling, and process state changes in real-time. Function and library interception allow developers to override or augment the behavior of functions within an application or shared library. This is particularly useful for logging, performance profiling, and applying patches or workarounds without modifying the source code. Techniques such as LD\_PRELOAD on Unix-like systems enable the substitution of specific library functions, facilitating dynamic analysis and manipulation of application behavior.

**ptrace**, a system call available on Unix-like operating systems, provides a powerful interface for a process to observe and control the execution of another process. It is the backbone of many debugging tools, including the GNU Debugger (GDB). Through **ptrace**, developers can set breakpoints, step through code, inspect memory and registers, and modify execution flow. This capability is invaluable for both user-space and kernel-space debugging, offering granular control over program execution. Similarly, **strace** is a diagnostic tool that intercepts and records all system calls made by a process. By providing a detailed log of system interactions, **strace** helps developers understand how applications communicate with the operating system, diagnose errors, and optimize system call usage. In the context of Internet of Things (IoT) and embedded systems, these tracing and interception mechanisms are equally critical. IoT devices often operate under resource constraints and interact closely with hardware and low-level system components. Tools like **ptrace** and **strace** enable developers to monitor system calls, diagnose hardware interactions, and ensure the reliability of embedded software.

In this work, we focus on syscall interception for the RISC-V architecture. This effort aims to extend the capabilities of existing debugging and monitoring tools to RISC-V, providing the same level of insight and control that developers currently enjoy on x86.


## Motivation and Related Work

Interception mechanisms like **strace**, **ptrace**, and similar tools are invaluable for software and system development. **strace** is a diagnostic utility in Unix-like operating systems that intercepts and logs all the system calls made by a process, providing detailed insights into the interactions between user programs and the kernel. By capturing system call arguments and return values, **strace** helps developers understand application behavior, diagnose issues, and optimize system call usage.

**ptrace**, on the other hand, is a system call that allows one process to observe and control the execution of another process. It is the foundation of many debugging tools, such as GDB. **ptrace** provides comprehensive control, including setting breakpoints, single-stepping through instructions, inspecting and modifying memory and registers, and intercepting system calls. This makes **ptrace** a versatile tool for debugging, reverse engineering, and security auditing. Other interception mechanisms include dynamic binary instrumentation tools like Valgrind and Intel's Pin, which allow developers to insert custom analysis code into a running application. These tools enable advanced profiling, performance monitoring, and memory checking, providing deep insights into program execution.

### Limitations of Current Interception Methods

Current interception methods like **ptrace** and **strace** have limitations that syscall interception can address. **ptrace**, while powerful, introduces significant performance overhead due to context switching between the tracer and tracee processes. It also requires explicit control over the tracee, which might not be feasible in all scenarios. **strace**, although lightweight compared to **ptrace**, is primarily a logging tool and does not allow for the modification of system calls.

### The Need for Syscall Interception

Syscall interception involves capturing and potentially modifying system calls directly at the kernel level before they are executed. This method allows for precise control over the system calls, enabling functionalities like security enforcement, syscall-level profiling, and syscall emulation. Syscall interception is particularly useful in scenarios where low-level system interactions need to be controlled or monitored without the overhead of a full debugging session. For example, **in security applications, syscall interception can enforce access control policies by blocking unauthorized system calls.** In performance profiling, it can provide detailed metrics on syscall usage with minimal performance impact. Additionally, syscall emulation can facilitate compatibility layers for running software designed for different operating systems or architectures.

In this work, we focus on implementing syscall interception for the RISC-V architecture, extending these advanced capabilities to a growing and important platform. By addressing the limitations of current interception methods, we aim to provide a versatile and efficient tool for developers and system administrators working with RISC-V systems.

## Methodology

The system call intercepting library provides a low-level interface for hooking Linux system calls in user space. This is achieved by hotpatching the machine code of the standard C library in the memory of a process. The user of this library can provide the functionality of almost any syscall in user space, using the very simple API specified in the `libsyscall_intercept_hook_point.h` header file:

```c
int (*intercept_hook_point)(long syscall_number,
            long arg0, long arg1,
            long arg2, long arg3,
            long arg4, long arg5,
            long *result);
```

### Syscall library in x86

The `__attribute__((constructor))` directive ensures that the intercept function runs before the main function. The intercept function is used to find the syscall and create patches to trap the syscall by overwriting the syscall with a jump and overwriting the nops (if available) in the padding area with trampoline jumps to the patch.

```c
static __attribute__((constructor)) void
intercept(int argc, char **argv)
{
    (void) argc;
    cmdline = argv[0];

    if (!syscall_hook_in_process_allowed())
        return;

    vdso_addr = (void *)(uintptr_t)getauxval(AT_SYSINFO_EHDR);
    debug_dumps_on = getenv("INTERCEPT_DEBUG_DUMP") != NULL;
    patch_all_objs = (getenv("INTERCEPT_ALL_OBJS") != NULL);
    intercept_setup_log(getenv("INTERCEPT_LOG"),
            getenv("INTERCEPT_LOG_TRUNC"));
    log_header();
    init_patcher();

    dl_iterate_phdr(analyze_object, NULL);
    if (!libc_found)
        xabort("libc not found");

    for (unsigned i = 0; i < objs_count; ++i) {
        if (objs[i].count > 0 && is_asm_wrapper_space_full())
            xabort("not enough space in asm_wrapper_space");
        allocate_trampoline_table(objs + i);
        create_patch_wrappers(objs + i, &next_asm_wrapper_space);
    }
    mprotect_asm_wrappers();
    for (unsigned i = 0; i < objs_count; ++i)
        activate_patches(objs + i);
}
```

The intercept function initializes the necessary structures and prepares the environment for syscall interception. It performs several tasks:

- **init_patcher**: Initializes the address and size of the patch wrapper template.
- **dl_iterate_phdr**: Iterates over all the library objects and calls the `analyze_object` function on each library object.
- **analyze_object**: Initializes the `patch_desc` struct for each shared library object, checks if the object should be patched, identifies the location of syscalls, and finds overwritable nops (nops in padded area ≥ 7-byte size) and other instructions around the syscall that can be overwritten.
- **create_patch_wrappers**: Prepares the jumping and returning logic (back to libc) to the actual assembly wrappers, deciding whether to use nop trampolines or to overwrite surrounding instructions if padding is not available.
- **create_wrappers**: Creates the assembly wrapper and copies the template to `intercept_template.s`. If replacing surrounding instructions for a jump to this wrapper, relocates all used surrounding instructions in this patch. Adds the return jump to the patch, which jumps back to libc from where the syscall is called.
- **activate_patches**: Actually overwrites the syscall and nops with jump instructions and gives RWX permission to the page.

The patches contain the hook function, which is a user-defined function that runs once a trapped syscall (from libc and libpthread) is called. By setting up these patches, the library effectively intercepts syscalls and allows custom handling within user space.
