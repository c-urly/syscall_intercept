```markdown
# Syscall Intercept Library for RISC-V

This repository provides a userspace library for intercepting system calls in a RISC-V environment. It is built using the libcapstone disassembly engine.

## Dependencies

### Runtime Dependencies
- **libcapstone**: A disassembly engine used under the hood.

### Build Dependencies
- **RISC-V toolchain**: Includes GCC and Clang.
- **QEMU**: For running RISC-V binaries.
- **riscv-gdb**: For debugging.
- **cmake**
- **perl**: For coding style checks.
- **pandoc**: For generating the man page.
- **GITHUB_REPO**: Repository on GitHub for x86 versions (e.g., `pmem/syscall_intercept`).

## Installation

Follow these steps to install the necessary dependencies and build the syscall_intercept library:

### Step 1: Install the RISC-V Toolchain

Clone and build the RISC-V GNU toolchain:

```bash
git clone https://github.com/riscv/riscv-gnu-toolchain
cd riscv-gnu-toolchain
./configure --prefix=/path/to/install/riscv-toolchain
make linux
export RISCV_TOOLCHAIN_PATH=/path/to/install/riscv-toolchain
export PATH=$RISCV_TOOLCHAIN_PATH/bin:$PATH
```

### Step 2: Install QEMU for RISC-V

```bash
git clone https://gitlab.com/qemu-project/qemu.git
cd qemu
./configure --target-list=riscv64-softmmu,riscv64-linux-user
make -j$(nproc)
sudo make install
```

### Step 3: Build and Install GDB

```bash
cd riscv-gnu-toolchain
./configure --prefix=/path/to/install/riscv-toolchain --enable-gdb
make gdb
```

### Step 4: Install libcapstone

```bash
git clone https://github.com/aquynh/capstone
cd capstone
make
sudo make install
```

### Step 5: Install Additional Tools

```bash
sudo apt-get install cmake perl pandoc
```

### Step 6: Build and Install syscall_intercept

Configure and build the library:

```bash
export RISCV_TOOLCHAIN_PATH=/path/to/install/riscv-toolchain
export PATH=$RISCV_TOOLCHAIN_PATH/bin:$PATH

cmake /path/to/your/project/syscall_intercept \
    -DCMAKE_INSTALL_PREFIX=/path/to/your/project/syscall_intercept/build/install \
    -DCMAKE_TOOLCHAIN_FILE=/path/to/your/project/syscall_intercept/cmake/riscv.cmake \
    -DCMAKE_BUILD_TYPE=Release
make
sudo make install
```

### Step 7: Compile and Run the Example

Compile the example and run it using QEMU with environment setup:

```bash
cd /path/to/your/project/syscall_intercept/src/example
riscv64-unknown-linux-gnu-gcc example.c -lsyscall_intercept -fpic -shared -o example_riscv.so

qemu-riscv64 \
    -E LD_PRELOAD=/path/to/your/project/syscall_intercept/src/example/example_riscv.so \
    -E LD_LIBRARY_PATH=/path/to/install/riscv-toolchain/sysroot/lib:/path/to/install/riscv-toolchain/sysroot/usr/lib:$LD_LIBRARY_PATH \
    -L /path/to/install/riscv-toolchain/sysroot \
    ./app_riscv64
```

## Example: Syscall Hook

Below is a simple example of creating a syscall hook in `example_riscv.so`:

```c
#include <libsyscall_intercept_hook_point.h>
#include <syscall.h>
#include <errno.h>

static int hook(long syscall_number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long *result) {
    if (syscall_number == SYS_getdents) {
        *result = -ENOTSUP;
        return 0; // Block the syscall
    }
    return 1; // Pass other syscalls to the kernel
}

static __attribute__((constructor)) void init(void) {
    intercept_hook_point = hook;
}
```

Compile this code using the RISC-V toolchain and run it with QEMU as shown in Step 7.

```