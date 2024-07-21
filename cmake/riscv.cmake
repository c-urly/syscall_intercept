# riscv.cmake
# Usage: cmake -DCMAKE_TOOLCHAIN_FILE=path/to/riscv.cmake ..

# Define the RISC-V toolchain path
if(DEFINED ENV{RISCV_TOOLCHAIN_PATH})
    set(RISCV_TOOLCHAIN_PATH $ENV{RISCV_TOOLCHAIN_PATH})
else()
    message(FATAL_ERROR "RISCV_TOOLCHAIN_PATH is not set in the environment.")
endif()

# Set the system name and processor
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR riscv64)

# Define the compilers
set(CMAKE_C_COMPILER ${RISCV_TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER ${RISCV_TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-g++)
set(CMAKE_ASM_COMPILER ${RISCV_TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-gcc)

# Define the archiver, linker, and other tools
set(CMAKE_C_COMPILER ${RISCV_TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER ${RISCV_TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-g++)
set(CMAKE_AR ${RISCV_TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-ar)
# set(CMAKE_ASM_COMPILER ${RISCV_TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-as)
set(CMAKE_OBJCOPY ${RISCV_TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-objcopy)
set(CMAKE_OBJDUMP ${RISCV_TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-objdump)
set(CMAKE_STRIP ${RISCV_TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-strip)
set(CMAKE_LINKER ${RISCV_TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-ld)
set(CMAKE_ADDR2LINE ${RISCV_TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-addr2line)
set(CMAKE_NM ${RISCV_TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-nm)
set(CMAKE_READELF ${RISCV_TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-readelf)
set(CMAKE_RANLIB ${RISCV_TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-ranlib)
set(CMAKE_ELFEDIT ${RISCV_TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-elfedit)
set(CMAKE_GCOV ${RISCV_TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-gcov)
set(CMAKE_GDB ${RISCV_TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-gdb)
set(CMAKE_SIZE ${RISCV_TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-size)
set(CMAKE_STRINGS ${RISCV_TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-strings)

# Define the executable suffix
set(CMAKE_EXECUTABLE_SUFFIX ".elf")

# Set common build flags
set(CMAKE_C_FLAGS "-g -march=rv64imafdc_zicsr -mabi=lp64d")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}")
set(CMAKE_ASM_FLAGS "${CMAKE_C_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "-march=rv64imafdc_zicsr -mabi=lp64d -nostartfiles")

# Add any include directories if necessary
include_directories(${RISCV_TOOLCHAIN_PATH}/include)

# Add Capstone include and library directories
set(CAPSTONE_INSTALL_PATH /home/curly/installs/capstone)
set(CAPSTONE_INCLUDE_DIR ${CAPSTONE_INSTALL_PATH}/include/capstone)
set(CAPSTONE_LIBRARY_DIR ${CAPSTONE_INSTALL_PATH}/lib)

include_directories(${CAPSTONE_INCLUDE_DIR})
link_directories(${CAPSTONE_LIBRARY_DIR})

# Set pkg-config executable to the RISC-V version
set(PKG_CONFIG_EXECUTABLE ${RISCV_TOOLCHAIN_PATH}/bin/pkg-config)

# Add the RISC-V sysroot libraries and custom Capstone path
list(APPEND CMAKE_PREFIX_PATH ${RISCV_TOOLCHAIN_PATH}/sysroot/libs ${CAPSTONE_INSTALL_PATH})

# Export the necessary environment variables
set(ENV{PKG_CONFIG_PATH} "${CAPSTONE_INSTALL_PATH}/lib/pkgconfig:${RISCV_TOOLCHAIN_PATH}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
if(NOT DEFINED ENV{LD_LIBRARY_PATH} OR ENV{LD_LIBRARY_PATH} STREQUAL "")
    set(ENV{LD_LIBRARY_PATH} "${RISCV_TOOLCHAIN_PATH}/lib:${CAPSTONE_LIBRARY_DIR}")
else()
    set(ENV{LD_LIBRARY_PATH} "${RISCV_TOOLCHAIN_PATH}/lib:${CAPSTONE_LIBRARY_DIR}:$ENV{LD_LIBRARY_PATH}")
endif()
set(ENV{PKG_CONFIG} "${PKG_CONFIG_EXECUTABLE}")

message(STATUS "Using RISC-V toolchain at ${RISCV_TOOLCHAIN_PATH}")
message(STATUS "Capstone include directory: ${CAPSTONE_INCLUDE_DIR}")
message(STATUS "Capstone library directory: ${CAPSTONE_LIBRARY_DIR}")
message(STATUS "RISC-V library path: ${RISCV_TOOLCHAIN_PATH}/sysroot/libs")
message(STATUS "PKG_CONFIG_PATH: $ENV{PKG_CONFIG_PATH}")
message(STATUS "LD_LIBRARY_PATH: $ENV{LD_LIBRARY_PATH}")
message(STATUS "PKG_CONFIG: $ENV{PKG_CONFIG}")
message(STATUS "CMAKE_PREFIX_PATH: ${CMAKE_PREFIX_PATH}")

