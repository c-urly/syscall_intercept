#!/bin/bash  # Ensure it's running in Bash

# Check if the RISCV_TOOLCHAIN_PATH environment variable is set
if [ -z "$RISCV_TOOLCHAIN_PATH" ]; then
    echo "Error: RISCV_TOOLCHAIN_PATH is not set."
    exit 1
fi

# Define the path to the unistd.h file inside the sysroot directory
unistd_file="$RISCV_TOOLCHAIN_PATH/sysroot/usr/include/asm-generic/unistd.h"

# Define the path to the intercept.conf file
config_file="intercept.conf"

# Check if the file exists
if [ ! -f "$unistd_file" ]; then
    echo "Error: $unistd_file not found."
    exit 1
fi

# Declare an associative array (dictionary) for syscalls
declare -A syscall_dict

# Read the syscalls from the unistd.h file, process the grep and cut output, and fill the dictionary
while read -r syscall1 syscall2; do
    # Add the syscall1 and syscall2 to the dictionary if both are present
    if [ -n "$syscall1" ] && [ -n "$syscall2" ]; then
        syscall_dict["$syscall1"]="$syscall2"
    fi
done < <(grep -i '#define __NR' "$unistd_file" | cut -d " " -f 2,3)

# Function to resolve string values to their corresponding numeric or final values
resolve_syscall() {
    local key="$1"
    local value="${syscall_dict[$key]}"

    # Loop to resolve the value if it's a string referring to another syscall
    while echo "$value" | grep -q '^__NR'; do
        value="${syscall_dict[$value]}"
    done

    # Return the final resolved value
    echo "$value"
}

# Create or clear the intercept.conf file
> "$config_file"

# Iterate over each key in the dictionary and resolve all references
for key in "${!syscall_dict[@]}"; do
    # Ignore __NR3264_* syscalls in the final output
    if echo "$key" | grep -q '^__NR3264_'; then
        continue
    fi
    
    # Resolve the syscall value and prepare the final entry
    final_value=$(resolve_syscall "$key")
    
    if [ -n "$final_value" ];  then
        echo "SYS_${key//"__NR_"/}:$final_value" >> "$config_file"
    fi
done

echo "Configuration written to $config_file"

