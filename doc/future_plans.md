# Changes to Port to RISC-V

Lets outline the steps required to port the library to the RISC-V architecture. Key tasks include modifying initialization routines, adapting syscall analysis, creating assembly wrappers, redirecting syscalls, and updating the build system. Each step ensures compatibility with RISC-V’s unique instruction set and architecture, facilitating the correct interception and handling of syscalls.




### **1. Modify `init_patcher` to Initialize Wrapper Assembly Labels**

- **Objective:** Adapt the initialization process to support RISC-V.
- **Tasks:**
  - Modify `init_patcher` to correctly initialize the assembly wrapper labels for RISC-V.

### **2. Iterate POSIX Headers Using `dl_iterate_phdr`**

- **Objective:** Use `dl_iterate_phdr` to iterate over POSIX headers and call `analyze_object`.
- **Tasks:**
  - Ensure `analyze_object` is invoked correctly to handle RISC-V objects.

### **3. Modify `analyze_object` for RISC-V**

- **Objective:** Update `analyze_object` to support RISC-V specific operations.
- **Tasks:**
  - **`find_syscalls` Function:**
    - Implement RISC-V-specific logic to allocate jump and NOP tables.
    - Identify jumps and NOPs in the section and reallocation tables.
  - **`syscall_no_intercept` Function:**
    - Create a RISC-V version for no intercept syscall in utils.S and also change logic to check for vector registers.
  - **`crawl_text` Function:**
    - Crawl `.text` sections to locate RISC-V control flow instructions using Capstone.
    - Mark jump and NOP instructions accordingly.
  - **`disasm_wrapper.c`:**
    - Modify to identify and mark RISC-V instructions.

### **4. Allocate Memory Near `.text` for Trampoline Table**

- **Objective:** Allocate memory for the trampoline table close to the `.text` section.
- **Tasks:**
  - Confirm memory allocation for trampolines in RISC-V, noting that jump size should not be an issue due to register usage.

### **5. Create Wrappers for Syscall Redirection**

- **Objective:** Create wrappers to redirect control flow from syscall locations to the patch wrappers.
- **Tasks:**
  - **`patcher.c`:**
    - Update logic to handle RISC-V’s 4-byte instructions or 2-byte compressed instructions.
    - Modify code to mark syscall instructions and create jumps to trampolines.
    - Utilize NOPs from padding areas for trampoline space.
  - **Assembly Wrappers:**
    - Convert `intercept_wrapper` and `intercept_template` to RISC-V.
    - Adjust for RISC-V-specific register saving before calling hooks.
    - Confirm any status registers that need saving.

### **6. Overwrite Syscall and NOP Regions**

- **Objective:** Redirect control flow to patch wrappers by overwriting syscall and NOP regions.
- **Tasks:**
  - **`activate_patch`:**
    - Adapt logic to bypass instruction replacement.
    - Implement RISC-V-specific changes in `mprotect_no_intercept`.

### **7. Update CMake Build System for RISC-V**

- **Objective:** Ensure the build system supports RISC-V compilation.
- **Tasks:**
  - **CMake Configuration:**
    - Update `CMakeLists.txt` to include RISC-V specific tools.
    - Compile files and dependencies for RISC-V during each deliverable.


# RISC-V Control Flow Instructions

### Summary of RISC-V Control Flow Instructions

| Instruction | Description |
|-------------|-------------|
| **Unconditional Jump** |
| `jal`       | Jump and link (saves return address). |
| `jalr`      | Jump and link register (jumps to address in register plus offset). |
| **Conditional Branch** |
| `beq`       | Branch if equal. |
| `bne`       | Branch if not equal. |
| `blt`       | Branch if less than (signed). |
| `bge`       | Branch if greater or equal (signed). |
| `bltu`      | Branch if less than (unsigned). |
| `bgeu`      | Branch if greater or equal (unsigned). |
| **Function Call and Return** |
| `jal`       | Function call (jump and save return address). |
| `jalr`      | Indirect function call. |
| `ret`       | Return from function (jump to return address). |
| **Compressed (RVC)** |
| `c.j`       | Compressed jump. |
| `c.jal`     | Compressed jump and link. |
| `c.jr`      | Compressed jump register. |
| `c.jalr`    | Compressed jump and link register. |
| `c.beqz`    | Compressed branch if equal to zero. |
| `c.bnez`    | Compressed branch if not equal to zero. |

