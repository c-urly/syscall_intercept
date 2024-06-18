## Changes for RISC-V

The work to port to RISC-V will be divided into four parts:

- **Modifying the logic for identifying syscalls in the RISC-V binary.**
- **Creating wrappers to jump from the syscall location, and modifying the intercept wrapper and template assembly files.**
- **Overwriting the syscall and NOP regions with jump and trampoline jumps to redirect the flow to patch wrappers.**
- **Updating the CMake build system for RISC-V.**

---