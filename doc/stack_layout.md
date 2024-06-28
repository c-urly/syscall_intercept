# Registers in RISCV


This table should cover the general-purpose registers, floating-point registers, and vector registers in RISC-V, including their ABI names, corresponding hardware registers, descriptions, and whether they are callee-saved or caller-saved.

### RISC-V Register Table

| ABI Name | Hardware Register | Description                              | Saved By     |
|----------|-------------------|------------------------------------------|--------------|
| `zero`   | `x0`              | Hard-wired zero                          | -            |
| `ra`     | `x1`              | Return address                           | Caller       |
| `sp`     | `x2`              | Stack pointer                            | Callee       |
| `gp`     | `x3`              | Global pointer                           | -            |
| `tp`     | `x4`              | Thread pointer                           | -            |
| `t0`     | `x5`              | Temporary                                | Caller       |
| `t1`     | `x6`              | Temporary                                | Caller       |
| `t2`     | `x7`              | Temporary                                | Caller       |
| `s0`/`fp`| `x8`              | Saved register/frame pointer             | Callee       |
| `s1`     | `x9`              | Saved register                           | Callee       |
| `a0`     | `x10`             | Function argument/return value           | Caller       |
| `a1`     | `x11`             | Function argument/return value           | Caller       |
| `a2`     | `x12`             | Function argument                        | Caller       |
| `a3`     | `x13`             | Function argument                        | Caller       |
| `a4`     | `x14`             | Function argument                        | Caller       |
| `a5`     | `x15`             | Function argument                        | Caller       |
| `a6`     | `x16`             | Function argument                        | Caller       |
| `a7`     | `x17`             | Function argument                        | Caller       |
| `s2`     | `x18`             | Saved register                           | Callee       |
| `s3`     | `x19`             | Saved register                           | Callee       |
| `s4`     | `x20`             | Saved register                           | Callee       |
| `s5`     | `x21`             | Saved register                           | Callee       |
| `s6`     | `x22`             | Saved register                           | Callee       |
| `s7`     | `x23`             | Saved register                           | Callee       |
| `s8`     | `x24`             | Saved register                           | Callee       |
| `s9`     | `x25`             | Saved register                           | Callee       |
| `s10`    | `x26`             | Saved register                           | Callee       |
| `s11`    | `x27`             | Saved register                           | Callee       |
| `t3`     | `x28`             | Temporary                                | Caller       |
| `t4`     | `x29`             | Temporary                                | Caller       |
| `t5`     | `x30`             | Temporary                                | Caller       |
| `t6`     | `x31`             | Temporary                                | Caller       |

### Floating-Point Registers

| ABI Name | Hardware Register | Description                              | Saved By     |
|----------|-------------------|------------------------------------------|--------------|
| `ft0`    | `f0`              | Floating-point temporary                 | Caller       |
| `ft1`    | `f1`              | Floating-point temporary                 | Caller       |
| `ft2`    | `f2`              | Floating-point temporary                 | Caller       |
| `ft3`    | `f3`              | Floating-point temporary                 | Caller       |
| `ft4`    | `f4`              | Floating-point temporary                 | Caller       |
| `ft5`    | `f5`              | Floating-point temporary                 | Caller       |
| `ft6`    | `f6`              | Floating-point temporary                 | Caller       |
| `ft7`    | `f7`              | Floating-point temporary                 | Caller       |
| `fs0`    | `f8`              | Floating-point saved                     | Callee       |
| `fs1`    | `f9`              | Floating-point saved                     | Callee       |
| `fa0`    | `f10`             | Floating-point argument/return value     | Caller       |
| `fa1`    | `f11`             | Floating-point argument/return value     | Caller       |
| `fa2`    | `f12`             | Floating-point argument                  | Caller       |
| `fa3`    | `f13`             | Floating-point argument                  | Caller       |
| `fa4`    | `f14`             | Floating-point argument                  | Caller       |
| `fa5`    | `f15`             | Floating-point argument                  | Caller       |
| `fa6`    | `f16`             | Floating-point argument                  | Caller       |
| `fa7`    | `f17`             | Floating-point argument                  | Caller       |
| `fs2`    | `f18`             | Floating-point saved                     | Callee       |
| `fs3`    | `f19`             | Floating-point saved                     | Callee       |
| `fs4`    | `f20`             | Floating-point saved                     | Callee       |
| `fs5`    | `f21`             | Floating-point saved                     | Callee       |
| `fs6`    | `f22`             | Floating-point saved                     | Callee       |
| `fs7`    | `f23`             | Floating-point saved                     | Callee       |
| `fs8`    | `f24`             | Floating-point saved                     | Callee       |
| `fs9`    | `f25`             | Floating-point saved                     | Callee       |
| `fs10`   | `f26`             | Floating-point saved                     | Callee       |
| `fs11`   | `f27`             | Floating-point saved                     | Callee       |
| `ft8`    | `f28`             | Floating-point temporary                 | Caller       |
| `ft9`    | `f29`             | Floating-point temporary                 | Caller       |
| `ft10`   | `f30`             | Floating-point temporary                 | Caller       |
| `ft11`   | `f31`             | Floating-point temporary                 | Caller       |


### Vector Registers

| ABI Name | Hardware Register | Description         | Saved By |
|----------|-------------------|---------------------|----------|
| `v0`     | `v0`              | Vector register     | Caller   |
| `v1`     | `v1`              | Vector register     | Caller   |
| `v2`     | `v2`              | Vector register     | Caller   |
| `v3`     | `v3`              | Vector register     | Caller   |
| `v4`     | `v4`              | Vector register     | Caller   |
| `v5`     | `v5`              | Vector register     | Caller   |
| `v6`     | `v6`              | Vector register     | Caller   |
| `v7`     | `v7`              | Vector register     | Caller   |
| `v8`     | `v8`              | Vector register     | Caller   |
| `v9`     | `v9`              | Vector register     | Caller   |
| `v10`    | `v10`             | Vector register     | Caller   |
| `v11`    | `v11`             | Vector register     | Caller   |
| `v12`    | `v12`             | Vector register     | Caller   |
| `v13`    | `v13`             | Vector register     | Caller   |
| `v14`    | `v14`             | Vector register     | Caller   |
| `v15`    | `v15`             | Vector register     | Caller   |
| `v16`    | `v16`             | Vector register     | Caller   |
| `v17`    | `v17`             | Vector register     | Caller   |
| `v18`    | `v18`             | Vector register     | Caller   |
| `v19`    | `v19`             | Vector register     | Caller   |
| `v20`    | `v20`             | Vector register     | Caller   |
| `v21`    | `v21`             | Vector register     | Caller   |
| `v22`    | `v22`             | Vector register     | Caller   |
| `v23`    | `v23`             | Vector register     | Caller   |
| `v24`    | `v24`             | Vector register     | Caller   |
| `v25`    | `v25`             | Vector register     | Caller   |
| `v26`    | `v26`             | Vector register     | Caller   |
| `v27`    | `v27`             | Vector register     | Caller   |
| `v28`    | `v28`             | Vector register     | Caller   |
| `v29`    | `v29`             | Vector register     | Caller   |
| `v30`    | `v30`             | Vector register     | Caller   |
| `v31`    | `v31`             | Vector register     | Caller   |


Before calling the intercept routine in `intercept_wrapper.s`, we need to preserve the stack and save the following registers to ensure their values are not altered during the syscall interception:

- Caller-saved registers (since intercept_wrapper is the caller to another function(intercept_routine)):

    t0 to t6 (x5 to x7, x28 to x31),
    a0 to a7 (x10 to x17),
    ra (x1)

- Callee-saved registers (if intercept_wrapper modifies them and needs to preserve the caller's context):

    s0 to s11 (x8 to x9, x18 to x27)

- Stack pointer and other essential registers:

    sp (if it needs to be manipulated within intercept_wrapper)

- Floating-point registers if they are used:

    Caller-saved: ft0 to ft11 (f0 to f7, f28 to f31),
    Callee-saved: fs0 to fs11 (f8 to f27)

- Vector registers if they are used:
    v0 to v31 (caller-saved by convention)

