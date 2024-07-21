/*
 * Copyright 2016-2017, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer
 *       in the documentation and/or other materials provided with the
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

/*
 * intercept_wrapper.S -- see asm_wrapper.md
 */

/* the function in this file */
.globl intercept_wrapper
.hidden intercept_wrapper
.type intercept_wrapper, @function

/* the C function in intercept.c */
.globl intercept_routine
.hidden intercept_routine
.type intercept_routine, @function

/* the other C function in intercept.c, called right after cloning a thread */
.globl intercept_routine_post_clone
.hidden intercept_routine_post_clone
.type intercept_routine_post_clone, @function

/* The boolean indicating whether YMM registers must be saved */
.globl intercept_wrapper_must_save_simd
.hidden intercept_wrapper_must_save_simd

.text

/*
 * Local stack layout:
 *
 * 0x448(sp)  -- return address, to the generated asm wrapper
 * Arguments received on stack:
 * 0x450(sp)  -- original value of sp
 * 0x458(sp)  -- pointer to a struct patch_desc instance
 * Locals on stack:
 * 0x78(sp) - 0x160(sp)  -- saved GPRs
 * 0x200(sp) - 0x400(sp) -- saved SIMD registers
 *
 * A pointer to these saved registers is passed to intercept_routine, so the
 * layout of `struct context` must match this part of the stack layout.
 *
 * Other arguments:
 * a0  -- which C function to call
 */
intercept_wrapper:
    .cfi_startproc

    /*
     * Stack size used locally: 0x448 bytes.
     *
     * This size assumes the stack pointer was correctly aligned before
     * executing the call instruction calling this function. The return
     * address pushed to the stack uses 8 bytes. This gives the equation:
     *
     * new_sp = original_sp - 8 - 0x448 == original_sp - 0x450
     * The number 0x450 is a multiple of 16, so the stack is still correctly
     * aligned. It is very easy to forget about this when making changes to this
     * code.
     */
    addi        sp, sp, -0x448
    .cfi_def_cfa_offset 0x0

    /* Save all GPRs on the stack */
    sd          ra, 0x160(sp)
    .cfi_offset 1, 0x160
    sd          t0, 0x158(sp)
    .cfi_offset 6, 0x158
    sd          t1, 0x150(sp)
    .cfi_offset 7, 0x150
    sd          t2, 0x148(sp)
    .cfi_offset 8, 0x148
    sd          t3, 0x140(sp)
    .cfi_offset 28, 0x140
    sd          t4, 0x138(sp)
    .cfi_offset 29, 0x138
    sd          t5, 0x130(sp)
    .cfi_offset 30, 0x130
    sd          t6, 0x128(sp)
    .cfi_offset 31, 0x128
    sd          s0, 0x120(sp)
    .cfi_offset 2, 0x120
    sd          s1, 0x118(sp)
    .cfi_offset 3, 0x118
    sd          a0, 0x110(sp)
    .cfi_offset 10, 0x110
    sd          a1, 0x108(sp)
    .cfi_offset 11, 0x108
    sd          a2, 0x100(sp)
    .cfi_offset 12, 0x100
    sd          a3, 0xf8(sp)
    .cfi_offset 13, 0xf8
    sd          a4, 0xf0(sp)
    .cfi_offset 14, 0xf0
    sd          a5, 0xe8(sp)
    .cfi_offset 15, 0xe8
    sd          a6, 0xe0(sp)
    .cfi_offset 16, 0xe0
    sd          a7, 0xd8(sp)
    .cfi_offset 17, 0xd8
    sd          s2, 0xd0(sp)
    .cfi_offset 18, 0xd0
    sd          s3, 0xc8(sp)
    .cfi_offset 19, 0xc8
    sd          s4, 0xc0(sp)
    .cfi_offset 20, 0xc0
    sd          s5, 0xb8(sp)
    .cfi_offset 21, 0xb8
    sd          s6, 0xb0(sp)
    .cfi_offset 22, 0xb0
    sd          s7, 0xa8(sp)
    .cfi_offset 23, 0xa8
    sd          s8, 0xa0(sp)
    .cfi_offset 24, 0xa0
    sd          s9, 0x98(sp)
    .cfi_offset 25, 0x98
    sd          s10, 0x90(sp)
    .cfi_offset 26, 0x90
    sd          s11, 0x88(sp)
    .cfi_offset 27, 0x88

    ld          t3, 0x450(sp)    /* fetch original value of sp */
    sd          t3, 0x80(sp)
    .cfi_offset 5, 0x80
    ld          t4, 0x458(sp)    /* fetch pointer to patch_desc */
    sd          t4, 0x78(sp)
    ld          t4, (t4)         /* fetch original value of pc */
    sd          t4, 0x70(sp)
    .cfi_offset 22, 0x70

    lb          t5, intercept_wrapper_must_save_simd
    beqz        t5, 0f

#ifdef HAS_RISCV_VECTOR

    /*
     * Save the SIMD registers.
     * Use vle.v and vse.v. These do not require alignment.
     */
    vsetvli     t6, zero, e32, m8
    vse.v       v0, 0x3c0(sp)
    vse.v       v1, 0x380(sp)
    vse.v       v2, 0x340(sp)
    vse.v       v3, 0x300(sp)
    vse.v       v4, 0x2c0(sp)
    vse.v       v5, 0x280(sp)
    vse.v       v6, 0x240(sp)
    vse.v       v7, 0x200(sp)
    j           1f

#endif

0:
    /* Save the Floating point registers. */
    fsw         ft0, 0x3c0(sp)
    fsw         ft1, 0x380(sp)
    fsw         ft2, 0x340(sp)
    fsw         ft3, 0x300(sp)
    fsw         ft4, 0x2c0(sp)
    fsw         ft5, 0x280(sp)
    fsw         ft6, 0x240(sp)
    fsw         ft7, 0x200(sp)

1:
    /* argument passed to intercept_routine */
    ld          a0, 0x78(sp)

    li          t5, 1
    beq         a0, t5, 0f
    /* jalr x1, intercept_routine */
    la          t6, intercept_routine
    jalr        x1, t6
    j           1f	
0:  
    /* jalr x1, intercept_routine_post_clone */
    la          t6, intercept_routine_post_clone
    jalr        x1, t6
1:
    /*
     * At this point, the return value of the C
     * function (a struct wrapper_ret instance) is in a0, a1.
     *
     * This function doesn't use these values for anything, just
     * forwards them to the higher level wrapper function, generated
     * from the template.
     */

    mv          t3, a1
    /*
     * At this point, the return values of this asm function
     * are in a0, t3.
     *
     * Restore the other registers, and return.
     */

    lb          t5, intercept_wrapper_must_save_simd
    beqz        t5, 0f

#ifdef HAS_RISCV_VECTOR

    vsetvli     t6, zero, e32, m8
    vle.v       v0, 0x3c0(sp)
    vle.v       v1, 0x380(sp)
    vle.v       v2, 0x340(sp)
    vle.v       v3, 0x300(sp)
    vle.v       v4, 0x2c0(sp)
    vle.v       v5, 0x280(sp)
    vle.v       v6, 0x240(sp)
    vle.v       v7, 0x200(sp)
    j           1f
#endif

0:
    flw         ft0, 0x3c0(sp)
    flw         ft1, 0x380(sp)
    flw         ft2, 0x340(sp)
    flw         ft3, 0x300(sp)
    flw         ft4, 0x2c0(sp)
    flw         ft5, 0x280(sp)
    flw         ft6, 0x240(sp)
    flw         ft7, 0x200(sp)

1:
    ld          ra, 0x160(sp)
    ld          t0, 0x158(sp)
    ld          t1, 0x150(sp)
    ld          t2, 0x148(sp)
    ld          t3, 0x140(sp)
    ld          t4, 0x138(sp)
    ld          t5, 0x130(sp)
    ld          t6, 0x128(sp)
    ld          s0, 0x120(sp)
    ld          s1, 0x118(sp)
    ld          a0, 0x110(sp)
    ld          a1, 0x108(sp)
    ld          a2, 0x100(sp)
    ld          a3, 0xf8(sp)
    ld          a4, 0xf0(sp)
    ld          a5, 0xe8(sp)
    ld          a6, 0xe0(sp)
    ld          a7, 0xd8(sp)
    ld          s2, 0xd0(sp)
    ld          s3, 0xc8(sp)
    ld          s4, 0xc0(sp)
    ld          s5, 0xb8(sp)
    ld          s6, 0xb0(sp)
    ld          s7, 0xa8(sp)
    ld          s8, 0xa0(sp)
    ld          s9, 0x98(sp)
    ld          s10, 0x90(sp)
    ld          s11, 0x88(sp)

    addi        sp, sp, 0x448

    ret
    .cfi_endproc
