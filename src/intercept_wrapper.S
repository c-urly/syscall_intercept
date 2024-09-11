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

.macro save_gprs
    sd          ra, 0x160(sp)
    sd          a6, 0x158(sp)
    sd          a5, 0x150(sp)
    sd          a4, 0x148(sp)
    sd          a3, 0x140(sp)
    sd          a2, 0x138(sp)
    sd          a1, 0x130(sp)
    sd          a0, 0x128(sp)
    sd          s1, 0x120(sp)
    sd          s0, 0x118(sp)
    sd          s11, 0x110(sp)
    sd          s10, 0x108(sp)
    sd          s9, 0x100(sp)
    sd          s8, 0xF8(sp)
    sd          s7, 0xF0(sp)
    sd          s6, 0xE8(sp)
    sd          s5, 0xE0(sp)
    sd          s4, 0xD8(sp)
    sd          s3, 0xD0(sp)
    sd          s2, 0xC8(sp)
    sd          t6, 0xC0(sp)
    sd          t5, 0xB8(sp)
    sd          t4, 0xB0(sp)
    sd          t3, 0xA8(sp)
    sd          t2, 0xA0(sp)
/*    sd          t0, 0x98(sp) */
.endm

.macro restore_gprs
    ld          ra, 0x160(sp)
    ld          a6, 0x158(sp)
    ld          a5, 0x150(sp)
    ld          a4, 0x148(sp)
    ld          a3, 0x140(sp)
    ld          a2, 0x138(sp)
    ld          a1, 0x130(sp)
    /*ld          a0, 0x128(sp)*/
    ld          s1, 0x120(sp)
    ld          s0, 0x118(sp)
    ld          s11, 0x110(sp)
    ld          s10, 0x108(sp)
    ld          s9, 0x100(sp)
    ld          s8, 0xF8(sp)
    ld          s7, 0xF0(sp)
    ld          s6, 0xE8(sp)
    ld          s5, 0xE0(sp)
    ld          s4, 0xD8(sp)
    ld          s3, 0xD0(sp)
    ld          s2, 0xC8(sp)
    ld          t6, 0xC0(sp)
    ld          t5, 0xB8(sp)
    ld          t4, 0xB0(sp)
    ld          t3, 0xA8(sp)
    ld          t2, 0xA0(sp)
 /*   ld          t0, 0x98(sp) */
.endm

.macro save_floating_point
    fsw         ft0, 0x3c0(sp)
    fsw         ft1, 0x380(sp)
    fsw         ft2, 0x340(sp)
    fsw         ft3, 0x300(sp)
    fsw         ft4, 0x2c0(sp)
    fsw         ft5, 0x280(sp)
    fsw         ft6, 0x240(sp)
    fsw         ft7, 0x200(sp)
.endm

.macro restore_floating_point
    flw         ft0, 0x3c0(sp)
    flw         ft1, 0x380(sp)
    flw         ft2, 0x340(sp)
    flw         ft3, 0x300(sp)
    flw         ft4, 0x2c0(sp)
    flw         ft5, 0x280(sp)
    flw         ft6, 0x240(sp)
    flw         ft7, 0x200(sp)
.endm

.macro save_simd
    vsetvli     a0, zero, e32, m8
    vse.v       v0, 0x3c0(sp)
    vse.v       v1, 0x380(sp)
    vse.v       v2, 0x340(sp)
    vse.v       v3, 0x300(sp)
    vse.v       v4, 0x2c0(sp)
    vse.v       v5, 0x280(sp)
    vse.v       v6, 0x240(sp)
    vse.v       v7, 0x200(sp)
.endm

.macro restore_simd
    vsetvli     a0, zero, e32, m8
    vle.v       v0, 0x3c0(sp)
    vle.v       v1, 0x380(sp)
    vle.v       v2, 0x340(sp)
    vle.v       v3, 0x300(sp)
    vle.v       v4, 0x2c0(sp)
    vle.v       v5, 0x280(sp)
    vle.v       v6, 0x240(sp)
    vle.v       v7, 0x200(sp)
.endm


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

    /* Stack adjustment */
    addi        sp, sp, -0x448
    .cfi_def_cfa_offset 0x0

    /* Save all GPRs */
    save_gprs

    /* Save original value of sp and patch_desc pointer */
    /* ld          a0, 0x450(sp) */
    /* sd          a0, 0x80(sp)  */
    .cfi_offset 5, 0x80
    ld          a0, 0x450(sp)
    sd          a0, 0x98(sp)

    /* Conditional save of SIMD or Floating Point registers */
    /* lb          a0, intercept_wrapper_must_save_simd */
    /* beqz        a0, 0f */
0:
    /* save_floating_point */

1:
    /* Call intercept routine */
    addi    a0, sp, 0x98
    bnez    a7, 0f  // Branch to label 0f if a7 is not zero
    la          a7, intercept_routine
    jalr        ra, a7
    j           1f
0:
    la          a7, intercept_routine_post_clone
    jalr        ra, a7

1:
    mv    t1, a1
    li    t2, 1 
    beq   t1, t2, 1f 
    ld    a0, 0x128(sp)

0:
    /* restore_floating_point */

1:
    /* Restore all GPRs */
    restore_gprs

    /* Stack readjustment and return */
    addi        sp, sp, 0x448
    ret
    .cfi_endproc
