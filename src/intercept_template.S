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
 *       notice, this list of conditions and the following disclaimer.
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
 * intercept_template.s -- see asm_wrapper.md
 */

.section .text

.global intercept_asm_wrapper_tmpl
.hidden intercept_asm_wrapper_tmpl
.global intercept_asm_wrapper_patch_desc_addr
.hidden intercept_asm_wrapper_patch_desc_addr
.global intercept_asm_wrapper_wrapper_level1_addr
.hidden intercept_asm_wrapper_wrapper_level1_addr
.global intercept_asm_wrapper_tmpl_end
.hidden intercept_asm_wrapper_tmpl_end

.align 4

/*
 * Locals on the stack:
 * 0(%sp) the original value of %sp, in the code around the syscall
 * 8(%sp) the pointer to the struct patch_desc instance
 *
 * The %t0 register controls which C function to call in intercept.c:
 *
 * if %t0 == 0 then call intercept_routine
 * if %t0 == 1 then intercept_routine_post_clone
 *
 * This value in %t0 is passed to the function intercept_wrapper.
 *
 *
 * Note: the addi instruction allocating stack for locals must not
 * ruin the stack alignment. It must round up the number of bytes
 * needed for locals.
 */
intercept_asm_wrapper_tmpl:
    li          t0, 0x0       /* choose intercept_routine */

0:  mv          t1, sp       /* remember original sp */
    addi        sp, sp, -128  /* avoid the red zone and allocate stack space */
    andi        sp, sp, -16   /* align the stack */
    addi        sp, sp, -32   /* allocate stack for some locals */
    sd          t1, 0(sp)     /* original sp on stack */
intercept_asm_wrapper_patch_desc_addr:
    la          t1, 0x000000000000 /* we can change this to mov */
    sd          t1, 8(sp)     /* patch_desc pointer on stack */
intercept_asm_wrapper_wrapper_level1_addr:
    la          t1, 0x000000000000 /* we can change this to mov */
    jalr        ra, t1, 0     /* call intercept_wrapper */
    ld          sp, 0(sp)     /* restore original sp */
    /*
     * The intercept_wrapper function did restore all registers to their
     * original state, except for a0, sp, pc, and t1.
     *
     * If t1 is zero, a0 contains a syscall number, and that syscall
     *  is executed here.
     * If t1 is 1, a0 contains the return value of the hooked syscall.
     * If t1 is 2, a clone syscall is executed here.
     */
    li          t2, 0
    beq         t1, t2, 2f
    li          t2, 1
    beq         t1, t2, 3f
    li          t2, 2
    beq         t1, t2, 1f

    ebreak       /* t1 value is invalid? */

1:
    /* execute the clone syscall in its original context */
    ecall
    li          t0, 1        /* choose intercept_routine_post_clone */
    /*
     * Now goto 0, and call the C function named
     * intercept_routine_post_clone both in the parent thread, and the
     * child thread.
     */
    j           0b

2:
    ecall
3:
intercept_asm_wrapper_tmpl_end:
    /*
     * This template must be appended here with a
     * jump back to the intercepted code.
     */
