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
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
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

#.global has_vector_extension;
#.hidden has_vector_extension;
#.type   has_vector_extension, @function

.global syscall_no_intercept;
.type   syscall_no_intercept, @function

.text

# has_vector_extension:
   # .cfi_startproc
  #  csrr a0, misa          # Read the misa CSR into a0
  #  li t0, 0x100           # Load immediate value 0x100 (bit 8 corresponds to 'V')
  #  and a0, a0, t0         # AND a0 with t0 to isolate the 'V' bit
  #  srli a0, a0, 8         # Shift right logical immediate to move the 'V' bit to the least significant bit
  #  jalr zero, ra          # Return (a0 will be 1 if 'V' is supported, 0 otherwise)
   # .cfi_endproc

#.size has_vector_extension, .-has_vector_extension

syscall_no_intercept:
	addi a7, a0, 0  // Move argument 1 into a7 (SYSCALL_NUM)
	addi a0, a1, 0  // Move argument 2 into a0
	addi a1, a2, 0  // Move argument 3 into a1
	addi a2, a3, 0  // Move argument 4 into a2
	addi a3, a4, 0  // Move argument 5 into a3
	addi a4, a5, 0  // Move argument 6 into a4
	addi a5, a6, 0  // Move argument 7 into a5
	ecall           // Make the system call
	ret             // Return from the function


.size   syscall_no_intercept, .-syscall_no_intercept
