/*
 * Copyright 2016-2020, Intel Corporation
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

/*
 * disasm_wrapper.c -- connecting the interceptor code
 * to the disassembler code from the capstone project.
 *
 * See:
 * http://www.capstone-engine.org/lang_c.html
 */

#include "intercept.h"
#include "intercept_util.h"
#include "disasm_wrapper.h"

#include <assert.h>
#include <string.h>
#include <syscall.h>
#include "capstone_wrapper.h"

struct intercept_disasm_context {
	csh handle;
	cs_insn *insn;
	const unsigned char *begin;
	const unsigned char *end;
};

/*
 * nop_vsnprintf - A dummy function, serving as a callback called by
 * the capstone implementation. The syscall_intercept library never makes
 * any use of string representation of instructions, but there seems to no
 * trivial way to use disassemble using capstone without it spending time
 * on printing syscalls. This seems to be the most that can be done in
 * this regard i.e. providing capstone with nop implementation of vsnprintf.
 */
static int
nop_vsnprintf()
{
	return 0;
}

/*
 * intercept_disasm_init -- should be called before disassembling a region of
 * code. The context created contains the context capstone needs ( or generally
 * the underlying disassembling library, if something other than capstone might
 * be used ).
 *
 * One must pass this context pointer to intercept_disasm_destroy following
 * a disassembling loop.
 */
struct intercept_disasm_context *
intercept_disasm_init(const unsigned char *begin, const unsigned char *end)
{
	struct intercept_disasm_context *context;

	context = xmmap_anon(sizeof(*context));
	context->begin = begin;
	context->end = end;

	/*
	 * Initialize the disassembler.
	 * The handle here must be passed to capstone each time it is used.
	 */
	if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64|CS_MODE_RISCVC, &context->handle) != CS_ERR_OK)
		xabort("cs_open");

	/*
	 * Kindly ask capstone to return some details about the instruction.
	 * Without this, it only prints the instruction, and we would need
	 * to parse the resulting string.
	 */
	if (cs_option(context->handle, CS_OPT_DETAIL, CS_OPT_ON) != 0)
		xabort("cs_option - CS_OPT_DETAIL");

	/*
	 * Overriding the printing routine used by capstone,
	 * see comments above about nop_vsnprintf.
	 */
	cs_opt_mem x = {
		.malloc = malloc,
		.free = free,
		.calloc = calloc,
		.realloc = realloc,
		.vsnprintf = nop_vsnprintf};
	if (cs_option(context->handle, CS_OPT_MEM, (size_t)&x) != 0)
		xabort("cs_option - CS_OPT_MEM");

	if ((context->insn = cs_malloc(context->handle)) == NULL)
		xabort("cs_malloc");

	return context;
}

/*
 * intercept_disasm_destroy -- see comments for above routine
 */
void
intercept_disasm_destroy(struct intercept_disasm_context *context)
{
	cs_free(context->insn, 1);
	cs_close(&context->handle);
	xmunmap(context, sizeof(*context));
}

bool is_ip_relative(cs_insn *insn) {
    cs_detail *detail = insn->detail;
    cs_riscv *riscv = &detail->riscv;

    for (int k = 0; k < riscv->op_count; k++) {
        cs_riscv_op *op = &riscv->operands[k];

        if (op->type == RISCV_OP_IMM && (insn->mnemonic[0] == 'j' || insn->mnemonic[0] == 'b')) {
            // Immediate operand in a jump or branch instruction is PC-relative
            return true;
        }
    }

    return false;
}

void calculate_jump_offset_and_address(cs_insn *insn, struct intercept_disasm_result *result) {
    int32_t offset = 0;
    uint64_t absolute_address = 0;

    uint32_t opcode = insn->id;
    uint32_t pc = insn->address;
    cs_detail *detail = insn->detail;

    switch (opcode) {
        case RISCV_INS_JAL: // JAL
            offset = detail->riscv.operands[0].imm;
            absolute_address = pc + offset;
            result->is_jump = true;
            result->is_rel_jump = true;
            break;

        case RISCV_INS_JALR: // JALR
            offset = detail->riscv.operands[0].imm;
            absolute_address = detail->riscv.operands[1].reg + offset;
            result->is_jump = true;
            result->is_indirect_jump = true;
            break;

        case RISCV_INS_AUIPC: // AUIPC
            offset = detail->riscv.operands[0].imm << 12;
            absolute_address = pc + offset;
            result->is_jump = false;
            result->is_rel_jump = false;
	    result->has_ip_relative_opr = true;
            break;

        case RISCV_INS_BEQ: // BEQ
        case RISCV_INS_BNE: // BNE
        case RISCV_INS_BLT: // BLT
        case RISCV_INS_BGE: // BGE
        case RISCV_INS_BLTU: // BLTU
        case RISCV_INS_BGEU: // BGEU
            offset = detail->riscv.operands[2].imm;
            absolute_address = pc + offset;
            result->is_jump = true;
            result->is_rel_jump = true;
            break;

        case RISCV_INS_C_J: // C.J (Compressed JAL)
            offset = detail->riscv.operands[0].imm;
            absolute_address = pc + offset;
            result->is_jump = true;
            result->is_rel_jump = true;
            break;

        case RISCV_INS_C_JAL: // C.JAL
            offset = detail->riscv.operands[0].imm;
            absolute_address = pc + offset;
            result->is_jump = true;
            result->is_rel_jump = true;
            break;

        case RISCV_INS_C_BEQZ: // C.BEQZ
        case RISCV_INS_C_BNEZ: // C.BNEZ
            offset = detail->riscv.operands[1].imm;
            absolute_address = pc + offset;
            result->is_jump = true;
            result->is_rel_jump = true;
            break;

        default:
            // For unsupported instructions, set defaults
            offset = 0;
            absolute_address = 0;
            break;
    }

    result->rip_disp = offset;
    result->rip_ref_addr = (const unsigned char *)absolute_address;
    result->has_ip_relative_opr = is_ip_relative(insn);
}

int64_t check_a7_reg(cs_insn *insn) {
    cs_riscv *riscv = &(insn->detail->riscv);
    int64_t a7 = -1;

    if (insn->id == RISCV_INS_ADDI) {
        cs_riscv *riscv = &(insn->detail->riscv);
        if (riscv->op_count == 3 &&
            riscv->operands[0].type == RISCV_OP_REG && riscv->operands[0].reg == RISCV_REG_A7 &&
            riscv->operands[1].type == RISCV_OP_REG && riscv->operands[1].reg == RISCV_REG_ZERO &&
            riscv->operands[2].type == RISCV_OP_IMM) {
            a7 = riscv->operands[2].imm;
            // debug_dump("mnemonic : %s a7: %d\n",insn->mnemonic,a7);
        }
    }
    return a7;
}

/*
 * intercept_disasm_next_instruction - Examines a single instruction
 * in a text section. This is only a wrapper around capstone specific code,
 * collecting data that can be used later to make decisions about patching.
 */
struct intercept_disasm_result
intercept_disasm_next_instruction(struct intercept_disasm_context *context,
					const unsigned char *code, int* syscall_reg)
{
	struct intercept_disasm_result result = {0, };
	const unsigned char *start = code;
	size_t size = (size_t)(context->end - code + 1);
	uint64_t address = (uint64_t)code;

	if (!cs_disasm_iter(context->handle, &start, &size,
	    &address, context->insn)) {
		return result;
	}

	result.length = context->insn->size;

	assert(result.length != 0);

	result.is_syscall = (context->insn->id == RISCV_INS_ECALL);
	// result.is_ret = (context->insn->id == X86_INS_RET);
	result.is_rel_jump = false;
	result.is_indirect_jump = false;
	// result.is_nop = is_nop(context->insn);
#ifndef NDEBUG
	result.mnemonic = context->insn->mnemonic;
#endif

    result.is_jump = false;

	calculate_jump_offset_and_address(context->insn, &result);
    // debug_dump("0x%" PRIx64 ":\t%s\t%s\n", context->insn->address, context->insn->mnemonic, context->insn->op_str);
    int64_t a7  = check_a7_reg(context->insn);
    if(a7 != -1){
        *syscall_reg = a7;
    }
	result.is_set = true;

	return result;
}
