/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_PROFILER_H_
#define _AOT_PROFILER_H_

#include "aot_llvm.h"

#if WASM_ENABLE_PROFILER != 0

#ifndef WAMR_PROFILE_FILE_ID
#error "WAMR_PROFILE_FILE_ID must be defined before including aot_profiler.h"
#endif

#define WAMR_PROFILE_OP_ENTRY_BLOCK 0x10000
#define WAMR_PROFILE_OP_RETURN_BLOCK 0x10001

/* WAMR_PROFILE_FILE_ID 255 is reserved for aot_profiler.c itself to
   avoid macro re-expansion in the wrapper implementations.  */
#if WAMR_PROFILE_FILE_ID != 255

#define LLVMBuildLoad2(builder, type, value, name)                             \
    wamr_profile_build_load2(comp_ctx, builder, type, value, name,             \
                             WAMR_PROFILE_FILE_ID, __LINE__)

#define LLVMBuildStore(builder, value, ptr)                                    \
    wamr_profile_build_store(comp_ctx, builder, value, ptr,                    \
                             WAMR_PROFILE_FILE_ID, __LINE__)

#define LLVMBuildCall2(builder, functype, func, args, nargs, name)             \
    wamr_profile_build_call2(comp_ctx, builder, functype, func, args, nargs,   \
                             name, WAMR_PROFILE_FILE_ID, __LINE__)

#define LLVMBuildSwitch(builder, value, else_block, num_cases)                 \
    wamr_profile_build_switch(comp_ctx, builder, value, else_block, num_cases, \
                              WAMR_PROFILE_FILE_ID, __LINE__)

#define LLVMBuildBr(builder, block)                                            \
    wamr_profile_build_br(comp_ctx, builder, block, WAMR_PROFILE_FILE_ID,      \
                          __LINE__)

#define LLVMBuildCondBr(builder, cond, then_block, else_block)                 \
    wamr_profile_build_cond_br(comp_ctx, builder, cond, then_block, else_block,\
                               WAMR_PROFILE_FILE_ID, __LINE__)

#define LLVMBuildRet(builder, value)                                           \
    wamr_profile_build_ret(comp_ctx, builder, value, WAMR_PROFILE_FILE_ID,     \
                           __LINE__)

#define LLVMBuildRetVoid(builder)                                              \
    wamr_profile_build_ret_void(comp_ctx, builder, WAMR_PROFILE_FILE_ID,       \
                                __LINE__)

#endif /* WAMR_PROFILE_FILE_ID != 255 */

#ifdef __cplusplus
extern "C" {
#endif

LLVMValueRef
wamr_profile_build_load2(AOTCompContext *comp_ctx, LLVMBuilderRef builder,
                         LLVMTypeRef type, LLVMValueRef value, const char *name,
                         uint8_t compiler_file, uint16_t compiler_loc);

LLVMValueRef
wamr_profile_build_store(AOTCompContext *comp_ctx, LLVMBuilderRef builder,
                         LLVMValueRef value, LLVMValueRef ptr,
                         uint8_t compiler_file, uint16_t compiler_loc);

LLVMValueRef
wamr_profile_build_call2(AOTCompContext *comp_ctx, LLVMBuilderRef builder,
                         LLVMTypeRef functype, LLVMValueRef func,
                         LLVMValueRef *args, unsigned nargs, const char *name,
                         uint8_t compiler_file, uint16_t compiler_loc);

LLVMValueRef
wamr_profile_build_switch(AOTCompContext *comp_ctx, LLVMBuilderRef builder,
                          LLVMValueRef value, LLVMBasicBlockRef else_block,
                          unsigned num_cases, uint8_t compiler_file,
                          uint16_t compiler_loc);

LLVMValueRef
wamr_profile_build_br(AOTCompContext *comp_ctx, LLVMBuilderRef builder,
                      LLVMBasicBlockRef block, uint8_t compiler_file,
                      uint16_t compiler_loc);

LLVMValueRef
wamr_profile_build_cond_br(AOTCompContext *comp_ctx, LLVMBuilderRef builder,
                           LLVMValueRef cond, LLVMBasicBlockRef then_block,
                           LLVMBasicBlockRef else_block, uint8_t compiler_file,
                           uint16_t compiler_loc);

LLVMValueRef
wamr_profile_build_ret(AOTCompContext *comp_ctx, LLVMBuilderRef builder,
                       LLVMValueRef value, uint8_t compiler_file,
                       uint16_t compiler_loc);

LLVMValueRef
wamr_profile_build_ret_void(AOTCompContext *comp_ctx, LLVMBuilderRef builder,
                            uint8_t compiler_file, uint16_t compiler_loc);

void
wamr_profile_append_func(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         const char *func_name, uint32_t entry_op);

void
wamr_profile_append_op(AOTCompContext *comp_ctx, uint32_t opcode);

void
wamr_profile_append_default_inst(AOTCompContext *comp_ctx);

#ifdef __cplusplus
}
#endif

#else /* WASM_ENABLE_PROFILER == 0 */

#define wamr_profile_append_func(comp_ctx, func_ctx, func_name, entry_op) \
    (void)0
#define wamr_profile_append_op(comp_ctx, opcode) (void)0
#define wamr_profile_append_default_inst(comp_ctx) (void)0

#endif /* WASM_ENABLE_PROFILER != 0 */

#endif /* _AOT_PROFILER_H_ */
