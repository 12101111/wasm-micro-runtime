/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#define WAMR_PROFILE_FILE_ID 255
#include "aot_profiler.h"

#if WASM_ENABLE_PROFILER != 0

static void
wamr_profile_set_debug_location(AOTCompContext *comp_ctx, uint32_t line,
                                uint32_t column)
{
    LLVMMetadataRef loc;

    if (!comp_ctx->profiler || !comp_ctx->current_debug_func)
        return;

    loc = LLVMDIBuilderCreateDebugLocation(comp_ctx->context, line, column,
                                           comp_ctx->current_debug_func, NULL);
    LLVMSetCurrentDebugLocation2(comp_ctx->builder, loc);
}

void
wamr_profile_append_func(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         const char *func_name, uint32_t entry_op, uint32_t offset)
{
    LLVMMetadataRef func_type_meta;
    LLVMMetadataRef debug_func;
    uint32_t line_no;
    const char *name = func_name;

    if (!comp_ctx->profiler)
        return;

    if (!name)
        name = LLVMGetValueName(func_ctx->func);

    line_no = profile_info_append_func(comp_ctx->profiler, name);

    func_type_meta = LLVMDIBuilderCreateSubroutineType(
        comp_ctx->debug_builder, comp_ctx->debug_file, NULL, 0,
        LLVMDIFlagPublic);

    debug_func = LLVMDIBuilderCreateFunction(
        comp_ctx->debug_builder, comp_ctx->debug_comp_unit, name,
        strlen(name), name, strlen(name), comp_ctx->debug_file,
        line_no, func_type_meta, true, true, line_no, LLVMDIFlagPublic, false);

    LLVMSetSubprogram(func_ctx->func, debug_func);
    func_ctx->debug_func = debug_func;
    comp_ctx->current_debug_func = debug_func;

    line_no = profile_info_append_op(comp_ctx->profiler, entry_op, offset);
    comp_ctx->profiler_line_no = line_no;

    wamr_profile_set_debug_location(comp_ctx, line_no, 0);
}

void
wamr_profile_append_op(AOTCompContext *comp_ctx, uint32_t opcode, uint32_t offset)
{
    uint32_t line_no;

    if (!comp_ctx->profiler)
        return;

    line_no = profile_info_append_op(comp_ctx->profiler, opcode, offset);
    comp_ctx->profiler_line_no = line_no;

    wamr_profile_set_debug_location(comp_ctx, line_no, 0);
}

static uint32_t
wamr_profile_append_inst_internal(AOTCompContext *comp_ctx, InstKind kind,
                                  uint8_t compiler_file, uint16_t compiler_loc)
{
    uint32_t column;

    if (!comp_ctx->profiler || !comp_ctx->current_debug_func)
        return 0;

    column = profile_info_append_inst(comp_ctx->profiler, kind, compiler_file,
                                      compiler_loc);
    wamr_profile_set_debug_location(comp_ctx, comp_ctx->profiler_line_no,
                                    column);
    return column;
}

void
wamr_profile_append_default_inst(AOTCompContext *comp_ctx)
{
    if (!comp_ctx->profiler)
        return;

    wamr_profile_set_debug_location(comp_ctx, comp_ctx->profiler_line_no, 0);
}

LLVMValueRef
wamr_profile_build_load2(AOTCompContext *comp_ctx, LLVMBuilderRef builder,
                         LLVMTypeRef type, LLVMValueRef value, const char *name,
                         uint8_t compiler_file, uint16_t compiler_loc)
{
    LLVMValueRef res;

    wamr_profile_append_inst_internal(comp_ctx, Load, compiler_file,
                                      compiler_loc);
    res = LLVMBuildLoad2(builder, type, value, name);
    wamr_profile_append_default_inst(comp_ctx);
    return res;
}

LLVMValueRef
wamr_profile_build_store(AOTCompContext *comp_ctx, LLVMBuilderRef builder,
                         LLVMValueRef value, LLVMValueRef ptr,
                         uint8_t compiler_file, uint16_t compiler_loc)
{
    LLVMValueRef res;

    wamr_profile_append_inst_internal(comp_ctx, Store, compiler_file,
                                      compiler_loc);
    res = LLVMBuildStore(builder, value, ptr);
    wamr_profile_append_default_inst(comp_ctx);
    return res;
}

LLVMValueRef
wamr_profile_build_call2(AOTCompContext *comp_ctx, LLVMBuilderRef builder,
                         LLVMTypeRef functype, LLVMValueRef func,
                         LLVMValueRef *args, unsigned nargs, const char *name,
                         uint8_t compiler_file, uint16_t compiler_loc)
{
    LLVMValueRef res;

    wamr_profile_append_inst_internal(comp_ctx, Call, compiler_file,
                                      compiler_loc);
    res = LLVMBuildCall2(builder, functype, func, args, nargs, name);
    wamr_profile_append_default_inst(comp_ctx);
    return res;
}

LLVMValueRef
wamr_profile_build_switch(AOTCompContext *comp_ctx, LLVMBuilderRef builder,
                          LLVMValueRef value, LLVMBasicBlockRef else_block,
                          unsigned num_cases, uint8_t compiler_file,
                          uint16_t compiler_loc)
{
    LLVMValueRef res;

    wamr_profile_append_inst_internal(comp_ctx, Switch, compiler_file,
                                      compiler_loc);
    res = LLVMBuildSwitch(builder, value, else_block, num_cases);
    wamr_profile_append_default_inst(comp_ctx);
    return res;
}

LLVMValueRef
wamr_profile_build_br(AOTCompContext *comp_ctx, LLVMBuilderRef builder,
                      LLVMBasicBlockRef block, uint8_t compiler_file,
                      uint16_t compiler_loc)
{
    LLVMValueRef res;

    wamr_profile_append_inst_internal(comp_ctx, Jump, compiler_file,
                                      compiler_loc);
    res = LLVMBuildBr(builder, block);
    wamr_profile_append_default_inst(comp_ctx);
    return res;
}

LLVMValueRef
wamr_profile_build_cond_br(AOTCompContext *comp_ctx, LLVMBuilderRef builder,
                           LLVMValueRef cond, LLVMBasicBlockRef then_block,
                           LLVMBasicBlockRef else_block, uint8_t compiler_file,
                           uint16_t compiler_loc)
{
    LLVMValueRef res;

    wamr_profile_append_inst_internal(comp_ctx, Branch, compiler_file,
                                      compiler_loc);
    res = LLVMBuildCondBr(builder, cond, then_block, else_block);
    wamr_profile_append_default_inst(comp_ctx);
    return res;
}

LLVMValueRef
wamr_profile_build_ret(AOTCompContext *comp_ctx, LLVMBuilderRef builder,
                       LLVMValueRef value, uint8_t compiler_file,
                       uint16_t compiler_loc)
{
    LLVMValueRef res;

    wamr_profile_append_inst_internal(comp_ctx, Return, compiler_file,
                                      compiler_loc);
    res = LLVMBuildRet(builder, value);
    wamr_profile_append_default_inst(comp_ctx);
    return res;
}

LLVMValueRef
wamr_profile_build_ret_void(AOTCompContext *comp_ctx, LLVMBuilderRef builder,
                            uint8_t compiler_file, uint16_t compiler_loc)
{
    LLVMValueRef res;

    wamr_profile_append_inst_internal(comp_ctx, Return, compiler_file,
                                      compiler_loc);
    res = LLVMBuildRetVoid(builder);
    wamr_profile_append_default_inst(comp_ctx);
    return res;
}

#endif /* WASM_ENABLE_PROFILER != 0 */
