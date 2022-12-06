/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "libc_wasi_wrapper.h"
#include "bh_platform.h"
#include "wasm_export.h"

void
wasm_runtime_set_exception(wasm_module_inst_t module, const char *exception);

/* clang-format off */
#define get_module_inst(exec_env) \
    wasm_runtime_get_module_inst(exec_env)

#define get_wasi_ctx(module_inst) \
    wasm_runtime_get_wasi_ctx(module_inst)

#define validate_app_addr(offset, size) \
    wasm_runtime_validate_app_addr(module_inst, offset, size)

#define validate_native_addr(addr, size) \
    wasm_runtime_validate_native_addr(module_inst, addr, size)

#define addr_app_to_native(offset) \
    wasm_runtime_addr_app_to_native(module_inst, offset)

#define addr_native_to_app(ptr) \
    wasm_runtime_addr_native_to_app(module_inst, ptr)

#define module_malloc(size, p_native_addr) \
    wasm_runtime_module_malloc(module_inst, size, p_native_addr)

#define module_free(offset) \
    wasm_runtime_module_free(module_inst, offset)
/* clang-format on */

typedef struct wasi_prestat_app {
    wasi_preopentype_t pr_type;
    uint32 pr_name_len;
} wasi_prestat_app_t;

typedef struct iovec_app {
    uint32 buf_offset;
    uint32 buf_len;
} iovec_app_t;

typedef struct WASIContext {
    struct fd_table *curfds;
    struct fd_prestats *prestats;
    struct argv_environ_values *argv_environ;
    struct addr_pool *addr_pool;
    char *ns_lookup_buf;
    char **ns_lookup_list;
    char *argv_buf;
    char **argv_list;
    char *env_buf;
    char **env_list;
} * wasi_ctx_t;

wasi_ctx_t
wasm_runtime_get_wasi_ctx(wasm_module_inst_t module_inst);

static inline struct fd_table *
wasi_ctx_get_curfds(wasm_module_inst_t module_inst, wasi_ctx_t wasi_ctx)
{
    if (!wasi_ctx)
        return NULL;
    return wasi_ctx->curfds;
}

static inline struct argv_environ_values *
wasi_ctx_get_argv_environ(wasm_module_inst_t module_inst, wasi_ctx_t wasi_ctx)
{
    if (!wasi_ctx)
        return NULL;
    return wasi_ctx->argv_environ;
}

static inline struct fd_prestats *
wasi_ctx_get_prestats(wasm_module_inst_t module_inst, wasi_ctx_t wasi_ctx)
{
    if (!wasi_ctx)
        return NULL;
    return wasi_ctx->prestats;
}

static wasi_errno_t
wasi_args_get(wasm_exec_env_t exec_env, uint32 *argv_offsets, char *argv_buf)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct argv_environ_values *argv_environ =
        wasi_ctx_get_argv_environ(module_inst, wasi_ctx);
    size_t argc, argv_buf_size, i;
    char **argv;
    uint64 total_size;
    wasi_errno_t err;

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    err = wasmtime_ssp_args_sizes_get(argv_environ, &argc, &argv_buf_size);
    if (err)
        return err;

    total_size = sizeof(int32) * ((uint64)argc + 1);
    if (total_size >= UINT32_MAX
        || !validate_native_addr(argv_offsets, (uint32)total_size)
        || argv_buf_size >= UINT32_MAX
        || !validate_native_addr(argv_buf, (uint32)argv_buf_size))
        return (wasi_errno_t)-1;

    total_size = sizeof(char *) * ((uint64)argc + 1);
    if (total_size >= UINT32_MAX
        || !(argv = wasm_runtime_malloc((uint32)total_size)))
        return (wasi_errno_t)-1;

    err = wasmtime_ssp_args_get(argv_environ, argv, argv_buf);
    if (err) {
        wasm_runtime_free(argv);
        return err;
    }

    for (i = 0; i < argc; i++)
        argv_offsets[i] = addr_native_to_app(argv[i]);

    wasm_runtime_free(argv);
    return 0;
}

static wasi_errno_t
wasi_args_sizes_get(wasm_exec_env_t exec_env, uint32 *argc_app,
                    uint32 *argv_buf_size_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct argv_environ_values *argv_environ;
    size_t argc, argv_buf_size;
    wasi_errno_t err;

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(argc_app, sizeof(uint32))
        || !validate_native_addr(argv_buf_size_app, sizeof(uint32)))
        return (wasi_errno_t)-1;

    argv_environ = wasi_ctx->argv_environ;

    err = wasmtime_ssp_args_sizes_get(argv_environ, &argc, &argv_buf_size);
    if (err)
        return err;

    *argc_app = (uint32)argc;
    *argv_buf_size_app = (uint32)argv_buf_size;
    return 0;
}

static wasi_errno_t
wasi_clock_time_get(wasm_exec_env_t exec_env,
                    wasi_clockid_t clock_id,    /* uint32 clock_id */
                    wasi_timestamp_t precision, /* uint64 precision */
                    wasi_timestamp_t *time /* uint64 *time */)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    if (!validate_native_addr(time, sizeof(wasi_timestamp_t)))
        return (wasi_errno_t)-1;

    return wasmtime_ssp_clock_time_get(clock_id, precision, time);
}

static wasi_errno_t
wasi_fd_close(wasm_exec_env_t exec_env, wasi_fd_t fd)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    struct fd_prestats *prestats = wasi_ctx_get_prestats(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    return wasmtime_ssp_fd_close(curfds, prestats, fd);
}

static wasi_errno_t
wasi_fd_seek(wasm_exec_env_t exec_env, wasi_fd_t fd, wasi_filedelta_t offset,
             wasi_whence_t whence, wasi_filesize_t *newoffset)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(newoffset, sizeof(wasi_filesize_t)))
        return (wasi_errno_t)-1;

    return wasmtime_ssp_fd_seek(curfds, fd, offset, whence, newoffset);
}

static wasi_errno_t
wasi_fd_fdstat_get(wasm_exec_env_t exec_env, wasi_fd_t fd,
                   wasi_fdstat_t *fdstat_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    wasi_fdstat_t fdstat;
    wasi_errno_t err;

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(fdstat_app, sizeof(wasi_fdstat_t)))
        return (wasi_errno_t)-1;

    err = wasmtime_ssp_fd_fdstat_get(curfds, fd, &fdstat);
    if (err)
        return err;

    memcpy(fdstat_app, &fdstat, sizeof(wasi_fdstat_t));
    return 0;
}

static wasi_errno_t
wasi_fd_write(wasm_exec_env_t exec_env, wasi_fd_t fd,
              const iovec_app_t *iovec_app, uint32 iovs_len,
              uint32 *nwritten_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    wasi_ciovec_t *ciovec, *ciovec_begin;
    uint64 total_size;
    size_t nwritten;
    uint32 i;
    wasi_errno_t err;

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    total_size = sizeof(iovec_app_t) * (uint64)iovs_len;
    if (!validate_native_addr(nwritten_app, (uint32)sizeof(uint32))
        || total_size >= UINT32_MAX
        || !validate_native_addr((void *)iovec_app, (uint32)total_size))
        return (wasi_errno_t)-1;

    total_size = sizeof(wasi_ciovec_t) * (uint64)iovs_len;
    if (total_size >= UINT32_MAX
        || !(ciovec_begin = wasm_runtime_malloc((uint32)total_size)))
        return (wasi_errno_t)-1;

    ciovec = ciovec_begin;

    for (i = 0; i < iovs_len; i++, iovec_app++, ciovec++) {
        if (!validate_app_addr(iovec_app->buf_offset, iovec_app->buf_len)) {
            err = (wasi_errno_t)-1;
            goto fail;
        }
        ciovec->buf = (char *)addr_app_to_native(iovec_app->buf_offset);
        ciovec->buf_len = iovec_app->buf_len;
    }

    err = wasmtime_ssp_fd_write(curfds, fd, ciovec_begin, iovs_len, &nwritten);
    if (err)
        goto fail;

    *nwritten_app = (uint32)nwritten;

    /* success */
    err = 0;

fail:
    wasm_runtime_free(ciovec_begin);
    return err;
}

static void
wasi_proc_exit(wasm_exec_env_t exec_env, wasi_exitcode_t rval)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    /* Here throwing exception is just to let wasm app exit,
       the upper layer should clear the exception and return
       as normal */
    wasm_runtime_set_exception(module_inst, "wasi proc exit");
}

static wasi_errno_t
wasi_proc_raise(wasm_exec_env_t exec_env, wasi_signal_t sig)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    char buf[32];
    snprintf(buf, sizeof(buf), "%s%d", "wasi proc raise ", sig);
    wasm_runtime_set_exception(module_inst, buf);

    return 0;
}

static wasi_errno_t
wasi_sched_yield(wasm_exec_env_t exec_env)
{
    return wasmtime_ssp_sched_yield();
}

/* clang-format off */
#define REG_NATIVE_FUNC(func_name, signature) \
    { #func_name, wasi_##func_name, signature, NULL }
/* clang-format on */

static NativeSymbol native_symbols_libc_wasi[] = {
    REG_NATIVE_FUNC(args_get, "(**)i"),
    REG_NATIVE_FUNC(args_sizes_get, "(**)i"),
    REG_NATIVE_FUNC(clock_time_get, "(iI*)i"),
    REG_NATIVE_FUNC(fd_close, "(i)i"),
    REG_NATIVE_FUNC(fd_seek, "(iIi*)i"),
    REG_NATIVE_FUNC(fd_fdstat_get, "(i*)i"),
    REG_NATIVE_FUNC(fd_write, "(i*i*)i"),
    REG_NATIVE_FUNC(proc_exit, "(i)"),
    REG_NATIVE_FUNC(proc_raise, "(i)i"),
    REG_NATIVE_FUNC(sched_yield, "()i"),
};

uint32
get_libc_wasi_export_apis(NativeSymbol **p_libc_wasi_apis)
{
    *p_libc_wasi_apis = native_symbols_libc_wasi;
    return sizeof(native_symbols_libc_wasi) / sizeof(NativeSymbol);
}
