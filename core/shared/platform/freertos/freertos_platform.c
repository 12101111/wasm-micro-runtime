/*
 * Copyright (C) 2022 Han Puyu.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_extension.h"
#include "platform_api_vmcore.h"
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include "locking.h"

int
bh_platform_init()
{
    return 0;
}

void
bh_platform_destroy()
{
}

void *
os_malloc(unsigned size)
{
    return malloc(size);
}

void *
os_realloc(void *ptr, unsigned size)
{
    return realloc(ptr, size);
}

void
os_free(void *ptr)
{
    free(ptr);
}

void *
os_mmap(void *hint, size_t size, int prot, int flags)
{
    return malloc((unsigned)size);
}

void
os_munmap(void *addr, size_t size)
{
    return free(addr);
}

int
os_mprotect(void *addr, size_t size, int prot)
{
    return 0;
}

void
os_dcache_flush()
{
}

uint8 *
os_thread_get_stack_boundary(void)
{
    return NULL;
}

int
fcntl(int fd, int cmd, int val)
{
    return 0;
}

ssize_t
writev(int fd, const struct iovec *iov, int iovcnt)
{
    ssize_t len = 0;
    for (int i = 0; i < iovcnt; i++) {
        int ret = write(fd, iov[i].iov_base, iov[i].iov_len);
        if (ret < 0) {
            return ret;
        }
        else {
            len += ret;
        }
    }
    return len;
}
