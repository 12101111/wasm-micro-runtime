/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _PLATFORM_INTERNAL_H
#define _PLATFORM_INTERNAL_H

#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <time.h>
#include <stdio.h>
#include <sys/types.h>

#include <FreeRTOS.h>
#include <FreeRTOS_POSIX/pthread.h>
#include <task.h>
#include <semphr.h>
#include <vfs.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef BH_PLATFORM_FREERTOS
#define BH_PLATFORM_FREERTOS
#endif

typedef TaskHandle_t korp_thread;
typedef korp_thread korp_tid;
typedef struct {
    bool is_recursive;
    SemaphoreHandle_t sem;
} korp_mutex;

struct os_thread_wait_node;
typedef struct os_thread_wait_node *os_thread_wait_list;
typedef struct korp_cond {
    SemaphoreHandle_t wait_list_lock;
    os_thread_wait_list thread_wait_list;
} korp_cond;

typedef SemaphoreHandle_t korp_sem;

int clock_gettime( clockid_t clock_id,
                   struct timespec * tp );

#define CLOCK_MONOTONIC 1

#define os_printf printf
#define os_vprintf vprintf

#define open aos_open
#define close aos_close
#define read aos_read
#define write aos_write
#define closedir aos_closedir
#define lseek aos_lseek
#define DIR aos_dir_t
#define PATH_MAX 256

struct iovec {
    void *iov_base;
    size_t iov_len;
};
ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
int fcntl(int fd, int cmd, int val);
#define F_GETFL  3
#define O_APPEND 02000
#define O_NONBLOCK 04000
#define O_SYNC 04010000

#define assert(__e) ((__e) ? (void)0 : __assert_func (__FILE__, __LINE__, \
						       __func__, #__e))
void __assert_func (const char *, int, const char *, const char *)
	    __attribute ((__noreturn__));


#define BH_APPLET_PRESERVED_STACK_SIZE (2 * BH_KB)

/* Default thread priority */
#define BH_THREAD_DEFAULT_PRIORITY 5

/* Special value for tv_nsec field of timespec */

#define UTIME_NOW ((1l << 30) - 1l)
#ifndef __cplusplus
#define UTIME_OMIT ((1l << 30) - 2l)
#endif

#ifdef DT_UNKNOWN
#undef DT_UNKNOWN
#endif

#ifdef DT_REG
#undef DT_REG
#endif

#ifdef DT_DIR
#undef DT_DIR
#endif

/* Below parts of d_type define are ported from Nuttx, under Apache License v2.0
 */

/* File type code for the d_type field in dirent structure.
 * Note that because of the simplified filesystem organization of the NuttX,
 * top-level, pseudo-file system, an inode can be BOTH a file and a directory
 */

#define DTYPE_UNKNOWN 0
#define DTYPE_FIFO 1
#define DTYPE_CHR 2
#define DTYPE_SEM 3
#define DTYPE_DIRECTORY 4
#define DTYPE_MQ 5
#define DTYPE_BLK 6
#define DTYPE_SHM 7
#define DTYPE_FILE 8
#define DTYPE_MTD 9
#define DTYPE_LINK 10
#define DTYPE_SOCK 12

/* The d_type field of the dirent structure is not specified by POSIX.  It
 * is a non-standard, 4.5BSD extension that is implemented by most OSs.  A
 * POSIX compliant OS may not implement the d_type field at all.  Many OS's
 * (including glibc) may use the following alternative naming for the file
 * type names:
 */

#define DT_UNKNOWN DTYPE_UNKNOWN
#define DT_FIFO DTYPE_FIFO
#define DT_CHR DTYPE_CHR
#define DT_SEM DTYPE_SEM
#define DT_DIR DTYPE_DIRECTORY
#define DT_MQ DTYPE_MQ
#define DT_BLK DTYPE_BLK
#define DT_SHM DTYPE_SHM
#define DT_REG DTYPE_FILE
#define DT_MTD DTYPE_MTD
#define DT_LNK DTYPE_LINK
#define DT_SOCK DTYPE_SOCK

#ifdef __cplusplus
}
#endif

#endif
