// Part of the Wasmtime Project, under the Apache License v2.0 with LLVM
// Exceptions. See
// https://github.com/bytecodealliance/wasmtime/blob/main/LICENSE for license
// information.
//
// Significant parts of this file are derived from cloudabi-utils. See
// https://github.com/bytecodealliance/wasmtime/blob/main/lib/wasi/sandboxed-system-primitives/src/LICENSE
// for license information.
//
// The upstream file contains the following copyright notice:
//
// Copyright (c) 2016-2018 Nuxi, https://nuxi.nl/

#include "ssp_config.h"
#include "bh_platform.h"
#include "wasmtime_ssp.h"
#include "locking.h"
#include "numeric_limits.h"
#include "posix.h"
#include "random.h"
#include "refcount.h"
#include "rights.h"
#include "str.h"
#include <stdio.h>
#include <string.h>

#if 0 /* TODO: -std=gnu99 causes compile error, comment them first */
// struct iovec must have the same layout as __wasi_iovec_t.
static_assert(offsetof(struct iovec, iov_base) ==
                  offsetof(__wasi_iovec_t, buf),
              "Offset mismatch");
static_assert(sizeof(((struct iovec *)0)->iov_base) ==
                  sizeof(((__wasi_iovec_t *)0)->buf),
              "Size mismatch");
static_assert(offsetof(struct iovec, iov_len) ==
                  offsetof(__wasi_iovec_t, buf_len),
              "Offset mismatch");
static_assert(sizeof(((struct iovec *)0)->iov_len) ==
                  sizeof(((__wasi_iovec_t *)0)->buf_len),
              "Size mismatch");
static_assert(sizeof(struct iovec) == sizeof(__wasi_iovec_t),
              "Size mismatch");

// struct iovec must have the same layout as __wasi_ciovec_t.
static_assert(offsetof(struct iovec, iov_base) ==
                  offsetof(__wasi_ciovec_t, buf),
              "Offset mismatch");
static_assert(sizeof(((struct iovec *)0)->iov_base) ==
                  sizeof(((__wasi_ciovec_t *)0)->buf),
              "Size mismatch");
static_assert(offsetof(struct iovec, iov_len) ==
                  offsetof(__wasi_ciovec_t, buf_len),
              "Offset mismatch");
static_assert(sizeof(((struct iovec *)0)->iov_len) ==
                  sizeof(((__wasi_ciovec_t *)0)->buf_len),
              "Size mismatch");
static_assert(sizeof(struct iovec) == sizeof(__wasi_ciovec_t),
              "Size mismatch");
#endif

#if defined(WASMTIME_SSP_STATIC_CURFDS)
static __thread struct fd_table *curfds;
static __thread struct fd_prestats *prestats;
static __thread struct argv_environ_values *argv_environ;
static __thread struct addr_pool *addr_pool;
#endif

bool
rwlock_init(struct rwlock *lock)
{
    //printf("rwlock_init %p\n", lock);
    //lock->read_count = 0;
    //pthread_mutex_init(&lock->read_lock, NULL);
    //pthread_mutex_init(&lock->write_lock, NULL);
    //printf("rwlock_init done!\n");
    return true;
}

void
rwlock_rdlock(struct rwlock *lock)
{
    //printf("rwlock_rdlock %p\n", lock);
    //pthread_mutex_lock(&lock->read_lock);
    //if (lock->read_count == 0) {
    //    pthread_mutex_lock(&lock->write_lock);
    //}
    //lock->read_count++;
    //pthread_mutex_unlock(&lock->read_lock);
    //printf("rwlock_rdlock done!\n");
}

void
rwlock_wrlock(struct rwlock *lock)
{
    /*
    printf("rwlock_wrlock %p\n", lock);
    pthread_mutex_lock(&lock->write_lock);
    printf("rwlock_wrlock done!\n");*/
}

void
rwlock_unlock(struct rwlock *lock)
{
    /*
    printf("rwlock_unlock %p\n", lock);
    pthread_mutex_lock(&lock->read_lock);
    if (lock->read_count <= 1) {
        pthread_mutex_unlock(&lock->write_lock);
    }
    if (lock->read_count >= 1) {
        lock->read_count--;
    }
    pthread_mutex_unlock(&lock->read_lock);
    printf("rwlock_unlock done!\n");*/
}

void
rwlock_destroy(struct rwlock *lock)
{
    /*
    printf("rwlock_destroy %p\n", lock);
    pthread_mutex_destroy(&lock->read_lock);
    pthread_mutex_destroy(&lock->write_lock);
    printf("rwlock_destroy done!\n");*/
}

// Converts a POSIX error code to a CloudABI error code.
static __wasi_errno_t
convert_errno(int error)
{
    static const __wasi_errno_t errors[] = {
#define X(v) [v] = __WASI_##v
        X(E2BIG),
        X(EACCES),
        X(EADDRINUSE),
        X(EADDRNOTAVAIL),
        X(EAFNOSUPPORT),
        X(EAGAIN),
        X(EALREADY),
        X(EBADF),
        X(EBADMSG),
        X(EBUSY),
        X(ECANCELED),
        X(ECHILD),
        X(ECONNABORTED),
        X(ECONNREFUSED),
        X(ECONNRESET),
        X(EDEADLK),
        X(EDESTADDRREQ),
        X(EDOM),
        X(EEXIST),
        X(EFAULT),
        X(EFBIG),
        X(EHOSTUNREACH),
        X(EINPROGRESS),
        X(EINTR),
        X(EINVAL),
        X(EIO),
        X(EISCONN),
        X(EISDIR),
        X(ELOOP),
        X(EMFILE),
        X(EMLINK),
        X(EMSGSIZE),
        X(ENAMETOOLONG),
        X(ENETDOWN),
        X(ENETRESET),
        X(ENETUNREACH),
        X(ENFILE),
        X(ENOBUFS),
        X(ENODEV),
        X(ENOENT),
        X(ENOEXEC),
        X(ENOLCK),
        X(ENOMEM),
        X(ENOMSG),
        X(ENOPROTOOPT),
        X(ENOSPC),
        X(ENOSYS),
#ifdef ENOTCAPABLE
        X(ENOTCAPABLE),
#endif
        X(ENOTCONN),
        X(ENOTDIR),
        X(ENOTEMPTY),
        X(ENOTSOCK),
        X(ENOTSUP),
        X(ENOTTY),
        X(ENXIO),
        X(EPERM),
        X(EPIPE),
        X(EPROTO),
        X(EPROTONOSUPPORT),
        X(EPROTOTYPE),
        X(ERANGE),
        X(EROFS),
        X(ESPIPE),
        X(ESRCH),
        X(ETIMEDOUT),
        X(ETXTBSY),
        X(EXDEV),
#undef X
#if EOPNOTSUPP != ENOTSUP
        [EOPNOTSUPP] = __WASI_ENOTSUP,
#endif
#if EWOULDBLOCK != EAGAIN
        [EWOULDBLOCK] = __WASI_EAGAIN,
#endif
    };
    if (error < 0 || (size_t)error >= sizeof(errors) / sizeof(errors[0])
        || errors[error] == 0)
        return __WASI_ENOSYS;
    return errors[error];
}

// Converts a POSIX timespec to a CloudABI timestamp.
static __wasi_timestamp_t
convert_timespec(const struct timespec *ts)
{
    if (ts->tv_sec < 0)
        return 0;
    if ((__wasi_timestamp_t)ts->tv_sec >= UINT64_MAX / 1000000000)
        return UINT64_MAX;
    return (__wasi_timestamp_t)ts->tv_sec * 1000000000
           + (__wasi_timestamp_t)ts->tv_nsec;
}

// Converts a CloudABI clock identifier to a POSIX clock identifier.
static bool
convert_clockid(__wasi_clockid_t in, clockid_t *out)
{
    switch (in) {
        case __WASI_CLOCK_MONOTONIC:
            *out = CLOCK_MONOTONIC;
            return true;
#if defined(CLOCK_PROCESS_CPUTIME_ID)
        case __WASI_CLOCK_PROCESS_CPUTIME_ID:
            *out = CLOCK_PROCESS_CPUTIME_ID;
            return true;
#endif
        case __WASI_CLOCK_REALTIME:
            *out = CLOCK_REALTIME;
            return true;
#if defined(CLOCK_THREAD_CPUTIME_ID)
        case __WASI_CLOCK_THREAD_CPUTIME_ID:
            *out = CLOCK_THREAD_CPUTIME_ID;
            return true;
#endif
        default:
            return false;
    }
}

__wasi_errno_t
wasmtime_ssp_clock_time_get(__wasi_clockid_t clock_id,
                            __wasi_timestamp_t precision,
                            __wasi_timestamp_t *time)
{
    clockid_t nclock_id;
    if (!convert_clockid(clock_id, &nclock_id))
        return __WASI_EINVAL;
    struct timespec ts;
    if (clock_gettime(nclock_id, &ts) < 0)
        return convert_errno(errno);
    *time = convert_timespec(&ts);
    return 0;
}

struct fd_prestat {
    const char *dir;
};

bool
fd_prestats_init(struct fd_prestats *pt)
{
    if (!rwlock_init(&pt->lock))
        return false;
    pt->prestats = NULL;
    pt->size = 0;
    pt->used = 0;
#if defined(WASMTIME_SSP_STATIC_CURFDS)
    prestats = pt;
#endif
    return true;
}

// Looks up a preopened resource table entry by number.
static __wasi_errno_t
fd_prestats_get_entry(struct fd_prestats *pt, __wasi_fd_t fd,
                      struct fd_prestat **ret) REQUIRES_SHARED(pt->lock)
{
    // Test for file descriptor existence.
    if (fd >= pt->size)
        return __WASI_EBADF;
    struct fd_prestat *prestat = &pt->prestats[fd];
    if (prestat->dir == NULL)
        return __WASI_EBADF;

    *ret = prestat;
    return 0;
}

struct fd_object {
    struct refcount refcount;
    __wasi_filetype_t type;
    int number;

    union {
        // Data associated with directory file descriptors.
        struct {
            struct mutex lock;         // Lock to protect members below.
            DIR *handle;               // Directory handle.
            __wasi_dircookie_t offset; // Offset of the directory.
        } directory;
    };
};

struct fd_entry {
    struct fd_object *object;
    __wasi_rights_t rights_base;
    __wasi_rights_t rights_inheriting;
};

bool
fd_table_init(struct fd_table *ft)
{
    if (!rwlock_init(&ft->lock))
        return false;
    ft->entries = NULL;
    ft->size = 0;
    ft->used = 0;
#if defined(WASMTIME_SSP_STATIC_CURFDS)
    curfds = ft;
#endif
    return true;
}

// Looks up a file descriptor table entry by number and required rights.
static __wasi_errno_t
fd_table_get_entry(struct fd_table *ft, __wasi_fd_t fd,
                   __wasi_rights_t rights_base,
                   __wasi_rights_t rights_inheriting, struct fd_entry **ret)
    REQUIRES_SHARED(ft->lock)
{
    // Test for file descriptor existence.
    if (fd >= ft->size)
        return __WASI_EBADF;
    struct fd_entry *fe = &ft->entries[fd];
    if (fe->object == NULL)
        return __WASI_EBADF;

    // Validate rights.
    if ((~fe->rights_base & rights_base) != 0
        || (~fe->rights_inheriting & rights_inheriting) != 0)
        return __WASI_ENOTCAPABLE;
    *ret = fe;
    return 0;
}

// Grows the file descriptor table to a required lower bound and a
// minimum number of free file descriptor table entries.
static bool
fd_table_grow(struct fd_table *ft, size_t min, size_t incr)
    REQUIRES_EXCLUSIVE(ft->lock)
{
    printf("fd_table_grow 1 ft->size %ld\n", ft->size);
    printf("min %ld incr %ld\n", min, incr);
    if (ft->size <= min || ft->size < (ft->used + incr) * 2) {
        // Keep on doubling the table size until we've met our constraints.
        size_t size = ft->size == 0 ? 1 : ft->size;
        printf("fd_table_grow 2 size %ld\n", size);
        while (size <= min || size < (ft->used + incr) * 2)
            size *= 2;

        printf("fd_table_grow 3 size %ld\n", size);
        // Grow the file descriptor table's allocation.
        struct fd_entry *entries =
            wasm_runtime_malloc((uint32)(sizeof(*entries) * size));
        if (entries == NULL)
            return false;

        if (ft->entries && ft->size > 0) {
            bh_memcpy_s(entries, (uint32)(sizeof(*entries) * size), ft->entries,
                        (uint32)(sizeof(*entries) * ft->size));
        }

        if (ft->entries)
            wasm_runtime_free(ft->entries);

        // Mark all new file descriptors as unused.
        for (size_t i = ft->size; i < size; ++i)
            entries[i].object = NULL;
        ft->entries = entries;
        ft->size = size;
    }
    printf("fd_table_grow 4 size %ld\n", ft->size);
    return true;
}

// Allocates a new file descriptor object.
static __wasi_errno_t
fd_object_new(__wasi_filetype_t type, struct fd_object **fo)
    TRYLOCKS_SHARED(0, (*fo)->refcount)
{
    *fo = wasm_runtime_malloc(sizeof(**fo));
    if (*fo == NULL)
        return __WASI_ENOMEM;
    refcount_init(&(*fo)->refcount, 1);
    (*fo)->type = type;
    (*fo)->number = -1;
    return 0;
}

// Attaches a file descriptor to the file descriptor table.
static void
fd_table_attach(struct fd_table *ft, __wasi_fd_t fd, struct fd_object *fo,
                __wasi_rights_t rights_base, __wasi_rights_t rights_inheriting)
    REQUIRES_EXCLUSIVE(ft->lock) CONSUMES(fo->refcount)
{
    printf("ft->size %ld\n", ft->size);
    printf("fd %d\n", fd);
    assert(ft->size > fd && "File descriptor table too small");
    struct fd_entry *fe = &ft->entries[fd];
    printf("fe->object %p\n", fe->object);
    assert(fe->object == NULL
           && "Attempted to overwrite an existing descriptor");
    fe->object = fo;
    fe->rights_base = rights_base;
    fe->rights_inheriting = rights_inheriting;
    ++ft->used;
    printf("ft->used %ld\n", ft->used);
    assert(ft->size >= ft->used * 2 && "File descriptor too full");
}

// Detaches a file descriptor from the file descriptor table.
static void
fd_table_detach(struct fd_table *ft, __wasi_fd_t fd, struct fd_object **fo)
    REQUIRES_EXCLUSIVE(ft->lock) PRODUCES((*fo)->refcount)
{
    assert(ft->size > fd && "File descriptor table too small");
    struct fd_entry *fe = &ft->entries[fd];
    *fo = fe->object;
    assert(*fo != NULL && "Attempted to detach nonexistent descriptor");
    fe->object = NULL;
    assert(ft->used > 0 && "Reference count mismatch");
    --ft->used;
}

// Determines the type of a file descriptor and its maximum set of
// rights that should be attached to it.
static __wasi_errno_t
fd_determine_type_rights(int fd, __wasi_filetype_t *type,
                         __wasi_rights_t *rights_base,
                         __wasi_rights_t *rights_inheriting)
{
        *type = __WASI_FILETYPE_CHARACTER_DEVICE;
        *rights_base = RIGHTS_TTY_BASE;
        *rights_inheriting = RIGHTS_TTY_INHERITING;
        return 0;
}

// Returns the underlying file descriptor number of a file descriptor
// object. This function can only be applied to objects that have an
// underlying file descriptor number.
static int
fd_number(const struct fd_object *fo)
{
    int number = fo->number;
    assert(number >= 0 && "fd_number() called on virtual file descriptor");
    return number;
}

#define CLOSE_NON_STD_FD(fd) \
    do {                     \
        if (fd > 2)          \
            close(fd);       \
    } while (0)

// Lowers the reference count on a file descriptor object. When the
// reference count reaches zero, its resources are cleaned up.
static void
fd_object_release(struct fd_object *fo) UNLOCKS(fo->refcount)
{
    if (refcount_release(&fo->refcount)) {
        switch (fo->type) {
            case __WASI_FILETYPE_DIRECTORY:
                // For directories we may keep track of a DIR object. Calling
                // closedir() on it also closes the underlying file descriptor.
                mutex_destroy(&fo->directory.lock);
                if (fo->directory.handle == NULL) {
                    CLOSE_NON_STD_FD(fd_number(fo));
                }
                else {
                    closedir(fo->directory.handle);
                }
                break;
            default:
                CLOSE_NON_STD_FD(fd_number(fo));
                break;
        }
        wasm_runtime_free(fo);
    }
}

// Inserts an already existing file descriptor into the file descriptor
// table.
bool
fd_table_insert_existing(struct fd_table *ft, __wasi_fd_t in, int out)
{
    printf("ft->size 1 %ld\n", ft->size);
    __wasi_filetype_t type;
    __wasi_rights_t rights_base, rights_inheriting;
    struct fd_object *fo;
    __wasi_errno_t error;

    if (fd_determine_type_rights(out, &type, &rights_base, &rights_inheriting)
        != 0)
        return false;

    error = fd_object_new(type, &fo);
    if (error != 0)
        return false;
    fo->number = out;
    if (type == __WASI_FILETYPE_DIRECTORY) {
        if (!mutex_init(&fo->directory.lock)) {
            fd_object_release(fo);
            return false;
        }
        fo->directory.handle = NULL;
    }

    printf("fd_table_insert_existing 1\n");
    // Grow the file descriptor table if needed.
    printf("ft->size 2 %ld\n", ft->size);
    rwlock_wrlock(&ft->lock);
    printf("ft->size 3 %ld\n", ft->size);
    printf("fd_table_insert_existing 2\n");
    if (!fd_table_grow(ft, in, 1)) {
        printf("ft->size 4 %ld\n", ft->size);
        rwlock_unlock(&ft->lock);
        printf("ft->size 5 %ld\n", ft->size);
        fd_object_release(fo);
        return false;
    }
    printf("fd_table_insert_existing 3\n");
    printf("ft->size 6 %ld\n", ft->size);
    fd_table_attach(ft, in, fo, rights_base, rights_inheriting);
    printf("ft->size 7 %ld\n", ft->size);
    printf("fd_table_insert_existing 4\n");
    rwlock_unlock(&ft->lock);
    printf("fd_table_insert_existing 5\n");
    return true;
}

__wasi_errno_t
wasmtime_ssp_fd_close(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds, struct fd_prestats *prestats,
#endif
    __wasi_fd_t fd)
{
    // Don't allow closing a pre-opened resource.
    // TODO: Eventually, we do want to permit this, once libpreopen in
    // userspace is capable of removing entries from its tables as well.
    {
        rwlock_rdlock(&prestats->lock);
        struct fd_prestat *prestat;
        __wasi_errno_t error = fd_prestats_get_entry(prestats, fd, &prestat);
        rwlock_unlock(&prestats->lock);
        if (error == 0) {
            return __WASI_ENOTSUP;
        }
    }

    // Validate the file descriptor.
    struct fd_table *ft = curfds;
    rwlock_wrlock(&ft->lock);
    struct fd_entry *fe;
    __wasi_errno_t error = fd_table_get_entry(ft, fd, 0, 0, &fe);
    if (error != 0) {
        rwlock_unlock(&ft->lock);
        return error;
    }

    // Remove it from the file descriptor table.
    struct fd_object *fo;
    fd_table_detach(ft, fd, &fo);
    rwlock_unlock(&ft->lock);
    fd_object_release(fo);
    return 0;
}

// Look up a file descriptor object in a locked file descriptor table
// and increases its reference count.
static __wasi_errno_t
fd_object_get_locked(struct fd_object **fo, struct fd_table *ft, __wasi_fd_t fd,
                     __wasi_rights_t rights_base,
                     __wasi_rights_t rights_inheriting)
    TRYLOCKS_EXCLUSIVE(0, (*fo)->refcount) REQUIRES_EXCLUSIVE(ft->lock)
{
    // Test whether the file descriptor number is valid.
    struct fd_entry *fe;
    __wasi_errno_t error =
        fd_table_get_entry(ft, fd, rights_base, rights_inheriting, &fe);
    if (error != 0)
        return error;

    // Increase the reference count on the file descriptor object. A copy
    // of the rights are also stored, so callers can still access those if
    // needed.
    *fo = fe->object;
    refcount_acquire(&(*fo)->refcount);
    return 0;
}

// Temporarily locks the file descriptor table to look up a file
// descriptor object, increases its reference count and drops the lock.
static __wasi_errno_t
fd_object_get(struct fd_table *curfds, struct fd_object **fo, __wasi_fd_t fd,
              __wasi_rights_t rights_base, __wasi_rights_t rights_inheriting)
    TRYLOCKS_EXCLUSIVE(0, (*fo)->refcount)
{
    struct fd_table *ft = curfds;
    rwlock_rdlock(&ft->lock);
    __wasi_errno_t error =
        fd_object_get_locked(fo, ft, fd, rights_base, rights_inheriting);
    rwlock_unlock(&ft->lock);
    return error;
}

__wasi_errno_t
wasmtime_ssp_fd_seek(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_filedelta_t offset, __wasi_whence_t whence,
    __wasi_filesize_t *newoffset)
{
    int nwhence;
    switch (whence) {
        case __WASI_WHENCE_CUR:
            nwhence = SEEK_CUR;
            break;
        case __WASI_WHENCE_END:
            nwhence = SEEK_END;
            break;
        case __WASI_WHENCE_SET:
            nwhence = SEEK_SET;
            break;
        default:
            return __WASI_EINVAL;
    }

    struct fd_object *fo;
    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd,
                      offset == 0 && whence == __WASI_WHENCE_CUR
                          ? __WASI_RIGHT_FD_TELL
                          : __WASI_RIGHT_FD_SEEK | __WASI_RIGHT_FD_TELL,
                      0);
    if (error != 0)
        return error;

    off_t ret = lseek(fd_number(fo), offset, nwhence);
    fd_object_release(fo);
    if (ret < 0)
        return convert_errno(errno);
    *newoffset = (__wasi_filesize_t)ret;
    return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_fdstat_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_fdstat_t *buf)
{
    struct fd_table *ft = curfds;
    rwlock_rdlock(&ft->lock);
    struct fd_entry *fe;
    __wasi_errno_t error = fd_table_get_entry(ft, fd, 0, 0, &fe);
    if (error != 0) {
        rwlock_unlock(&ft->lock);
        return error;
    }

    // Extract file descriptor type and rights.
    struct fd_object *fo = fe->object;
    *buf = (__wasi_fdstat_t){
        .fs_filetype = fo->type,
        .fs_rights_base = fe->rights_base,
        .fs_rights_inheriting = fe->rights_inheriting,
    };

    // Fetch file descriptor flags.
    int ret;
    switch (fo->type) {
        default:
            ret = fcntl(fd_number(fo), F_GETFL, 0);
            break;
    }
    rwlock_unlock(&ft->lock);
    if (ret < 0)
        return convert_errno(errno);

    if ((ret & O_APPEND) != 0)
        buf->fs_flags |= __WASI_FDFLAG_APPEND;
#ifdef O_DSYNC
    if ((ret & O_DSYNC) != 0)
        buf->fs_flags |= __WASI_FDFLAG_DSYNC;
#endif
    if ((ret & O_NONBLOCK) != 0)
        buf->fs_flags |= __WASI_FDFLAG_NONBLOCK;
#ifdef O_RSYNC
    if ((ret & O_RSYNC) != 0)
        buf->fs_flags |= __WASI_FDFLAG_RSYNC;
#endif
    if ((ret & O_SYNC) != 0)
        buf->fs_flags |= __WASI_FDFLAG_SYNC;
    return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_write(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, const __wasi_ciovec_t *iov, size_t iovcnt, size_t *nwritten)
{
    struct fd_object *fo;
    //__wasi_errno_t error =
    //    fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_WRITE, 0);
    //if (error != 0)
    //    return error;

#if 0
    ssize_t len = writev(fd_number(fo), (const struct iovec *)iov, (int)iovcnt);
#else
    ssize_t len = 0;
    /* redirect stdout/stderr output to BH_VPRINTF function */
    //if (fd_number(fo) == 1 || fd_number(fo) == 2) {
        int i;
        const struct iovec *iov1 = (const struct iovec *)iov;

        for (i = 0; i < (int)iovcnt; i++, iov1++) {
            if (iov1->iov_len > 0 && iov1->iov_base) {
                char* str = iov1->iov_base;
                len += iov1->iov_len;
                if (str[iov1->iov_len] != '\0') {
                    str[iov1->iov_len] = '\0';
                }
                puts(iov1->iov_base);
                //char format[16];

                /* make up format string "%.ns" */
                //snprintf(format, sizeof(format), "%%.%ds", (int)iov1->iov_len);
                //len += (ssize_t)os_printf(format, iov1->iov_base);
            }
        }
    //}
    //else {
    //    len = writev(fd_number(fo), (const struct iovec *)iov, (int)iovcnt);
    //}
#endif /* end of BH_VPRINTF */
    //fd_object_release(fo);
    if (len < 0)
        return convert_errno(errno);
    *nwritten = (size_t)len;
    return 0;
}

__wasi_errno_t
wasmtime_ssp_sched_yield(void)
{
    if (sched_yield() < 0)
        return convert_errno(errno);
    return 0;
}

__wasi_errno_t
wasmtime_ssp_args_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct argv_environ_values *argv_environ,
#endif
    char **argv, char *argv_buf)
{
    for (size_t i = 0; i < argv_environ->argc; ++i) {
        argv[i] =
            argv_buf + (argv_environ->argv_list[i] - argv_environ->argv_buf);
    }
    argv[argv_environ->argc] = NULL;
    bh_memcpy_s(argv_buf, (uint32)argv_environ->argv_buf_size,
                argv_environ->argv_buf, (uint32)argv_environ->argv_buf_size);
    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_args_sizes_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct argv_environ_values *argv_environ,
#endif
    size_t *argc, size_t *argv_buf_size)
{
    *argc = argv_environ->argc;
    *argv_buf_size = argv_environ->argv_buf_size;
    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_environ_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct argv_environ_values *argv_environ,
#endif
    char **environ, char *environ_buf)
{
    for (size_t i = 0; i < argv_environ->environ_count; ++i) {
        environ[i] =
            environ_buf
            + (argv_environ->environ_list[i] - argv_environ->environ_buf);
    }
    environ[argv_environ->environ_count] = NULL;
    bh_memcpy_s(environ_buf, (uint32)argv_environ->environ_buf_size,
                argv_environ->environ_buf,
                (uint32)argv_environ->environ_buf_size);
    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_environ_sizes_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct argv_environ_values *argv_environ,
#endif
    size_t *environ_count, size_t *environ_buf_size)
{
    *environ_count = argv_environ->environ_count;
    *environ_buf_size = argv_environ->environ_buf_size;
    return __WASI_ESUCCESS;
}

bool
argv_environ_init(struct argv_environ_values *argv_environ, char *argv_buf,
                  size_t argv_buf_size, char **argv_list, size_t argc,
                  char *environ_buf, size_t environ_buf_size,
                  char **environ_list, size_t environ_count)
{
    memset(argv_environ, 0, sizeof(struct argv_environ_values));

    argv_environ->argv_buf = argv_buf;
    argv_environ->argv_buf_size = argv_buf_size;
    argv_environ->argv_list = argv_list;
    argv_environ->argc = argc;
    argv_environ->environ_buf = environ_buf;
    argv_environ->environ_buf_size = environ_buf_size;
    argv_environ->environ_list = environ_list;
    argv_environ->environ_count = environ_count;
    return true;
}

void
argv_environ_destroy(struct argv_environ_values *argv_environ)
{}

void
fd_table_destroy(struct fd_table *ft)
{
    if (ft->entries) {
        for (uint32 i = 0; i < ft->size; i++) {
            if (ft->entries[i].object != NULL) {
                fd_object_release(ft->entries[i].object);
            }
        }
        rwlock_destroy(&ft->lock);
        wasm_runtime_free(ft->entries);
    }
}

void
fd_prestats_destroy(struct fd_prestats *pt)
{
    if (pt->prestats) {
        for (uint32 i = 0; i < pt->size; i++) {
            if (pt->prestats[i].dir != NULL) {
                wasm_runtime_free((void *)pt->prestats[i].dir);
            }
        }
        rwlock_destroy(&pt->lock);
        wasm_runtime_free(pt->prestats);
    }
}
