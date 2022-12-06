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
// Copyright (c) 2016 Nuxi, https://nuxi.nl/

#ifndef LOCKING_H
#define LOCKING_H

#include "ssp_config.h"

#ifndef __has_extension
#define __has_extension(x) 0
#endif

#if __has_extension(c_thread_safety_attributes)
#define LOCK_ANNOTATE(x) __attribute__((x))
#else
#define LOCK_ANNOTATE(x)
#endif

/* Lock annotation macros. */

#define LOCKABLE LOCK_ANNOTATE(lockable)

#define LOCKS_EXCLUSIVE(...) LOCK_ANNOTATE(exclusive_lock_function(__VA_ARGS__))
#define LOCKS_SHARED(...) LOCK_ANNOTATE(shared_lock_function(__VA_ARGS__))

#define TRYLOCKS_EXCLUSIVE(...) \
    LOCK_ANNOTATE(exclusive_trylock_function(__VA_ARGS__))
#define TRYLOCKS_SHARED(...) LOCK_ANNOTATE(shared_trylock_function(__VA_ARGS__))

#define UNLOCKS(...) LOCK_ANNOTATE(unlock_function(__VA_ARGS__))

#define REQUIRES_EXCLUSIVE(...) \
    LOCK_ANNOTATE(exclusive_locks_required(__VA_ARGS__))
#define REQUIRES_SHARED(...) LOCK_ANNOTATE(shared_locks_required(__VA_ARGS__))
#define REQUIRES_UNLOCKED(...) LOCK_ANNOTATE(locks_excluded(__VA_ARGS__))

#define NO_LOCK_ANALYSIS LOCK_ANNOTATE(no_thread_safety_analysis)

/* Mutex that uses the lock annotations. */

struct LOCKABLE mutex {
    pthread_mutex_t object;
};

/* clang-format off */
#define MUTEX_INITIALIZER \
    { PTHREAD_MUTEX_INITIALIZER }
/* clang-format on */

static inline bool
mutex_init(struct mutex *lock) REQUIRES_UNLOCKED(*lock)
{
    return pthread_mutex_init(&lock->object, NULL) == 0 ? true : false;
}

static inline void
mutex_destroy(struct mutex *lock) REQUIRES_UNLOCKED(*lock)
{
    pthread_mutex_destroy(&lock->object);
}

static inline void
mutex_lock(struct mutex *lock) LOCKS_EXCLUSIVE(*lock) NO_LOCK_ANALYSIS
{
    pthread_mutex_lock(&lock->object);
}

static inline void
mutex_unlock(struct mutex *lock) UNLOCKS(*lock) NO_LOCK_ANALYSIS
{
    pthread_mutex_unlock(&lock->object);
}

struct rwlock {
    pthread_mutex_t read_lock;
    pthread_mutex_t write_lock;
    volatile int read_count;
};

bool
rwlock_init(struct rwlock *lock);

void
rwlock_rdlock(struct rwlock *lock);

void
rwlock_wrlock(struct rwlock *lock);

void
rwlock_unlock(struct rwlock *lock);

void
rwlock_destroy(struct rwlock *lock);

#endif
