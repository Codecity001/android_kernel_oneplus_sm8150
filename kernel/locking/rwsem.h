/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __INTERNAL_RWSEM_H
#define __INTERNAL_RWSEM_H

#include <linux/jiffies.h>
#include <linux/rwsem.h>

/*
 * The least significant owner bits are defined in <linux/rwsem.h> so helper
 * users outside kernel/locking/ can preserve the nonspinnable state when they
 * transfer lock ownership without dropping the underlying rwsem.
 */

/*
 * On 64-bit architectures, the bit definitions of count are:
 *
 * Bit  0    - writer locked bit
 * Bit  1    - waiters present bit
 * Bit  2    - handoff bit
 * Bits 3-7  - reserved
 * Bits 8-62 - reader count
 * Bit  63   - read fail bit
 */
#define RWSEM_WRITER_LOCKED	(1UL << 0)
#define RWSEM_FLAG_WAITERS	(1UL << 1)
#define RWSEM_FLAG_HANDOFF	(1UL << 2)
#define RWSEM_FLAG_READFAIL	(1UL << (BITS_PER_LONG - 1))

#define RWSEM_READER_SHIFT	8
#define RWSEM_READER_BIAS	(1UL << RWSEM_READER_SHIFT)
#define RWSEM_READER_MASK	(~(RWSEM_READER_BIAS - 1))
#define RWSEM_WRITER_MASK	RWSEM_WRITER_LOCKED
#define RWSEM_LOCK_MASK		(RWSEM_WRITER_MASK | RWSEM_READER_MASK)
#define RWSEM_READ_FAILED_MASK	(RWSEM_WRITER_MASK | RWSEM_FLAG_WAITERS | \
				 RWSEM_FLAG_HANDOFF | RWSEM_FLAG_READFAIL)

#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
static inline void rwsem_set_owner(struct rw_semaphore *sem)
{
	WRITE_ONCE(sem->owner, current);
}

static inline void rwsem_clear_owner(struct rw_semaphore *sem)
{
	WRITE_ONCE(sem->owner, NULL);
}

static inline bool rwsem_cmpxchg_owner(struct rw_semaphore *sem,
				       unsigned long *old, unsigned long new)
{
	unsigned long prev;

	prev = cmpxchg((unsigned long *)&sem->owner, *old, new);
	if (prev == *old)
		return true;

	*old = prev;
	return false;
}

static inline bool rwsem_test_oflags(struct rw_semaphore *sem,
				     unsigned long flags)
{
	return ((unsigned long)READ_ONCE(sem->owner)) & flags;
}

static inline void __rwsem_set_reader_owned(struct rw_semaphore *sem,
					    struct task_struct *owner)
{
	unsigned long val = (unsigned long)owner | RWSEM_READER_OWNED |
		(((unsigned long)READ_ONCE(sem->owner)) &
		 RWSEM_RD_NONSPINNABLE);

	WRITE_ONCE(sem->owner, (struct task_struct *)val);
}

static inline void rwsem_set_reader_owned(struct rw_semaphore *sem)
{
	__rwsem_set_reader_owned(sem, current);
}

static inline void rwsem_clear_reader_owned(struct rw_semaphore *sem)
{
}

static inline bool is_rwsem_reader_owned(struct rw_semaphore *sem)
{
	return rwsem_test_oflags(sem, RWSEM_READER_OWNED);
}

static inline void rwsem_set_nonspinnable(struct rw_semaphore *sem)
{
	unsigned long owner = (unsigned long)READ_ONCE(sem->owner);

	do {
		if (!(owner & RWSEM_READER_OWNED))
			break;
		if (owner & RWSEM_NONSPINNABLE)
			break;
	} while (!rwsem_cmpxchg_owner(sem, &owner,
				      owner | RWSEM_NONSPINNABLE));
}

static inline bool rwsem_read_trylock(struct rw_semaphore *sem)
{
	long cnt = atomic_long_add_return_acquire(RWSEM_READER_BIAS,
						  &sem->count);

	if (WARN_ON_ONCE(cnt < 0))
		rwsem_set_nonspinnable(sem);
	return !(cnt & RWSEM_READ_FAILED_MASK);
}

static inline struct task_struct *rwsem_owner(struct rw_semaphore *sem)
{
	return (struct task_struct *)
		(((unsigned long)READ_ONCE(sem->owner)) &
		 ~RWSEM_OWNER_FLAGS_MASK);
}

static inline struct task_struct *
rwsem_owner_flags(struct rw_semaphore *sem, unsigned long *pflags)
{
	unsigned long owner = (unsigned long)READ_ONCE(sem->owner);

	*pflags = owner & RWSEM_OWNER_FLAGS_MASK;
	return (struct task_struct *)(owner & ~RWSEM_OWNER_FLAGS_MASK);
}
#else
static inline void rwsem_set_owner(struct rw_semaphore *sem)
{
}

static inline void rwsem_clear_owner(struct rw_semaphore *sem)
{
}

static inline void __rwsem_set_reader_owned(struct rw_semaphore *sem,
					    struct task_struct *owner)
{
}

static inline void rwsem_set_reader_owned(struct rw_semaphore *sem)
{
}

static inline void rwsem_clear_reader_owned(struct rw_semaphore *sem)
{
}

static inline bool is_rwsem_reader_owned(struct rw_semaphore *sem)
{
	return true;
}

static inline void rwsem_set_nonspinnable(struct rw_semaphore *sem)
{
}

static inline bool rwsem_test_oflags(struct rw_semaphore *sem,
				     unsigned long flags)
{
	return false;
}

static inline bool rwsem_read_trylock(struct rw_semaphore *sem)
{
	return !(atomic_long_add_return_acquire(RWSEM_READER_BIAS, &sem->count) &
		 RWSEM_READ_FAILED_MASK);
}

static inline struct task_struct *rwsem_owner(struct rw_semaphore *sem)
{
	return NULL;
}

static inline struct task_struct *
rwsem_owner_flags(struct rw_semaphore *sem, unsigned long *pflags)
{
	*pflags = 0;
	return NULL;
}
#endif

enum rwsem_waiter_type {
	RWSEM_WAITING_FOR_WRITE,
	RWSEM_WAITING_FOR_READ
};

/*
 * The local RWSEM_PRIO_AWARE waiter reshuffling is intentionally not
 * preserved: upstream handoff fairness depends on strict FIFO writer order.
 */
struct rwsem_waiter {
	struct list_head list;
	struct task_struct *task;
	enum rwsem_waiter_type type;
	unsigned long timeout;
	unsigned long last_rowner;
};

#define rwsem_first_waiter(sem) \
	list_first_entry(&(sem)->wait_list, struct rwsem_waiter, list)

enum rwsem_wake_type {
	RWSEM_WAKE_ANY,
	RWSEM_WAKE_READERS,
	RWSEM_WAKE_READ_OWNED
};

enum writer_wait_state {
	WRITER_NOT_FIRST,
	WRITER_FIRST,
	WRITER_HANDOFF
};

#define RWSEM_WAIT_TIMEOUT	DIV_ROUND_UP(HZ, 250)
#define MAX_READERS_WAKEUP	0x100

#endif /* __INTERNAL_RWSEM_H */
