// SPDX-License-Identifier: GPL-2.0
/* rwsem.c: R/W semaphores: contention handling functions
 *
 * Written by David Howells (dhowells@redhat.com).
 * Derived from arch/i386/kernel/semaphore.c
 *
 * Writer lock-stealing by Alex Shi <alex.shi@intel.com>
 * and Michel Lespinasse <walken@google.com>
 *
 * Optimistic spinning by Tim Chen <tim.c.chen@intel.com>
 * and Davidlohr Bueso <davidlohr@hp.com>. Based on mutexes.
 *
 * Count-field handoff rework adapted from upstream rwsem handoff support.
 */
#include <linux/rwsem.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/sched/task.h>
#include <linux/sched/rt.h>
#include <linux/sched/wake_q.h>
#include <linux/sched/signal.h>
#include <linux/sched/debug.h>
#include <linux/sched/clock.h>
#include <linux/osq_lock.h>

#include "rwsem.h"

void __init_rwsem(struct rw_semaphore *sem, const char *name,
		  struct lock_class_key *key)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	debug_check_no_locks_freed((void *)sem, sizeof(*sem));
	lockdep_init_map(&sem->dep_map, name, key, 0);
#endif
	atomic_long_set(&sem->count, RWSEM_UNLOCKED_VALUE);
	raw_spin_lock_init(&sem->wait_lock);
	INIT_LIST_HEAD(&sem->wait_list);
#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
	sem->owner = NULL;
	osq_lock_init(&sem->osq);
#endif
}
EXPORT_SYMBOL(__init_rwsem);

static void rwsem_mark_wake(struct rw_semaphore *sem,
			    enum rwsem_wake_type wake_type,
			    struct wake_q_head *wake_q)
{
	struct rwsem_waiter *waiter, *tmp;
	long oldcount, woken = 0, adjustment = 0;
	struct list_head wlist;

	lockdep_assert_held(&sem->wait_lock);

	waiter = rwsem_first_waiter(sem);

	if (waiter->type == RWSEM_WAITING_FOR_WRITE) {
		if (wake_type == RWSEM_WAKE_ANY)
			wake_q_add(wake_q, waiter->task);
		return;
	}

	if (unlikely(atomic_long_read(&sem->count) < 0))
		return;

	if (wake_type != RWSEM_WAKE_READ_OWNED) {
		struct task_struct *owner;

		adjustment = RWSEM_READER_BIAS;
		oldcount = atomic_long_fetch_add(adjustment, &sem->count);
		if (unlikely(oldcount & RWSEM_WRITER_MASK)) {
			if (!(oldcount & RWSEM_FLAG_HANDOFF) &&
			    time_after(jiffies, waiter->timeout))
				adjustment -= RWSEM_FLAG_HANDOFF;

			atomic_long_add(-adjustment, &sem->count);
			return;
		}

		owner = waiter->task;
#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
		if (waiter->last_rowner & RWSEM_RD_NONSPINNABLE)
			owner = (void *)((unsigned long)owner |
					 RWSEM_RD_NONSPINNABLE);
#endif
		__rwsem_set_reader_owned(sem, owner);
	}

	INIT_LIST_HEAD(&wlist);
	list_for_each_entry_safe(waiter, tmp, &sem->wait_list, list) {
		if (waiter->type == RWSEM_WAITING_FOR_WRITE)
			continue;

		woken++;
		list_move_tail(&waiter->list, &wlist);
		if (woken >= MAX_READERS_WAKEUP)
			break;
	}

	adjustment = woken * RWSEM_READER_BIAS - adjustment;
	if (list_empty(&sem->wait_list))
		adjustment -= RWSEM_FLAG_WAITERS;

	if (woken && (atomic_long_read(&sem->count) & RWSEM_FLAG_HANDOFF))
		adjustment -= RWSEM_FLAG_HANDOFF;

	if (adjustment)
		atomic_long_add(adjustment, &sem->count);

	list_for_each_entry_safe(waiter, tmp, &wlist, list) {
		struct task_struct *tsk;

		tsk = waiter->task;
		get_task_struct(tsk);
		smp_store_release(&waiter->task, NULL);
		wake_q_add(wake_q, tsk);
		put_task_struct(tsk);
	}
}

static inline bool rwsem_try_write_lock(struct rw_semaphore *sem,
					enum writer_wait_state wstate)
{
	long count, new, old;

	lockdep_assert_held(&sem->wait_lock);

	count = atomic_long_read(&sem->count);
	for (;;) {
		bool has_handoff = !!(count & RWSEM_FLAG_HANDOFF);

		if (has_handoff && wstate == WRITER_NOT_FIRST)
			return false;

		new = count;
		if (count & RWSEM_LOCK_MASK) {
			if (has_handoff || (wstate != WRITER_HANDOFF))
				return false;
			new |= RWSEM_FLAG_HANDOFF;
		} else {
			new |= RWSEM_WRITER_LOCKED;
			new &= ~RWSEM_FLAG_HANDOFF;

			if (list_is_singular(&sem->wait_list))
				new &= ~RWSEM_FLAG_WAITERS;
		}

		old = atomic_long_cmpxchg_acquire(&sem->count, count, new);
		if (old == count)
			break;
		count = old;
	}

	if (new & RWSEM_FLAG_HANDOFF)
		return false;

	rwsem_set_owner(sem);
	return true;
}

#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
static inline bool rwsem_try_read_lock_unqueued(struct rw_semaphore *sem)
{
	long count = atomic_long_read(&sem->count);

	if (count & (RWSEM_WRITER_MASK | RWSEM_FLAG_HANDOFF))
		return false;

	count = atomic_long_fetch_add_acquire(RWSEM_READER_BIAS, &sem->count);
	if (!(count & (RWSEM_WRITER_MASK | RWSEM_FLAG_HANDOFF))) {
		rwsem_set_reader_owned(sem);
		return true;
	}

	atomic_long_add(-RWSEM_READER_BIAS, &sem->count);
	return false;
}

static inline bool rwsem_try_write_lock_unqueued(struct rw_semaphore *sem)
{
	long count = atomic_long_read(&sem->count);
	long old;

	while (!(count & (RWSEM_LOCK_MASK | RWSEM_FLAG_HANDOFF))) {
		old = atomic_long_cmpxchg_acquire(&sem->count, count,
						  count | RWSEM_WRITER_LOCKED);
		if (old == count) {
			rwsem_set_owner(sem);
			return true;
		}
		count = old;
	}
	return false;
}

static inline bool owner_on_cpu(struct task_struct *owner)
{
	return owner->on_cpu && !vcpu_is_preempted(task_cpu(owner));
}

static inline bool rwsem_can_spin_on_owner(struct rw_semaphore *sem,
					   unsigned long nonspinnable)
{
	struct task_struct *owner;
	unsigned long flags;
	bool ret = true;

	BUILD_BUG_ON(!((unsigned long)RWSEM_OWNER_UNKNOWN &
		      RWSEM_NONSPINNABLE));

	if (need_resched())
		return false;

	preempt_disable();
	rcu_read_lock();
	owner = rwsem_owner_flags(sem, &flags);
	if ((flags & nonspinnable) ||
	    (owner && !(flags & RWSEM_READER_OWNED) && !owner_on_cpu(owner)))
		ret = false;
	rcu_read_unlock();
	preempt_enable();

	return ret;
}

enum owner_state {
	OWNER_NULL		= 1 << 0,
	OWNER_WRITER		= 1 << 1,
	OWNER_READER		= 1 << 2,
	OWNER_NONSPINNABLE	= 1 << 3,
};
#define OWNER_SPINNABLE		(OWNER_NULL | OWNER_WRITER | OWNER_READER)

static inline enum owner_state
rwsem_owner_state(struct task_struct *owner, unsigned long flags,
		  unsigned long nonspinnable)
{
	if (flags & nonspinnable)
		return OWNER_NONSPINNABLE;
	if (flags & RWSEM_READER_OWNED)
		return OWNER_READER;
	return owner ? OWNER_WRITER : OWNER_NULL;
}

static noinline enum owner_state
rwsem_spin_on_owner(struct rw_semaphore *sem, unsigned long nonspinnable)
{
	struct task_struct *new, *owner;
	unsigned long flags, new_flags;
	enum owner_state state;

	owner = rwsem_owner_flags(sem, &flags);
	state = rwsem_owner_state(owner, flags, nonspinnable);
	if (state != OWNER_WRITER)
		return state;

	rcu_read_lock();
	for (;;) {
		new = rwsem_owner_flags(sem, &new_flags);
		if ((new != owner) || (new_flags != flags)) {
			state = rwsem_owner_state(new, new_flags,
						  nonspinnable);
			break;
		}

		barrier();

		if (need_resched() || !owner_on_cpu(owner)) {
			state = OWNER_NONSPINNABLE;
			break;
		}

		cpu_relax();
	}
	rcu_read_unlock();

	return state;
}

static inline u64 rwsem_rspin_threshold(struct rw_semaphore *sem)
{
	long count = atomic_long_read(&sem->count);
	int readers = count >> RWSEM_READER_SHIFT;
	u64 delta;

	if (readers > 30)
		readers = 30;
	delta = (20 + readers) * NSEC_PER_USEC / 2;

	return sched_clock() + delta;
}

static bool rwsem_optimistic_spin(struct rw_semaphore *sem, bool wlock)
{
	bool taken = false;
	int prev_owner_state = OWNER_NULL;
	int loop = 0;
	u64 rspin_threshold = 0;
	unsigned long nonspinnable = wlock ? RWSEM_WR_NONSPINNABLE
					   : RWSEM_RD_NONSPINNABLE;

	preempt_disable();

	if (!osq_lock(&sem->osq))
		goto done;

	for (;;) {
		enum owner_state owner_state;

		owner_state = rwsem_spin_on_owner(sem, nonspinnable);
		if (!(owner_state & OWNER_SPINNABLE))
			break;

		taken = wlock ? rwsem_try_write_lock_unqueued(sem)
			      : rwsem_try_read_lock_unqueued(sem);
		if (taken)
			break;

		if (wlock && (owner_state == OWNER_READER)) {
			if (prev_owner_state != OWNER_READER) {
				if (rwsem_test_oflags(sem, nonspinnable))
					break;
				rspin_threshold = rwsem_rspin_threshold(sem);
				loop = 0;
			} else if (!(++loop & 0xf) &&
				   (sched_clock() > rspin_threshold)) {
				rwsem_set_nonspinnable(sem);
				break;
			}
		}

		if (owner_state != OWNER_WRITER) {
			if (need_resched())
				break;
			if (rt_task(current) &&
			    (prev_owner_state != OWNER_WRITER))
				break;
		}
		prev_owner_state = owner_state;
		cpu_relax();
	}
	osq_unlock(&sem->osq);
done:
	preempt_enable();
	return taken;
}

static inline void clear_wr_nonspinnable(struct rw_semaphore *sem)
{
	unsigned long owner = (unsigned long)READ_ONCE(sem->owner);

	while (owner & RWSEM_WR_NONSPINNABLE) {
		if (rwsem_cmpxchg_owner(sem, &owner,
					owner & ~RWSEM_WR_NONSPINNABLE))
			break;
	}
}

static inline bool rwsem_reader_phase_trylock(struct rw_semaphore *sem,
					      unsigned long last_rowner)
{
	unsigned long owner = (unsigned long)READ_ONCE(sem->owner);

	if (!(owner & RWSEM_READER_OWNED))
		return false;

	if (((owner ^ last_rowner) & ~RWSEM_OWNER_FLAGS_MASK) &&
	    rwsem_try_read_lock_unqueued(sem))
		return true;
	return false;
}
#else
static inline bool rwsem_can_spin_on_owner(struct rw_semaphore *sem,
					   unsigned long nonspinnable)
{
	return false;
}

static inline bool rwsem_optimistic_spin(struct rw_semaphore *sem, bool wlock)
{
	return false;
}

static inline void clear_wr_nonspinnable(struct rw_semaphore *sem) { }

static inline bool rwsem_reader_phase_trylock(struct rw_semaphore *sem,
					      unsigned long last_rowner)
{
	return false;
}

static inline int
rwsem_spin_on_owner(struct rw_semaphore *sem, unsigned long nonspinnable)
{
	return 0;
}
#define OWNER_NULL	1
#endif

static struct rw_semaphore *
rwsem_down_read_slowpath(struct rw_semaphore *sem, int state)
{
	long count, adjustment = -RWSEM_READER_BIAS;
	struct rwsem_waiter waiter;
	DEFINE_WAKE_Q(wake_q);
	bool wake = false;

#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
	waiter.last_rowner = (unsigned long)READ_ONCE(sem->owner);
	if (!(waiter.last_rowner & RWSEM_READER_OWNED))
		waiter.last_rowner &= RWSEM_RD_NONSPINNABLE;

	if (!rwsem_can_spin_on_owner(sem, RWSEM_RD_NONSPINNABLE))
		goto queue;

	atomic_long_add(-RWSEM_READER_BIAS, &sem->count);
	adjustment = 0;
	if (rwsem_optimistic_spin(sem, false)) {
		if (atomic_long_read(&sem->count) & RWSEM_FLAG_WAITERS) {
			raw_spin_lock_irq(&sem->wait_lock);
			if (!list_empty(&sem->wait_list))
				rwsem_mark_wake(sem, RWSEM_WAKE_READ_OWNED,
						&wake_q);
			raw_spin_unlock_irq(&sem->wait_lock);
			wake_up_q(&wake_q);
		}
		return sem;
	} else if (rwsem_reader_phase_trylock(sem, waiter.last_rowner)) {
		return sem;
	}
#endif

queue:
	waiter.task = current;
	waiter.type = RWSEM_WAITING_FOR_READ;
	waiter.timeout = jiffies + RWSEM_WAIT_TIMEOUT;

	raw_spin_lock_irq(&sem->wait_lock);
	if (list_empty(&sem->wait_list)) {
		if (adjustment && !(atomic_long_read(&sem->count) &
		    (RWSEM_WRITER_MASK | RWSEM_FLAG_HANDOFF))) {
			smp_acquire__after_ctrl_dep();
			raw_spin_unlock_irq(&sem->wait_lock);
			rwsem_set_reader_owned(sem);
			return sem;
		}
		adjustment += RWSEM_FLAG_WAITERS;
	}
	list_add_tail(&waiter.list, &sem->wait_list);

	if (adjustment)
		count = atomic_long_add_return(adjustment, &sem->count);
	else
		count = atomic_long_read(&sem->count);

	if (!(count & RWSEM_LOCK_MASK)) {
		clear_wr_nonspinnable(sem);
		wake = true;
	}
	if (wake || (!(count & RWSEM_WRITER_MASK) &&
		     (adjustment & RWSEM_FLAG_WAITERS)))
		rwsem_mark_wake(sem, RWSEM_WAKE_ANY, &wake_q);

	raw_spin_unlock_irq(&sem->wait_lock);
	wake_up_q(&wake_q);

	for (;;) {
		set_current_state(state);
		if (!smp_load_acquire(&waiter.task))
			break;
		if (signal_pending_state(state, current)) {
			raw_spin_lock_irq(&sem->wait_lock);
			if (waiter.task)
				goto out_nolock;
			raw_spin_unlock_irq(&sem->wait_lock);
			break;
		}
		schedule();
	}

	__set_current_state(TASK_RUNNING);
	return sem;

out_nolock:
	list_del(&waiter.list);
	if (list_empty(&sem->wait_list)) {
		atomic_long_andnot(RWSEM_FLAG_WAITERS | RWSEM_FLAG_HANDOFF,
				   &sem->count);
	}
	raw_spin_unlock_irq(&sem->wait_lock);
	__set_current_state(TASK_RUNNING);
	return ERR_PTR(-EINTR);
}

static inline void rwsem_disable_reader_optspin(struct rw_semaphore *sem,
						bool disable)
{
#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
	if (unlikely(disable))
		WRITE_ONCE(sem->owner, (struct task_struct *)
			((unsigned long)READ_ONCE(sem->owner) |
			 RWSEM_RD_NONSPINNABLE));
#endif
}

static struct rw_semaphore *
rwsem_down_write_slowpath(struct rw_semaphore *sem, int state)
{
	bool disable_rspin;
	enum writer_wait_state wstate;
	struct rwsem_waiter waiter;
	struct rw_semaphore *ret = sem;
	DEFINE_WAKE_Q(wake_q);

#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
	if (rwsem_can_spin_on_owner(sem, RWSEM_WR_NONSPINNABLE) &&
	    rwsem_optimistic_spin(sem, true))
		return sem;

	disable_rspin = rwsem_test_oflags(sem, RWSEM_NONSPINNABLE);
#else
	disable_rspin = false;
#endif

	waiter.task = current;
	waiter.type = RWSEM_WAITING_FOR_WRITE;
	waiter.timeout = jiffies + RWSEM_WAIT_TIMEOUT;

	raw_spin_lock_irq(&sem->wait_lock);

	wstate = list_empty(&sem->wait_list) ? WRITER_FIRST : WRITER_NOT_FIRST;
	list_add_tail(&waiter.list, &sem->wait_list);

	if (wstate == WRITER_NOT_FIRST) {
		long count = atomic_long_read(&sem->count);

		if (!(count & RWSEM_WRITER_MASK))
			rwsem_mark_wake(sem, (count & RWSEM_READER_MASK) ?
					RWSEM_WAKE_READERS :
					RWSEM_WAKE_ANY, &wake_q);

		if (wake_q.first != WAKE_Q_TAIL) {
			raw_spin_unlock_irq(&sem->wait_lock);
			wake_up_q(&wake_q);
			wake_q_init(&wake_q);
			raw_spin_lock_irq(&sem->wait_lock);
		}
	} else {
		atomic_long_or(RWSEM_FLAG_WAITERS, &sem->count);
	}

	set_current_state(state);
	for (;;) {
		if (rwsem_try_write_lock(sem, wstate))
			break;

		raw_spin_unlock_irq(&sem->wait_lock);

		if (wstate == WRITER_HANDOFF &&
		    rwsem_spin_on_owner(sem, RWSEM_NONSPINNABLE) ==
		    OWNER_NULL)
			goto trylock_again;

		for (;;) {
			long count;

			if (signal_pending_state(state, current))
				goto out_nolock;

			schedule();
			set_current_state(state);

			if (wstate == WRITER_HANDOFF)
				break;

			if ((wstate == WRITER_NOT_FIRST) &&
			    (rwsem_first_waiter(sem) == &waiter))
				wstate = WRITER_FIRST;

			count = atomic_long_read(&sem->count);
			if (!(count & RWSEM_LOCK_MASK))
				break;

			if ((wstate == WRITER_FIRST) &&
			    (rt_task(current) ||
			     time_after(jiffies, waiter.timeout))) {
				wstate = WRITER_HANDOFF;
				break;
			}
		}
trylock_again:
		raw_spin_lock_irq(&sem->wait_lock);
	}
	__set_current_state(TASK_RUNNING);
	list_del(&waiter.list);
	rwsem_disable_reader_optspin(sem, disable_rspin);
	raw_spin_unlock_irq(&sem->wait_lock);

	return ret;

out_nolock:
	__set_current_state(TASK_RUNNING);
	raw_spin_lock_irq(&sem->wait_lock);
	list_del(&waiter.list);

	if (unlikely(wstate == WRITER_HANDOFF))
		atomic_long_andnot(RWSEM_FLAG_HANDOFF, &sem->count);

	if (list_empty(&sem->wait_list))
		atomic_long_andnot(RWSEM_FLAG_WAITERS, &sem->count);
	else
		rwsem_mark_wake(sem, RWSEM_WAKE_ANY, &wake_q);
	raw_spin_unlock_irq(&sem->wait_lock);
	wake_up_q(&wake_q);

	return ERR_PTR(-EINTR);
}

static struct rw_semaphore *rwsem_handoff_wake(struct rw_semaphore *sem,
					       long count)
{
	unsigned long flags;
	DEFINE_WAKE_Q(wake_q);

	(void)count;

	raw_spin_lock_irqsave(&sem->wait_lock, flags);
	if (!list_empty(&sem->wait_list))
		rwsem_mark_wake(sem, RWSEM_WAKE_ANY, &wake_q);
	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
	wake_up_q(&wake_q);

	return sem;
}

static struct rw_semaphore *rwsem_handoff_downgrade_wake(struct rw_semaphore *sem)
{
	unsigned long flags;
	DEFINE_WAKE_Q(wake_q);

	raw_spin_lock_irqsave(&sem->wait_lock, flags);
	if (!list_empty(&sem->wait_list))
		rwsem_mark_wake(sem, RWSEM_WAKE_READ_OWNED, &wake_q);
	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
	wake_up_q(&wake_q);

	return sem;
}

void __down_read(struct rw_semaphore *sem)
{
	if (!rwsem_read_trylock(sem)) {
		rwsem_down_read_slowpath(sem, TASK_UNINTERRUPTIBLE);
	} else {
		rwsem_set_reader_owned(sem);
	}
}

int __down_read_killable(struct rw_semaphore *sem)
{
	if (!rwsem_read_trylock(sem)) {
		if (IS_ERR(rwsem_down_read_slowpath(sem, TASK_KILLABLE)))
			return -EINTR;
	} else {
		rwsem_set_reader_owned(sem);
	}
	return 0;
}

int __down_read_trylock(struct rw_semaphore *sem)
{
	long tmp = RWSEM_UNLOCKED_VALUE;

	do {
		if (atomic_long_cmpxchg_acquire(&sem->count, tmp,
						tmp + RWSEM_READER_BIAS) ==
		    tmp) {
			rwsem_set_reader_owned(sem);
			return 1;
		}
		tmp = atomic_long_read(&sem->count);
	} while (!(tmp & RWSEM_READ_FAILED_MASK));
	return 0;
}

void __down_write(struct rw_semaphore *sem)
{
	long tmp = RWSEM_UNLOCKED_VALUE;

	if (unlikely(atomic_long_cmpxchg_acquire(&sem->count, tmp,
						 RWSEM_WRITER_LOCKED) != tmp))
		rwsem_down_write_slowpath(sem, TASK_UNINTERRUPTIBLE);
	else
		rwsem_set_owner(sem);
}

int __down_write_killable(struct rw_semaphore *sem)
{
	long tmp = RWSEM_UNLOCKED_VALUE;

	if (unlikely(atomic_long_cmpxchg_acquire(&sem->count, tmp,
						 RWSEM_WRITER_LOCKED) != tmp)) {
		if (IS_ERR(rwsem_down_write_slowpath(sem, TASK_KILLABLE)))
			return -EINTR;
	} else {
		rwsem_set_owner(sem);
	}
	return 0;
}

int __down_write_trylock(struct rw_semaphore *sem)
{
	long tmp = RWSEM_UNLOCKED_VALUE;

	if (atomic_long_cmpxchg_acquire(&sem->count, tmp,
					RWSEM_WRITER_LOCKED) == tmp) {
		rwsem_set_owner(sem);
		return 1;
	}
	return 0;
}

void __up_read(struct rw_semaphore *sem)
{
	long tmp;

	rwsem_clear_reader_owned(sem);
	tmp = atomic_long_add_return_release(-RWSEM_READER_BIAS, &sem->count);
	if (unlikely((tmp & (RWSEM_LOCK_MASK | RWSEM_FLAG_WAITERS)) ==
		     RWSEM_FLAG_WAITERS)) {
		clear_wr_nonspinnable(sem);
		rwsem_handoff_wake(sem, tmp);
	}
}

void __up_write(struct rw_semaphore *sem)
{
	long tmp;

	rwsem_clear_owner(sem);
	tmp = atomic_long_fetch_add_release(-RWSEM_WRITER_LOCKED, &sem->count);
	if (unlikely(tmp & RWSEM_FLAG_WAITERS))
		rwsem_handoff_wake(sem, tmp);
}

void __downgrade_write(struct rw_semaphore *sem)
{
	long tmp;

	tmp = atomic_long_fetch_add_release(-RWSEM_WRITER_LOCKED +
					    RWSEM_READER_BIAS,
					    &sem->count);
	rwsem_set_reader_owned(sem);
	if (tmp & RWSEM_FLAG_WAITERS)
		rwsem_handoff_downgrade_wake(sem);
}

#if BITS_PER_LONG == 64
#define RWSEM_COMPAT_ACTIVE_MASK	0xffffffffL
#else
#define RWSEM_COMPAT_ACTIVE_MASK	0x0000ffffL
#endif

#define RWSEM_COMPAT_WAITING_BIAS	(-RWSEM_COMPAT_ACTIVE_MASK - 1)
#define RWSEM_COMPAT_ACTIVE_READ_BIAS	1L
#define RWSEM_COMPAT_ACTIVE_WRITE_BIAS	(RWSEM_COMPAT_WAITING_BIAS + 1L)

static void rwsem_compat_mark_wake(struct rw_semaphore *sem,
				   enum rwsem_wake_type wake_type,
				   struct wake_q_head *wake_q)
{
	struct rwsem_waiter *waiter, *tmp;
	long oldcount, woken = 0, adjustment = 0;
	struct list_head wlist;

	lockdep_assert_held(&sem->wait_lock);

	waiter = rwsem_first_waiter(sem);

	if (waiter->type == RWSEM_WAITING_FOR_WRITE) {
		if (wake_type == RWSEM_WAKE_ANY)
			wake_q_add(wake_q, waiter->task);
		return;
	}

	if (wake_type != RWSEM_WAKE_READ_OWNED) {
		adjustment = RWSEM_COMPAT_ACTIVE_READ_BIAS;
try_reader_grant:
		oldcount = atomic_long_fetch_add(adjustment, &sem->count);
		if (unlikely(oldcount < RWSEM_COMPAT_WAITING_BIAS)) {
			if (atomic_long_add_return(-adjustment, &sem->count) <
			    RWSEM_COMPAT_WAITING_BIAS)
				return;
			goto try_reader_grant;
		}
		rwsem_set_reader_owned(sem);
	}

	INIT_LIST_HEAD(&wlist);
	list_for_each_entry_safe(waiter, tmp, &sem->wait_list, list) {
		if (waiter->type == RWSEM_WAITING_FOR_WRITE)
			break;

		woken++;
		list_move_tail(&waiter->list, &wlist);
	}

	adjustment = woken * RWSEM_COMPAT_ACTIVE_READ_BIAS - adjustment;
	if (list_empty(&sem->wait_list))
		adjustment -= RWSEM_COMPAT_WAITING_BIAS;

	if (adjustment)
		atomic_long_add(adjustment, &sem->count);

	list_for_each_entry_safe(waiter, tmp, &wlist, list) {
		struct task_struct *tsk;

		tsk = waiter->task;
		get_task_struct(tsk);
		smp_store_release(&waiter->task, NULL);
		wake_q_add(wake_q, tsk);
		put_task_struct(tsk);
	}
}

static struct rw_semaphore *
rwsem_compat_down_read_failed_common(struct rw_semaphore *sem, int state)
{
	long count, adjustment = -RWSEM_COMPAT_ACTIVE_READ_BIAS;
	struct rwsem_waiter waiter;
	DEFINE_WAKE_Q(wake_q);
	bool is_first_waiter;

	waiter.task = current;
	waiter.type = RWSEM_WAITING_FOR_READ;

	raw_spin_lock_irq(&sem->wait_lock);
	is_first_waiter = list_empty(&sem->wait_list);
	if (is_first_waiter)
		adjustment += RWSEM_COMPAT_WAITING_BIAS;
	list_add_tail(&waiter.list, &sem->wait_list);

	count = atomic_long_add_return(adjustment, &sem->count);
	if (count == RWSEM_COMPAT_WAITING_BIAS ||
	    (count > RWSEM_COMPAT_WAITING_BIAS &&
	     (adjustment != -RWSEM_COMPAT_ACTIVE_READ_BIAS ||
	      is_first_waiter)))
		rwsem_compat_mark_wake(sem, RWSEM_WAKE_ANY, &wake_q);

	raw_spin_unlock_irq(&sem->wait_lock);
	wake_up_q(&wake_q);

	for (;;) {
		set_current_state(state);
		if (!waiter.task)
			break;
		if (signal_pending_state(state, current)) {
			raw_spin_lock_irq(&sem->wait_lock);
			if (waiter.task)
				goto out_nolock;
			raw_spin_unlock_irq(&sem->wait_lock);
			break;
		}
		schedule();
	}

	__set_current_state(TASK_RUNNING);
	return sem;

out_nolock:
	list_del(&waiter.list);
	if (list_empty(&sem->wait_list))
		atomic_long_add(-RWSEM_COMPAT_WAITING_BIAS, &sem->count);
	raw_spin_unlock_irq(&sem->wait_lock);
	__set_current_state(TASK_RUNNING);
	return ERR_PTR(-EINTR);
}

__visible struct rw_semaphore * __sched
rwsem_down_read_failed(struct rw_semaphore *sem)
{
	return rwsem_compat_down_read_failed_common(sem, TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(rwsem_down_read_failed);

__visible struct rw_semaphore * __sched
rwsem_down_read_failed_killable(struct rw_semaphore *sem)
{
	return rwsem_compat_down_read_failed_common(sem, TASK_KILLABLE);
}
EXPORT_SYMBOL(rwsem_down_read_failed_killable);

static inline bool rwsem_compat_try_write_lock(long count,
					       struct rw_semaphore *sem)
{
	if (count != RWSEM_COMPAT_WAITING_BIAS)
		return false;

	count = list_is_singular(&sem->wait_list) ?
		RWSEM_COMPAT_ACTIVE_WRITE_BIAS :
		RWSEM_COMPAT_ACTIVE_WRITE_BIAS + RWSEM_COMPAT_WAITING_BIAS;

	if (atomic_long_cmpxchg_acquire(&sem->count, RWSEM_COMPAT_WAITING_BIAS,
					count) == RWSEM_COMPAT_WAITING_BIAS) {
		rwsem_set_owner(sem);
		return true;
	}

	return false;
}

static struct rw_semaphore *
rwsem_compat_down_write_failed_common(struct rw_semaphore *sem, int state)
{
	long count;
	bool waiting = true;
	bool is_first_waiter;
	struct rwsem_waiter waiter;
	struct rw_semaphore *ret = sem;
	DEFINE_WAKE_Q(wake_q);

	count = atomic_long_sub_return(RWSEM_COMPAT_ACTIVE_WRITE_BIAS, &sem->count);

	waiter.task = current;
	waiter.type = RWSEM_WAITING_FOR_WRITE;

	raw_spin_lock_irq(&sem->wait_lock);

	if (list_empty(&sem->wait_list))
		waiting = false;
	is_first_waiter = !waiting;
	list_add_tail(&waiter.list, &sem->wait_list);

	if (waiting) {
		count = atomic_long_read(&sem->count);
		if (!is_first_waiter && count > RWSEM_COMPAT_WAITING_BIAS) {
			rwsem_compat_mark_wake(sem, RWSEM_WAKE_READERS, &wake_q);
			wake_up_q(&wake_q);
			wake_q_init(&wake_q);
		}
	} else {
		count = atomic_long_add_return(RWSEM_COMPAT_WAITING_BIAS,
					       &sem->count);
	}

	set_current_state(state);
	for (;;) {
		if (rwsem_compat_try_write_lock(count, sem))
			break;

		raw_spin_unlock_irq(&sem->wait_lock);

		do {
			if (signal_pending_state(state, current))
				goto out_write_nolock;

			schedule();
			set_current_state(state);
		} while ((count = atomic_long_read(&sem->count)) &
			 RWSEM_COMPAT_ACTIVE_MASK);

		raw_spin_lock_irq(&sem->wait_lock);
	}
	__set_current_state(TASK_RUNNING);
	list_del(&waiter.list);
	raw_spin_unlock_irq(&sem->wait_lock);

	return ret;

out_write_nolock:
	__set_current_state(TASK_RUNNING);
	raw_spin_lock_irq(&sem->wait_lock);
	list_del(&waiter.list);
	if (list_empty(&sem->wait_list))
		atomic_long_add(-RWSEM_COMPAT_WAITING_BIAS, &sem->count);
	else
		rwsem_compat_mark_wake(sem, RWSEM_WAKE_ANY, &wake_q);
	raw_spin_unlock_irq(&sem->wait_lock);
	wake_up_q(&wake_q);

	return ERR_PTR(-EINTR);
}

__visible struct rw_semaphore * __sched
rwsem_down_write_failed(struct rw_semaphore *sem)
{
	return rwsem_compat_down_write_failed_common(sem, TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(rwsem_down_write_failed);

__visible struct rw_semaphore * __sched
rwsem_down_write_failed_killable(struct rw_semaphore *sem)
{
	return rwsem_compat_down_write_failed_common(sem, TASK_KILLABLE);
}
EXPORT_SYMBOL(rwsem_down_write_failed_killable);

__visible struct rw_semaphore *rwsem_wake(struct rw_semaphore *sem)
{
	unsigned long flags;
	DEFINE_WAKE_Q(wake_q);

	raw_spin_lock_irqsave(&sem->wait_lock, flags);
	if (!list_empty(&sem->wait_list))
		rwsem_compat_mark_wake(sem, RWSEM_WAKE_ANY, &wake_q);
	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
	wake_up_q(&wake_q);

	return sem;
}
EXPORT_SYMBOL(rwsem_wake);

__visible struct rw_semaphore *rwsem_downgrade_wake(struct rw_semaphore *sem)
{
	unsigned long flags;
	DEFINE_WAKE_Q(wake_q);

	raw_spin_lock_irqsave(&sem->wait_lock, flags);
	if (!list_empty(&sem->wait_list))
		rwsem_compat_mark_wake(sem, RWSEM_WAKE_READ_OWNED, &wake_q);
	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
	wake_up_q(&wake_q);

	return sem;
}
EXPORT_SYMBOL(rwsem_downgrade_wake);
