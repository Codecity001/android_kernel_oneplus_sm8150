/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_RWSEM_H
#define _ASM_GENERIC_RWSEM_H

#ifndef _LINUX_RWSEM_H
#error "Please don't include <asm/rwsem.h> directly, use <linux/rwsem.h> instead."
#endif

#ifdef __KERNEL__

#define RWSEM_UNLOCKED_VALUE	0x00000000L

extern void __down_read(struct rw_semaphore *sem);
extern int __must_check __down_read_killable(struct rw_semaphore *sem);
extern int __down_read_trylock(struct rw_semaphore *sem);
extern void __down_write(struct rw_semaphore *sem);
extern int __must_check __down_write_killable(struct rw_semaphore *sem);
extern int __down_write_trylock(struct rw_semaphore *sem);
extern void __up_read(struct rw_semaphore *sem);
extern void __up_write(struct rw_semaphore *sem);
extern void __downgrade_write(struct rw_semaphore *sem);

#endif	/* __KERNEL__ */
#endif	/* _ASM_GENERIC_RWSEM_H */
