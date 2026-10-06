#include <linux/module.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/namei.h>
#include <linux/blk_types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/mm.h>
#include <linux/dcache.h>
#include <linux/hashtable.h>

#include "kernel_compat.h"
#include "baseband_guard.h"
#include "objsec.h"
#include "security.h"

struct device_hash_node { dev_t dev; struct hlist_node h; };
DEFINE_HASHTABLE(allowed_devs, 7);

static bool allow_has(dev_t dev)
{
	struct device_hash_node *p;

	hash_for_each_possible(allowed_devs, p, h, (u64)dev)
		if (p->dev == dev) return true;
	return false;
}

static void allow_add(dev_t dev)
{
	struct device_hash_node *n;
	if (!dev || allow_has(dev)) return;
	n = kmalloc(sizeof(*n), GFP_ATOMIC);
	if (!n) return;
	n->dev = dev;
	hash_add(allowed_devs, &n->h, (u64)dev);
	bb_pr("allow-cache dev %u:%u\n", MAJOR(dev), MINOR(dev));
}

static bool is_zram_device(dev_t dev)
{
	bool is_zram = bbg_is_named_device(dev, "zram");
	if (is_zram) {
		bb_pr("zram dev %u:%u identified, whitelisting\n",
				MAJOR(dev), MINOR(dev));
	}
	return is_zram;
}

static bool reverse_allow_match_and_cache(dev_t cur)
{
	if (!cur) return false;
	if (is_zram_device(cur)) {
		allow_add(cur);
		return true;
	}
	if (is_allowed_partition_dev_resolve(cur)) {
		allow_add(cur);
		return true;
	}
	return false;
}

static const char *bbg_file_path(struct file *file, char *buf, int buflen)
{
	char *p;
	if (!file || !buf || buflen <= 0) return NULL;
	buf[0] = '\0';
	p = d_path(&file->f_path, buf, buflen);
	return IS_ERR(p) ? NULL : p;
}

static int bbg_get_cmdline(char *buf, int buflen)
{
	int n, i;
	if (!buf || buflen <= 0) return 0;
	n = get_cmdline(current, buf, buflen);
	if (n <= 0) return 0;
	for (i = 0; i < n - 1; i++) if (buf[i] == '\0') buf[i] = ' ';
	if (n < buflen) buf[n] = '\0';
	else buf[buflen - 1] = '\0';
	return n;
}

static void bbg_log_deny_detail(const char *why, struct file *file, struct inode *inode, unsigned int cmd_opt)
{
	const int PATH_BUFLEN = 256;
	const int CMD_BUFLEN  = 256;

	char *pathbuf = kmalloc(PATH_BUFLEN, GFP_ATOMIC);
	char *cmdbuf  = kmalloc(CMD_BUFLEN,  GFP_ATOMIC);

	const char *path = pathbuf ? bbg_file_path(file, pathbuf, PATH_BUFLEN) : NULL;
	dev_t dev = inode ? inode->i_rdev : 0;

	if (cmdbuf)
		bbg_get_cmdline(cmdbuf, CMD_BUFLEN);

	if (cmd_opt) {
		pr_info(
			"baseband_guard: deny %s cmd=0x%x dev=%u:%u path=%s pid=%d comm=%s argv=\"%s\"\n",
			why, cmd_opt, MAJOR(dev), MINOR(dev),
			path ? path : "?", current->pid, current->comm,
			cmdbuf ? cmdbuf : "?");
	} else {
		pr_info(
			"baseband_guard: deny %s dev=%u:%u path=%s pid=%d comm=%s argv=\"%s\"\n",
			why, MAJOR(dev), MINOR(dev),
			path ? path : "?", current->pid, current->comm,
			cmdbuf ? cmdbuf : "?");
	}

	kfree(cmdbuf);
	kfree(pathbuf);
}

static int deny(const char *why, struct file *file, struct inode *inode, unsigned int cmd_opt)
{
	bbg_log_deny_detail(why, file, inode, cmd_opt);
	bb_pr_rl("deny %s pid=%d comm=%s\n", why, current->pid, current->comm);
	if (!BB_ENFORCING) return 0;
	return -EPERM;
}

/* Stateless trust check: root-impl domains (su/ksu/magisk) are untrusted at
 * the moment of the operation; the original bprm_set_creds flag propagation
 * never fires with KSU Next, which sets the sid before exec. */
static bool current_is_untrusted_root(void)
{
	static u32 su_sid, ksu_sid, magisk_sid;
	const struct task_security_struct *tsec;

	if (!selinux_initialized(&selinux_state))
		return false;

	if (!su_sid)
		security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &su_sid);
	if (!ksu_sid)
		security_secctx_to_secid("u:r:ksu:s0", strlen("u:r:ksu:s0"), &ksu_sid);
	if (!magisk_sid)
		security_secctx_to_secid("u:r:magisk:s0", strlen("u:r:magisk:s0"), &magisk_sid);

	tsec = selinux_cred(current_cred());
	return (su_sid && tsec->sid == su_sid) ||
	       (ksu_sid && tsec->sid == ksu_sid) ||
	       (magisk_sid && tsec->sid == magisk_sid);
}

static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;

	if (likely(!current_is_untrusted_root()))
		return 0;

	if (!(mask & MAY_WRITE)) return 0;
	if (!file) return 0;

	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0;

	return deny("write to protected partition", file, inode, 0);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0)
static int bb_inode_setattr(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *iattr)
#else
static int bb_inode_setattr(struct dentry *dentry, struct iattr *iattr) 
#endif
{
	struct inode *inode;

	if (likely(!current_is_untrusted_root()))
	        return 0;
	
	inode = d_inode(dentry);

	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0;

	return deny("setattr on protected partition", 0, inode, 0);
}

static inline bool is_destructive_ioctl(unsigned int cmd)
{
	switch (cmd) {
	case BLKDISCARD:
	case BLKSECDISCARD:
	case BLKZEROOUT:
#ifdef BLKPG
	case BLKPG:
#endif
#ifdef BLKRRPART
	case BLKRRPART:
#endif
	case BLKROSET:
		return true;
	default:
		return false;
	}
}

static int bb_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode;

	if (!file) return 0;
	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	if (!is_destructive_ioctl(cmd))
		return 0;

	if (likely(!current_is_untrusted_root()))
		return 0;

	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0;

	return deny("destructive ioctl on protected partition", file, inode, cmd);
}

#ifdef BB_HAS_IOCTL_COMPAT
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
	return bb_file_ioctl(file, cmd, arg);
}
#endif

static struct security_hook_list bb_hooks[] = {
	LSM_HOOK_INIT(file_permission,      bb_file_permission),
	LSM_HOOK_INIT(file_ioctl,           bb_file_ioctl),
	LSM_HOOK_INIT(inode_setattr, 		bb_inode_setattr),

#ifdef BB_HAS_IOCTL_COMPAT
	LSM_HOOK_INIT(file_ioctl_compat,    bb_file_ioctl_compat),
#endif
};

static int __init bbg_init(void)
{
	security_add_hooks_compat(bb_hooks, ARRAY_SIZE(bb_hooks));
	pr_info("baseband_guard power by https://t.me/qdykernel\n");
	pr_info("baseband_guard repo: %s", __stringify(BBG_REPO));
	pr_info("baseband_guard version: %s", __stringify(BBG_VERSION));
	return 0;
}

/* The 4.14 ordered-LSM backport dropped security_initcall(); a device-level
 * initcall still runs before __lsm_ro_after_init sections are sealed and
 * before userspace starts, which is all hook registration needs. */
device_initcall(bbg_init);

MODULE_DESCRIPTION("protect All Block & Power by TG@qdykernel");
MODULE_AUTHOR("秋刀鱼 & https://t.me/qdykernel");
MODULE_LICENSE("GPL v2");


