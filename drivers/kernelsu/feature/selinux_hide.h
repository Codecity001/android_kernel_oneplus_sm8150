#ifndef __KSU_H_SELINUX_HIDE
#define __KSU_H_SELINUX_HIDE

#include <linux/types.h>

int sepol_expected_argc(u32 cmd);

void ksu_selinux_hide_init();
void ksu_selinux_hide_exit();
void ksu_selinux_hide_handle_second_stage();
void ksu_selinux_hide_handle_post_fs_data();

// fork: tracked from selinux/rules.c applied sepolicy cmds
void ksu_selinux_hide_add_type(const char *name);
void ksu_selinux_hide_add_rule(const char *src, const char *tgt);

// fork: LSM setprocattr hook entry (hook/lsm_hooks.c)
int ksu_hide_setprocattr(const char *name, void *value, size_t size);

#endif
