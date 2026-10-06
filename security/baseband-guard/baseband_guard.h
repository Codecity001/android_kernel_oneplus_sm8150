#define BB_ENFORCING 1

#define bb_pr(fmt, ...)    pr_debug("baseband_guard: " fmt, ##__VA_ARGS__)
#define bb_pr_rl(fmt, ...) pr_info_ratelimited("baseband_guard: " fmt, ##__VA_ARGS__)

static const char * const allowlist_names[] = {
#ifndef CONFIG_BBG_BLOCK_BOOT
	"boot", "init_boot",
	"vendor_boot", "vendor_kernel_boot",
#endif
	"dtbo",
	"userdata", "cache", "metadata", "misc",
	"vbmeta", "vbmeta_system", "vbmeta_vendor",
#ifndef CONFIG_BBG_BLOCK_RECOVERY
	"recovery"
#endif
};
static const size_t allowlist_cnt = ARRAY_SIZE(allowlist_names);

bool is_allowed_partition_dev_resolve(dev_t dev);
