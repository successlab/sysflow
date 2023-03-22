#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xe66262b4, "module_layout" },
	{ 0xd0eea172, "kmalloc_caches" },
	{ 0x5a34a45c, "__kmalloc" },
	{ 0x79aa04a2, "get_random_bytes" },
	{ 0x52760ca9, "getnstimeofday" },
	{ 0x91715312, "sprintf" },
	{ 0x3ce53499, "netlink_kernel_create" },
	{ 0xde0bdcff, "memset" },
	{ 0x9297bb87, "current_task" },
	{ 0xae003909, "s2os_save_report_func" },
	{ 0x27e1a049, "printk" },
	{ 0x42224298, "sscanf" },
	{ 0x6fad49fe, "s2os_rm_sysflow_func" },
	{ 0xd8f8d768, "netlink_kernel_release" },
	{ 0x7ec9bfbc, "strncpy" },
	{ 0xb4390f9a, "mcount" },
	{ 0x16305289, "warn_slowpath_null" },
	{ 0xa865971a, "netlink_unicast" },
	{ 0xfd037b6f, "s2os_invoke_sysflow_func" },
	{ 0xd1ef5560, "init_net" },
	{ 0x217dda13, "flex_array_get" },
	{ 0xa1bb5691, "nf_unregister_hooks" },
	{ 0x998e3990, "__alloc_skb" },
	{ 0x4a8f2f34, "netlink_broadcast" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xc2d748ea, "gStatus" },
	{ 0x4b09d48c, "kmem_cache_alloc_trace" },
	{ 0xe7722171, "flex_array_free" },
	{ 0x37a0cba, "kfree" },
	{ 0x236c8c64, "memcpy" },
	{ 0x5d022b09, "nf_register_hooks" },
	{ 0xd3dcab0b, "flex_array_alloc" },
	{ 0x89a3ed94, "s2os_save_sysflow_func" },
	{ 0x2976965c, "s2os_rm_report_func" },
	{ 0xe113bbbc, "csum_partial" },
	{ 0xbe8e575c, "skb_put" },
	{ 0x1ec4eb34, "flex_array_prealloc" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "EE2966DF34057BF3E1B10B9");
