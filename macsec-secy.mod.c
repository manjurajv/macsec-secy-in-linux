#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
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
	{ 0x135dd1a3, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x77bbacbb, __VMLINUX_SYMBOL_STR(eth_header_parse) },
	{ 0x540ffd46, __VMLINUX_SYMBOL_STR(eth_validate_addr) },
	{ 0xca64687f, __VMLINUX_SYMBOL_STR(eth_mac_addr) },
	{ 0xb6b46a7c, __VMLINUX_SYMBOL_STR(param_ops_int) },
	{ 0xe0f63f5b, __VMLINUX_SYMBOL_STR(rtnl_link_unregister) },
	{ 0x6e720ff2, __VMLINUX_SYMBOL_STR(rtnl_unlock) },
	{ 0xa1c76e0a, __VMLINUX_SYMBOL_STR(_cond_resched) },
	{ 0x9d0d0bfb, __VMLINUX_SYMBOL_STR(register_netdevice) },
	{ 0x894bd6bc, __VMLINUX_SYMBOL_STR(alloc_netdev_mqs) },
	{ 0xd7efc9f9, __VMLINUX_SYMBOL_STR(__rtnl_link_unregister) },
	{ 0x8896fff8, __VMLINUX_SYMBOL_STR(__rtnl_link_register) },
	{ 0xc7a4fbed, __VMLINUX_SYMBOL_STR(rtnl_lock) },
	{ 0xbfcaa532, __VMLINUX_SYMBOL_STR(___pskb_trim) },
	{ 0x6ea69cf6, __VMLINUX_SYMBOL_STR(skb_pull) },
	{ 0x8b881dc9, __VMLINUX_SYMBOL_STR(__pskb_pull_tail) },
	{ 0x5d48a5c2, __VMLINUX_SYMBOL_STR(dev_queue_xmit) },
	{ 0x7d11c268, __VMLINUX_SYMBOL_STR(jiffies) },
	{ 0xe3be3980, __VMLINUX_SYMBOL_STR(skb_put) },
	{ 0x8235805b, __VMLINUX_SYMBOL_STR(memmove) },
	{ 0x16305289, __VMLINUX_SYMBOL_STR(warn_slowpath_null) },
	{ 0x9c99e24b, __VMLINUX_SYMBOL_STR(skb_push) },
	{ 0xc897c382, __VMLINUX_SYMBOL_STR(sg_init_table) },
	{ 0xb6244511, __VMLINUX_SYMBOL_STR(sg_init_one) },
	{ 0x12da5bb2, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0x5267c7e4, __VMLINUX_SYMBOL_STR(crypto_aead_setauthsize) },
	{ 0x1b550694, __VMLINUX_SYMBOL_STR(crypto_alloc_aead) },
	{ 0x79aa04a2, __VMLINUX_SYMBOL_STR(get_random_bytes) },
	{ 0x434da38b, __VMLINUX_SYMBOL_STR(netdev_rx_handler_register) },
	{ 0x8e80f6f6, __VMLINUX_SYMBOL_STR(free_netdev) },
	{ 0xee7b34d3, __VMLINUX_SYMBOL_STR(ether_setup) },
	{ 0xf217ed6a, __VMLINUX_SYMBOL_STR(mem_map) },
	{ 0x50c89f23, __VMLINUX_SYMBOL_STR(__alloc_percpu) },
	{ 0xf6098949, __VMLINUX_SYMBOL_STR(netdev_rx_handler_unregister) },
	{ 0xc9ec4e21, __VMLINUX_SYMBOL_STR(free_percpu) },
	{ 0x7ecb001b, __VMLINUX_SYMBOL_STR(__per_cpu_offset) },
	{ 0xfe7c4287, __VMLINUX_SYMBOL_STR(nr_cpu_ids) },
	{ 0xc0a3d105, __VMLINUX_SYMBOL_STR(find_next_bit) },
	{ 0x579fbcd2, __VMLINUX_SYMBOL_STR(cpu_possible_mask) },
	{ 0x60f6e9a3, __VMLINUX_SYMBOL_STR(netif_carrier_on) },
	{ 0xadbf7058, __VMLINUX_SYMBOL_STR(netif_carrier_off) },
	{ 0xf0fdf6cb, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0x55168fd9, __VMLINUX_SYMBOL_STR(__dev_get_by_name) },
	{ 0x4f6b400b, __VMLINUX_SYMBOL_STR(_copy_from_user) },
	{ 0xc6cbbc89, __VMLINUX_SYMBOL_STR(capable) },
	{ 0x4f8b5ddb, __VMLINUX_SYMBOL_STR(_copy_to_user) },
	{ 0xb6ed1e53, __VMLINUX_SYMBOL_STR(strncpy) },
	{ 0x50eedeb8, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xb4390f9a, __VMLINUX_SYMBOL_STR(mcount) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "4D085518E5A0D5901FFBC51");
