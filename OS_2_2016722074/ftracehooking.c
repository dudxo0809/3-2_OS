#include "ftracehooking.h"

#define __NR_ftrace 336

void **syscall_table;

void *real_ftrace;

int ft_opencnt = 0;
int ft_readcnt = 0;
int ft_writecnt = 0;
int ft_lseekcnt = 0;
int ft_closecnt = 0;

EXPORT_SYMBOL(ft_opencnt);
EXPORT_SYMBOL(ft_readcnt);
EXPORT_SYMBOL(ft_writecnt);
EXPORT_SYMBOL(ft_lseekcnt);
EXPORT_SYMBOL(ft_closecnt);
/*
__SYSCALL_DEFINEx(1, ftrace, pid_t, pid){

	int ret;

	printk("hook start\n");
	ret = (real_ftrace)(pid);
	printk("hook end\n");

	return 777;
}
*/

asmlinkage int (*original_ftrace)(const struct pt_regs*);
asmlinkage int new_ftrace(const struct pt_regs* regs){
	
	int ret = 0;
	//printk("hook! \n");
	//printk("open cnt : %d\n", ft_opencnt);
	
	printk("OS Assignment2 ftrace [%d] Start\n", current->pid);
	printk("[2016722074] /%s file[abc.txt] stats [x] read - %d / written - %d\n",current->comm ,1 , 1);
	printk("open[%d]  close[%d]  read[%d]  write[%d]  lseek[%d]\n", ft_opencnt, ft_closecnt, ft_readcnt, ft_writecnt, ft_lseekcnt);
	printk("OS Assignment2 ftrace [%d] End\n", current->pid);

	//ret = (*original_ftrace)(regs);

	return ret;
}


void make_rw(void *addr){

	unsigned int level;
	pte_t *pte = lookup_address((u64)addr, &level);

	if(pte->pte &~ _PAGE_RW)
		pte->pte |= _PAGE_RW;
}

void make_ro(void *addr){

	unsigned int level;
	pte_t *pte = lookup_address((u64)addr, &level);

	pte->pte = pte->pte &~ _PAGE_RW;
}

static int __init hooking_init(void){

	syscall_table = (void**) kallsyms_lookup_name("sys_call_table");

	make_rw(syscall_table);

	//real_ftrace = syscall_table[__NR_ftrace];
	original_ftrace = syscall_table[__NR_ftrace];	

	//syscall_table[__NR_ftrace] = __x64_sysftrace;
	syscall_table[__NR_ftrace] = new_ftrace;

	return 0;
}

static void __exit hooking_exit(void){

	//syscall_table[__NR_ftrace] = real_ftrace;
	syscall_table[__NR_ftrace] = original_ftrace;

	make_ro(syscall_table);
}


module_init(hooking_init);
module_exit(hooking_exit);
MODULE_LICENSE("GPL");

