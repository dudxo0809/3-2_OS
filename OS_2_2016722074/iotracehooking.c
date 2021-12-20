#include "ftracehooking.h"
#include <uapi/linux/string.h>

#define __NR_read 0
#define __NR_write 1
#define __NR_open 2
#define __NR_close 3
#define __NR_lseek 8

#define FILENAME "abc.txt"

extern int ft_opencnt;
extern int ft_readcnt;
extern int ft_writecnt;
extern int ft_lseekcnt;
extern int ft_closecnt;

void **syscall_table;
  
void *real_open;


asmlinkage long (*original_read)(const struct pt_regs*);
asmlinkage long ftrace_read(const struct pt_regs* regs){

	char __user *filename = (char*)regs->di;
	char user_filename[256] = {0};
	long copied = strncpy_from_user(user_filename, filename, sizeof(user_filename));
	

	if(strcmp(user_filename, FILENAME) == 0){
		ft_readcnt++;
	}
	return (*original_read)(regs);
}

asmlinkage long (*original_write)(const struct pt_regs*);
asmlinkage long ftrace_write(const struct pt_regs* regs){

	char __user *filename = (char*)regs->di;
	char user_filename[256] = {0};
	long copied = strncpy_from_user(user_filename, filename, sizeof(user_filename));

	if(strcmp(user_filename, FILENAME) == 0){
		ft_writecnt++;
	}
	return (*original_write)(regs);
}

asmlinkage long (*original_open)(const struct pt_regs*);
asmlinkage long ftrace_open(const struct pt_regs* regs){

	//ft_opencnt++;
	//printk("new_open!!!\n");

	char __user *filename = (char*)regs->di;
	char user_filename[256] = {0};
	long copied = strncpy_from_user(user_filename, filename, sizeof(user_filename));

	if(strcmp(user_filename, FILENAME) == 0){
		ft_opencnt++;
		//printk("abc has open\n");
	}

	return (*original_open)(regs);
}

asmlinkage long (*original_close)(const struct pt_regs*);
asmlinkage long ftrace_close(const struct pt_regs* regs){

	char __user *filename = (char*)regs->di;
	char user_filename[256] = {0};
	long copied = strncpy_from_user(user_filename, filename, sizeof(user_filename));

	if(strcmp(user_filename, FILENAME) == 0){
		ft_closecnt++;
	}
	return (*original_close)(regs);
}

asmlinkage long (*original_lseek)(const struct pt_regs*);
asmlinkage long ftrace_lseek(const struct pt_regs* regs){

	char __user *filename = (char*)regs->di;
	char user_filename[256] = {0};
	long copied = strncpy_from_user(user_filename, filename, sizeof(user_filename));

	if(strcmp(user_filename, FILENAME) == 0){
		ft_lseekcnt++;
	}
	return (*original_lseek)(regs);
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

	syscall_table = (void**)kallsyms_lookup_name("sys_call_table");

	make_rw(syscall_table);

	original_open = syscall_table[__NR_open];
	original_read = syscall_table[__NR_read];
	original_write = syscall_table[__NR_write];
	original_close = syscall_table[__NR_close];
	original_lseek = syscall_table[__NR_lseek];

	syscall_table[__NR_open] = ftrace_open;
	syscall_table[__NR_read] = ftrace_read;
	syscall_table[__NR_write] = ftrace_write;
	syscall_table[__NR_close] = ftrace_close;
	syscall_table[__NR_lseek] = ftrace_lseek;

	return 0;
}


static void __exit hooking_exit(void){

	syscall_table[__NR_open] = original_open;
	syscall_table[__NR_read] = original_read;
	syscall_table[__NR_write] = original_write;
	syscall_table[__NR_close] = original_close;
	syscall_table[__NR_lseek] = original_lseek;

	make_ro(syscall_table);

}

module_init(hooking_init);
module_exit(hooking_exit);
MODULE_LICENSE("GPL");
