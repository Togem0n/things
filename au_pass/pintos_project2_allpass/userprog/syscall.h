#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

#define NOT_LOADED 0
#define LOAD_SUCCESS 1
#define LOAD_FAIL 2

#define USER_VADDR_BOTTOM ((void *) 0x08048000)
#define STACK_HEURISTIC 32

#define CLOSE_ALL -1
#define ERROR -1
//File structre
struct file_struct
{
	struct file* file; //file pointer
	int file_desc;     //file discriptor
	struct list_elem elem;
};


struct lock file_lock;
void syscall_init (void);

#endif /* userprog/syscall.h */
