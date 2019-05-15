#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/page.h"

static void syscall_handler (struct intr_frame *);
void sys_exit(int status);
/*
 * unmapped some file
 */

struct sup_page_entry*
check_valid_ptr (const void *vaddr, void* esp)
{
    if (!is_user_vaddr (vaddr) || vaddr < USER_VADDR_BOTTOM)
    {
 	sys_exit(ERROR);
    }
    bool load = false;
    struct sup_page_entry *spte = get_spte((void *)vaddr);
    if (spte)
    {
       load_page(spte);
       load = spte->is_loaded;
    }
    else if (vaddr >= esp - STACK_HEURISTIC)
    {
        load = grow_stack ((void *) vaddr);
    }
    if (!load)
    {
       sys_exit(ERROR);
    } 
    return spte;
}

void
check_valid_buffer (void *buffer, unsigned size, void *esp,
		    bool to_write)
{
   unsigned i;
   char *local_buffer = (char *)buffer;
   for (i = 0; i < size; i++)
   {
      struct sup_page_entry *spte = check_valid_ptr((const void*)local_buffer,esp);
      if (spte && to_write)
      {
	  if (!spte->writable)
	   {
 		sys_exit(ERROR);
           }
      }
	local_buffer++;
   }

}
void
check_valid_string (const void* str, void* esp)
{
    check_valid_ptr (str, esp);
    while (* (char *)str != 0)
    {
	str = (char *)str + 1;
 	check_valid_ptr (str, esp);
    }
}
void
unpin_ptr (void* vaddr)
{
  struct sup_page_entry *spte = get_spte (vaddr);
  if (spte)
  {
      spte->pinned = false;
  }
}
void
unpin_string (void* str)
{
  unpin_ptr (str);
  while (* (char *) str != 0)
  {
     str = (char *)str + 1;
     unpin_ptr (str);
  }
}

void
unpin_buffer (void* buffer, unsigned size)
{
   unsigned i;
   char* local_buffer = (char *)buffer;
   for (i = 0; i < size; i++)
   {
   	unpin_ptr (local_buffer);
  	local_buffer ++;
   }
}
void
munmap (int mapping)
{
   process_remove_mmap(mapping);
}
//struct lock file_lock; //lock for handing file sys
/*
 * Memory mapping handler:
 */
int
mmap (int fd, void *addr)
{
    struct file *old_file = process_get_file (fd);
    if (!old_file || !is_user_vaddr(addr)|| addr <USER_VADDR_BOTTOM ||
	((uint32_t)addr %PGSIZE) != 0)
    {
	return ERROR;
    } 
    struct file *file = file_reopen(old_file);
    if (!file || file_length (old_file) == 0)
    {
	return ERROR;
    }
    thread_current () ->mapid++;
    int32_t ofs= 0;
    uint32_t read_bytes = file_length (file);
    while (read_bytes > 0)
    {
	uint32_t page_read_bytes = read_bytes <PGSIZE ?read_bytes: PGSIZE;
        uint32_t page_zero_bytes = PGSIZE - page_read_bytes;
        if (!add_mmap_to_page_table(file,ofs,addr,page_read_bytes,page_zero_bytes))
        {
		munmap (thread_current() ->mapid);
		return ERROR;
         }
         read_bytes -= page_read_bytes;
	 ofs += page_read_bytes;
	 addr += PGSIZE;
    }
    return thread_current ()->mapid;

}

void
validate_page (const void *addr)
{
	void *ptr = pagedir_get_page (thread_current ()->pagedir, addr);
	if (!ptr)
	{
		sys_exit (-1);
	}

}

struct file*
get_file_handle (int file_desc)
{
	//printf("file handle 1\n");
   struct list_elem *e = list_begin (&thread_current()->files_owned_list);
   struct list_elem *next;
   while (e != list_end (&thread_current()->files_owned_list))
   {

     struct file_struct *f = list_entry (e, struct file_struct,
                                          elem);
     next = list_next(e);
     if (file_desc == f->file_desc)
       {
       //	printf("file handle 2\n");
        return f->file;
       }
     e = next;
   }
   return NULL;

}


void
syscall_init (void) 
{
	//("System call init...\n");
	lock_init (&file_lock);
  	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


//shut down os
void
sys_halt (void)
{
	shutdown_power_off();
}

//exit current thread and releases any resources acquired by it
void
sys_exit (int status)
{

	//printf("In exit...\n");
	struct thread *current = thread_current();	
	//set exit code as status
//        if (thread_alive(current->tid)){
	   current->chp->status = status; 
//         }
//	printf("%s: exit(%d)\n", current->name, status);
        current->exit_status = status;
	thread_get_child_data(current->parent, current->tid)->exit_status=current->exit_status;
	thread_exit();	 

}

void
sys_close (int file_desc)
{
	struct file_struct *file_ptr = get_file_handle (file_desc);
	if (file_ptr != NULL)
		 {
		 	if (file_desc == file_ptr->file_desc)
		 	{
		 		file_close (file_ptr->file);
		 		list_remove (&file_ptr->elem);
		 		free (file_ptr);
		 	}	
		 }
	

}

unsigned
sys_tell (int file_desc)
{
	struct file *file_ptr = get_file_handle (file_desc);
	unsigned cursor = file_tell (file_ptr);
	return cursor;
}

void
sys_seek (int file_desc, unsigned offset)
{
	lock_acquire (&file_lock);
	struct file *file_ptr = get_file_handle (file_desc); 
	file_seek (file_ptr, offset);	
	lock_release (&file_lock);
}

int
sys_read (int file_desc, char *buf, unsigned s)
{
	validate_ptr (buf);
	validate_page (buf);
	//printf("Validaion passed..\n");
     
	if (file_desc == STDIN_FILENO)
		 {
		 	//read from buffer
		 	int i;
		 	for (i = 0; i < s; i++)
		 		 {
		 		 	*(buf++) = input_getc();
		 		 	return s; 
		 		 }
		 }
        lock_acquire (&file_lock);	
	struct file* file_ptr = get_file_handle (file_desc);
	if (file_ptr == NULL)
	{
		lock_release (&file_lock);
		return -1;
	}
	//printf("Got Fd...\n");
	off_t bytes_read = file_read (file_ptr, buf, s);
	lock_release (&file_lock);
	return bytes_read;

}

int
sys_filesize (int file_desc)
{
	lock_acquire (&file_lock);	
	struct file *file_ptr = get_file_handle (file_desc);
	int file_size = file_length (file_ptr);
	lock_release (&file_lock);
	return file_size;
}

bool
sys_remove (const char *file)
{
	lock_acquire (&file_lock);
	bool status = filesys_remove (file);
	lock_release (&file_lock);
	return status;	
}

bool
sys_create (const char *file, unsigned size)
{
	if (file == NULL)
		 {
		 	sys_exit (-1);
		 }
	validate_ptr (file);
	validate_page (file);
	lock_acquire (&file_lock);
	bool status = filesys_create (file, size);
	lock_release (&file_lock);
	return status;
}

static int
sys_wait (pid_t pid)
{
	return process_wait (pid);
}

static pid_t
sys_exec (const char *input)
{
	//printf("Exec call..\n");
	validate_ptr (input);
	validate_page (input);
	pid_t pid = process_execute(input);
	struct child_process *process = get_process_for_pid (pid);
	if (process == NULL)
	 {
	 	return -1;
	 }
	
       
	
//	while (process->load == NOT_LOADED )
//		{
//		        barrier ();
//                	if (process->load == LOAD_SUCCESS)
//				break;
//		}
		
	if (process->load == LOAD_FAIL)
		 {
		 	return -1;
		 }
	return pid;	 

}

static int
sys_open (const char *file)
{
	if (file == NULL)
		 {
	//	 	printf("file null...\n");
		 	sys_exit (-1);
		 }
	validate_ptr (file);	 
	validate_page (file);	 
	lock_acquire (&file_lock);
	struct file *handle = filesys_open (file);

	if (handle == NULL)
		 {
	//	 	printf("handle null...\n");
		 	lock_release (&file_lock);
		 	//sys_exit(-1);
		 	return -1;
		 }

	struct file_struct *file_ptr = malloc (sizeof (struct file_struct));
	if (file_ptr == NULL)
		 {
		 	//Should close file here.............
	//	 	printf("no memory allocated..\n");
		 	lock_release (&file_lock);
		 	return -1;
		 }
	file_ptr->file_desc = thread_current ()->file_desc;
	//so that on opening twice it gives diff fd
	thread_current ()->file_desc++; 
	file_ptr->file = handle;
	list_push_back (&thread_current ()->files_owned_list , &file_ptr->elem);
	//check for file name with thread name for rox-* tests
	if (strcmp (file, thread_current ()->name) == 0)
	 {
	 	file_deny_write (handle);
	 }

	lock_release (&file_lock);	 


/*
	
*/
	//printf("returning %d\n", file_ptr->file_desc);
	return file_ptr->file_desc;
}


static int
sys_write (int file_desc, const void *buffer, unsigned size)
{
	//printf("write 1\n");
	validate_ptr (buffer);
	validate_page (buffer);
	if (file_desc == STDOUT_FILENO)
	 {
	 	int left = size;
	 	while (left > 128)
	 		 {
	 		 	putbuf (buffer, 128);
	 		 	buffer = (const char *)buffer + 128;
	 		 	left = left - 128;

	 		 }
	 	putbuf (buffer, left);
	 //	printf("bytes wrriten to buffer: %d\n",size );
	 	return size;
	 }

	 lock_acquire (&file_lock);
	 struct file *file_ptr = get_file_handle (file_desc);
	// printf("write 2\n");
	 //if lock doesn't acquired then return
	 if (file_ptr == NULL)
	 	 {
	 	 	lock_release (&file_lock);
	 	 	sys_exit (-1);
	 	 }
	// printf("write 3\n");	 
	 int bytes_wrriten = file_write (file_ptr, buffer, size);
	// printf("Wrriten to file bytes:%d\n",bytes_wrriten );
	 lock_release (&file_lock);
	 return bytes_wrriten;	 
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	//printf("System call handler...\n");
	//printf("%x\n", * ( int *) f->esp);
	int arg[3];  //maximum 3 args are required by a syscall

	//validates the pointer
	validate_ptr((const void *) f->esp);
	validate_page((const void *) f->esp);
	
	//added for project 3
        check_valid_ptr ((const void*)f->esp, f->esp);

	//switch for diff system calls
	switch(* ( int *) f->esp)
	{
		case SYS_HALT:
		 {
			sys_halt();
			break;
		 }
		case SYS_EXIT:
		 {
		 	get_arguments_from_stack(f, &arg[0], 1);
		 	f->eax = arg[0];
		 	sys_exit(arg[0]);
		 	break;
		 }
		case SYS_EXEC:
		 {
		 	get_arguments_from_stack(f, &arg[0], 1);
		 	f->eax = sys_exec ((const char*)arg[0]);
		 	break;
		 } 
		case SYS_WAIT:
		 {
		 	get_arguments_from_stack(f, &arg[0], 1);
		 	f->eax = sys_wait (arg[0]);
		 	break;
		 }
		case SYS_CREATE:
		 {
		 	get_arguments_from_stack(f, &arg[0], 2);
		 	check_valid_string ((const void*)arg[0], f->esp);
                        f->eax = sys_create ((const char *)arg[0], (unsigned) arg[1]);
		 	break;
		 }
		case SYS_REMOVE:
		 {
		 	get_arguments_from_stack(f, &arg[0], 1);
		        check_valid_string ((const void *)arg[0], f->esp); 
                	f->eax = sys_remove ((const char *) arg[0]);
		 	break;	
		 }
		case SYS_OPEN:
		 {
		 	get_arguments_from_stack (f, &arg[0], 1);
			check_valid_string ((const void*)arg[0], f->esp);
		 	f->eax = sys_open ((const char *)arg[0]);
		 	break;
		 }
		case SYS_FILESIZE:
		 {
		 	get_arguments_from_stack (f, &arg[0], 1);
		 	f->eax = sys_filesize (arg[0]);
		 	break;
		 } 
		case SYS_READ:
		 {
		 	get_arguments_from_stack (f, &arg[0], 3);
			check_valid_buffer ((void *)arg[1],(unsigned)arg[2], f->esp,true); 
                	f->eax = sys_read (arg[0], (void *) arg[1], (unsigned) arg[2]);
			unpin_buffer ((void *)arg[1], (unsigned)arg[2]); 
			break;
		 } 
		case SYS_WRITE:
		 {
		 	get_arguments_from_stack (f, &arg[0], 3);
		// 	printf("writing....\n");
		 	//allocate_buffer ((void *) arg[1], (unsigned) arg[2]);
			check_valid_buffer ((void *)arg[1], (unsigned)arg[2], f->esp,false);
		 	f->eax = sys_write ((int) arg[0], (const void*)arg[1],
		 						(unsigned) arg[2]);
			unpin_buffer ((void *)arg[1], (unsigned) arg[2]);
		 	break;
		 } 
		case SYS_SEEK:
		 {
		 	get_arguments_from_stack (f, &arg[0], 2);
		 	sys_seek (arg[0], (unsigned) arg[1]);
		 	break;
		 } 
		case SYS_TELL:
		 {
		 	get_arguments_from_stack (f, &arg[0], 1);
		 	f->eax = sys_tell (arg[0]);
		 	break;
		 } 
		case SYS_CLOSE:
		 {
		 	get_arguments_from_stack (f, &arg[0], 1);
		 	sys_close(arg[0]);
		 	break;
		 } 
		case SYS_MMAP:
		{
		       get_arguments_from_stack (f, &arg[0], 2);
			f->eax = mmap(arg[0], (void *)arg[1]);
			break;
		}
		case SYS_MUNMAP:
		{
		      get_arguments_from_stack (f, &arg[0],1);
		      munmap (arg[0]);
		      break;
		}
	}
		unpin_ptr(f->esp);
  
}

//get arguments from stack
void
get_arguments_from_stack (struct intr_frame *f, int *arg, int n)
{
	int i;
	
	for(i = 0; i < n; ++i)
		 {

		 	int *ptr = (int *)f->esp + i + 1;
		 	
		 	validate_ptr((const void *)ptr);
		 	arg[i] = *ptr;
		 //	printf("Arg[%d] :%s\n",i, &arg[i] );
		 }
}



//Add child thread/process to child list and add details like pid, exit status
struct
child_process* add_child (int pid)
{
	struct child_process* chp = malloc(sizeof(struct child_process));
	chp->pid = pid;
	chp->load = NOT_LOADED;
	chp->wait = false;
	chp->exit = false;
	lock_init(&chp->wait_lock);

  	sema_init (&chp->sema_wait, 0);
  	sema_init (&chp->sema_exit, 0);
	list_push_back(&thread_current()->child_list, &chp->elem);
	return chp;
}
//Validates stack pointer
void
validate_ptr (const void *addr)
{
	if (!is_user_vaddr (addr))
	 {
	 //	printf("Not a user address...\n");
		sys_exit(-1);
	 }
	
}

void
close_all_files (void)
{
   struct list_elem *el = list_begin (&thread_current()->files_owned_list);
   struct list_elem *nxt;
   while (el != list_end (&thread_current()->files_owned_list))
   {
     struct file_struct *fs = list_entry (el, struct file_struct,
                                          elem);
     nxt = list_next(el);
     file_close (fs->file);
     list_remove (&fs->elem);
     free (fs);
     el = nxt;
   }
}


