#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

//int 
//process_add_file (struct file *f);

struct mmap_file{
    struct sup_page_entry *spte;
    int mapid;
    struct list_elem elem;
};

struct file* 
process_get_file (int fd);

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
bool install_page (void *upage, void *kpage, bool writable);
#endif /* userprog/process.h */
