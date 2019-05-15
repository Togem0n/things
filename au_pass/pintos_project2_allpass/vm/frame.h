#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/palloc.h"
#include "threads/synch.h"
#include "vm/page.h"
#include <stdbool.h>
#include <stdint.h>
#include <list.h>

struct lock frame_table_lock;

struct list frame_table;

struct frame_entry{
   void *frame;
   struct sup_page_entry *spte;
   struct thread *thread;
   struct list_elem elem;

   //for frame sharging
   struct list page_list;
};

void
frame_table_init (void);

void *
frame_alloc (enum palloc_flags flags, struct sup_page_entry *spte);

void
frame_free (void *frame);

void 
frame_add_to_table (void *frame, struct sup_page_entry *spte);

void *
frame_evict (enum palloc_flags flags);

void
add_page_entry_to_frame (struct sup_page_entry *spte, void *frame);

#endif
