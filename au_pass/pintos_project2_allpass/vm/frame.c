#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"

void *
lookup_frame (off_t block_id);

struct frame_entry *
find_frame_entry (void *frame);

/*
 * Initialize the frame table, This frame table 
 * in essence is a list, so we need to initialize this list
 * also we need a frame_lock to do synchronization.
 */
void
frame_table_init (void)
{
   list_init (&frame_table);
   lock_init (&frame_table_lock);
}

/*
 * allocate a frame from user pool
 */
void *
frame_alloc (enum palloc_flags flags, struct sup_page_entry *spte)
{
     //if trying to get page from kernel pool, return null
    if ( (flags & PAL_USER) == 0)
     {
 	return NULL;	
     }
     
      
      void *frame =  NULL;
      
//     if (find_frame_entry (lookup_frame (spte->block_id)) != NULL){
//           frame = find_frame_entry (lookup_frame (spte->block_id));
//	   return frame;
//     }
      
     frame = palloc_get_page (flags); 
     //if it's valid frame, add it to frame table, which are used to 
     //keep track all the frame activity
     if (frame)
       {
            frame_add_to_table (frame, spte);
           
       }
     else
	{
		while(!frame)
		{
		  frame = frame_evict (flags);
		  lock_release (&frame_table_lock);
		}
		if (!frame)
		{
		   PANIC("Frame could not be evicted because swap is full!");
		}
	  frame_add_to_table (frame,spte);
	}
	return frame;
}
/*
 *  Loop the frame_table, find the freeing frame if any, remove it from
 *  the table list, free the frame table entry it occupies, and most importantly
 *  free all the data inside this frame.
 */
void
frame_free (void *frame)
{
   struct list_elem *e;
   lock_acquire (&frame_table_lock);
   for (e = list_begin (&frame_table); e != list_end (&frame_table); e = list_next(e))
    {
       struct frame_entry *fe = list_entry  (e, struct frame_entry, elem);
 	if (fe->frame == frame)
	{
                
               
//             if (list_size (&fe->page_list) < 2)
//             {   
        	list_remove (e);
        	free (fe);
		palloc_free_page (frame);
		break;
//     	     }
	}
    }
   lock_release (&frame_table_lock);
}

/*
 *  Add frame_entry to frame table. Note we have list struct
 *  which are easily causing race condition
 */
void
frame_add_to_table (void *frame, struct sup_page_entry *spte)
{
    struct frame_entry *fte = malloc (sizeof (struct frame_entry));
    fte->frame = frame;
    fte->spte = spte;
    fte->thread = thread_current ();
    lock_acquire (&frame_table_lock);
    list_push_back (&frame_table, &fte->elem);
    list_init (&fte->page_list);
//    list_push_back (&fte->page_list, &spte->sup_elem);
    lock_release (&frame_table_lock);
} 

void
frame_add_page_to_table (void *frame, struct sup_page_entry *spte)
{


}

void *
frame_evict (enum palloc_flags flags)
{
     lock_acquire(&frame_table_lock);
     struct list_elem *e = list_begin(&frame_table);
  
  while (true)
    {
      struct frame_entry *fte = list_entry(e, struct frame_entry, elem);
      if (!fte->spte->pinned)
	{
	  struct thread *t = fte->thread;
	  if (pagedir_is_accessed(t->pagedir, fte->spte->uva))
	    {
	      pagedir_set_accessed(t->pagedir, fte->spte->uva, false);
	    }
	  else
	    {
	      if (pagedir_is_dirty(t->pagedir, fte->spte->uva) ||
		  fte->spte->type == SWAP)
		{
		  if (fte->spte->type == MMAP)
		    {
		      lock_acquire(&file_lock);
		      file_write_at(fte->spte->file, fte->frame,
				    fte->spte->read_bytes,
				    fte->spte->offset);
		      lock_release(&file_lock);
		    }
		  else
		    {
		      fte->spte->type = SWAP;
		      fte->spte->swap_index = swap_out(fte->frame);
		    }
		}
	      fte->spte->is_loaded = false;
	      list_remove(&fte->elem);
	      pagedir_clear_page(t->pagedir, fte->spte->uva);
	      palloc_free_page(fte->frame);
	      free(fte);
	      return palloc_get_page(flags);
	    }
	}
      e = list_next(e);
      if (e == list_end(&frame_table))
	{
	  e = list_begin(&frame_table);
	}
    }
}

/*
 *  For frame sharing, we add this func, loop the frame list, find the matching
 *  block_id
 */

void *
lookup_frame (off_t block_id)
{
     if (block_id == -1) return NULL;
     void *frame = NULL;
//     lock_acquire (&frame_table_lock);
     struct list_elem *e = list_begin (&frame_table);
     for ( e = list_begin (&frame_table); e != list_end (&frame_table); e = list_next (e)){
           struct frame_entry *ft = list_entry (e, struct frame_entry, elem);
//           struct list_elem *ele = list_begin (&ft->page_list);
//           for (ele = list_begin(&ft->page_list); ele != list_end (&ft->page_list); ele = list_next (ele))
//	   {
//               struct sup_page_entry *spte = list_entry (ele, struct sup_page_entry, sup_elem);
                if (ft->spte->type == FILE && ft-> spte->block_id == block_id)
 	        {
 		     frame = ft->frame;
//   	             lock_release (&frame_table_lock);
		     return frame;
                }
//           } 
     }     
//     lock_release (&frame_table_lock);
     return frame;
}

struct frame_entry *
find_frame_entry (void *frame)
{
    if (frame == NULL) return NULL;
   // lock_acquire (&frame_table_lock);
   struct list_elem *e = list_begin (&frame_table);
   for (e = list_begin (&frame_table); e != list_end (&frame_table); e = list_next (e)){
       struct frame_entry *fe = list_entry (e, struct frame_entry, elem);
       if ( fe -> frame == frame){
  //            lock_release (&frame_table_lock);
              return fe;
       }
   }
 //  lock_release (&frame_table_lock);
   return NULL;
}

/*
 * This is to add a page entry to frame entry, so that multiple page can share one frame
 */
void 
add_page_entry_to_frame(struct sup_page_entry *spte, void *frame)
{
    //1.find frame entry from the frame table 
    struct frame_entry *fe = find_frame_entry (frame);
    if (fe == NULL) return;
    //2.add this supplemental page entry to this frame entry  
    lock_acquire (&frame_table_lock);
    list_push_back (&fe->page_list, &spte->sup_elem);
    lock_release (&frame_table_lock);
}

