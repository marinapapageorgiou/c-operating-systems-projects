#include "userprog/syscall.h"
#include "lib/syscall-nr.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);
void sys_write(int *);
void sys_exit(int *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  // Get the "start point" in the stack
  int *stack = f->esp;
  // System call code will be always in the beginning
  int code = *(stack+0);

  switch (code) {
    case SYS_WRITE:
      sys_write(stack);
      break;
    
    case SYS_EXIT:
      sys_exit(stack);
      break;
    
    default:
      break;
  }
}

void sys_write(int *stack) {
  // Write syscall receives three parameters: file id to write, content buffer and content length
  int fd = *(stack+1);
  // Cast from const void * to const char *
  const char *buffer = (const char *) *(stack+2);
  // Cast from unsigned to size_t
  size_t size = (size_t) *(stack+3);

  if (fd == 1)
    // If file id to write, it means it is stdout
    putbuf(buffer, size);
}

void sys_exit(int *stack) {
  // System exit only has the return status code
  int status = *(stack+1);
  thread_exit();
}
