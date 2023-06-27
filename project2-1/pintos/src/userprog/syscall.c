#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <stdbool.h>
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*
    **SYS_HALT,                   Halt the operating system.
    **SYS_EXIT,                   Terminate this process.
    SYS_EXEC,                     Start another process.
    SYS_WAIT,                     Wait for a child process to die.
    **SYS_CREATE,                 Create a file.
    SYS_REMOVE,                   Delete a file.
    **SYS_OPEN,                   Open a file.
    SYS_FILESIZE,                 Obtain a file's size.
    SYS_READ,                     Read from a file.
    **SYS_WRITE,                  Write to a file.
    SYS_SEEK,                     Change position in a file.
    SYS_TELL,                     Report current position in a file.
    **SYS_CLOSE,                  Close a file.
  */
static void
syscall_handler (struct intr_frame *f) 
{
  switch(*(uint32_t *)(f->esp)) {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      check(f->esp+4);
      exit(*(uint32_t *)(f->esp+4));
      break;
    case SYS_EXEC:
      break;
    case SYS_WAIT:
      break;
    case SYS_CREATE:
      check(f->esp+16);
      check(f->esp+20);
      f->eax = create((const char *)* (uint32_t*)(f->esp+16), (unsigned *)*(uint32_t *)(f->esp+20));
      break;
    case SYS_REMOVE:
      break;
    case SYS_OPEN:
      check(f->esp+4);
      f->eax = open((const char*)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_FILESIZE:
      break;
    case SYS_READ:
      break;
    case SYS_WRITE:
      check(f->esp+20);
      check(f->esp+24);
      check(f->esp+28);
      f->eax = write((int)*(uint32_t *)(f->esp+20), (void *)*(uint32_t *)(f->esp + 24), (unsigned)*((uint32_t *)(f->esp + 28)));
      break;
    case SYS_SEEK:
      break;
    case SYS_TELL:
      break;
    case SYS_CLOSE:
      check(f->esp+4);
      close((const char*)*(uint32_t *)(f->esp + 4));
      break;
  }
}

void
halt (void)
{
  shutdown_power_off();
}

void
exit (int status) 
{
  struct thread *cur = thread_current();
  printf("%s: exit(%d)\n", cur->name, status);
  int i;
  for (i = 3; i < 128; i++) {
    if (cur->files[i] != NULL) close(i);
  }
  thread_exit();
}

bool
create (const char *file, unsigned initial_size)
{
  if (file == NULL) exit(-1);
  return filesys_create(file, initial_size);
}

int
open (const char *file)
{
  if (file == NULL) return -1;
  struct file *f = filesys_open(file);
  struct file **files = thread_current()->files;
  if (f == NULL) {
    return -1;
  } else {
    int i;
    for (i = 3; i < 128; i++){
      if (files[i] == NULL) {
        thread_current()->fd = i;
        files[i] = f;
        break;
      }
    }
  }
  return thread_current()->fd;
}

int
write (int fd, const void *buffer, unsigned size)
{
  if (fd == 1) {
    //writes to console: call putbuf(buffer, size) and return size
    putbuf(buffer, size);
  }
  return size;
}

void
close (int fd)
{
  if (thread_current()->files[fd] == NULL) exit(-1);
  file_close(thread_current()->files[fd]);
  thread_current()->files[fd] = NULL;
}

void
check(const void *address) {
  if (!is_user_vaddr (address)) exit(-1);
}