#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <stdbool.h>
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/inode.h"

static void syscall_handler (struct intr_frame *);
struct semaphore sync_file;
struct lock file_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  sema_init (&sync_file, 1);
  lock_init (&file_lock);
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
      check(f->esp+4);
      f->eax = exec((const char *)*(uint32_t *)(f->esp+4));
      break;
    case SYS_WAIT:
      check(f->esp+4);
      f->eax = wait((pid_t)*(uint32_t*)(f->esp+4));
      break;
    case SYS_CREATE:
      check(f->esp+16);
      check(f->esp+20);
      f->eax = create((const char *)*(uint32_t*)(f->esp+16), (unsigned *)*(uint32_t *)(f->esp+20));
      break;
    case SYS_REMOVE:
      check(f->esp+4);
      f->eax = remove((const char *)*(uint32_t *)(f->esp+4));
      break;
    case SYS_OPEN:
      check(f->esp+4);
      f->eax = open((const char*)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_FILESIZE:
      check(f->esp+4);
      f->eax = filesize((int)*(uint32_t*)(f->esp+4));
      break;
    case SYS_READ:
      check(f->esp+20);
      check(f->esp+24);
      check(f->esp+28);
      f->eax = read((int)*(uint32_t *)(f->esp+20), (void *)*(uint32_t *)(f->esp+24), (unsigned)*((uint32_t *)(f->esp + 28)));
      break;
    case SYS_WRITE:
      check(f->esp+20);
      check(f->esp+24);
      check(f->esp+28);
      f->eax = write((int)*(uint32_t *)(f->esp+20), (void *)*(uint32_t *)(f->esp + 24), (unsigned)*((uint32_t *)(f->esp + 28)));
      break;
    case SYS_SEEK:
      check(f->esp+16);
      check(f->esp+20);
      seek((int)*(uint32_t *)(f->esp+16), (unsigned)*(uint32_t *)(f->esp+20));
      break;
    case SYS_TELL:
      check(f->esp+4);
      f->eax = tell((int)*(uint32_t *)(f->esp+4));
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
  sema_up (&sync_file);
  struct thread *cur = thread_current();
  cur->exit_status = status;
  printf("%s: exit(%d)\n", cur->name, status);
  int i;
  for (i = 3; i < 128; i++) {
    if (cur->files[i] != NULL) close(i);
  }
  thread_exit();
}

pid_t
exec (const char *file)
{
  sema_down (&sync_file);
  pid_t p = process_execute(file);
  sema_up (&sync_file);
  return p;
}

int
wait (pid_t pid)
{
  return process_wait(pid);
}

bool
create (const char *file, unsigned initial_size)
{
  if (file == NULL) exit(-1);
  sema_down (&sync_file);
  bool c = filesys_create(file, initial_size);
  sema_up (&sync_file);
  return c;
}

bool
remove (const char *file)
{
  if (file == NULL) exit(-1);
  sema_down (&sync_file);
  bool r = filesys_remove(file);
  sema_up (&sync_file);
  return r;
}

int
open (const char *file)
{
  if (file == NULL) return -1;
  sema_down (&sync_file);
  struct file *f = filesys_open(file);
  struct file **files = thread_current()->files;
  if (f == NULL) {
    sema_up (&sync_file);
    return -1;
  } else {
    int i;
    for (i = 3; i < 128; i++){
      if (files[i] == NULL) {
        thread_current()->fd = i;
        if (!strcmp(thread_current()->name, file)) file_deny_write(f);
        files[i] = f;
        break;
      }
    }
  }
  sema_up (&sync_file);
  return thread_current()->fd;
}

int
filesize (int fd)
{
  if (thread_current()->files[fd] == NULL)  exit(-1);

  sema_down (&sync_file);
  int length = file_length (thread_current()->files[fd]);
  sema_up (&sync_file);

  return length;
}

int
read (int fd, void *buffer, unsigned length)
{
  check (buffer);
  check (length);
  check (buffer+length);

  if (thread_current()->files[fd] == NULL)  return -1;

  if (fd == 0) {
    int input = 0;
    *(char *) buffer = input_getc();
    for (input; input < length; input++) {
      if ( ((char *)buffer)[input] == '\0') break;
    }
    return input;
  } else if (fd > 2) {
    sema_down (&sync_file);
    int r = file_read (thread_current()->files[fd], buffer, length);
    sema_up (&sync_file);
    return r;
  }

  return -1;
}

int
write (int fd, const void *buffer, unsigned size)
{
  check (buffer);
  check (size);
  check (buffer+size);
  sema_down (&sync_file);
  lock_acquire (&file_lock);
  if (fd == 1) {
    //writes to console: call putbuf(buffer, size) and return size
    putbuf(buffer, size);
    lock_release (&file_lock);
    sema_up (&sync_file);
    return size;
  } else if (fd > 2) {
    struct file *target_file = thread_current()->files[fd];
    if (target_file == NULL) {
      lock_release (&file_lock);
      sema_up (&sync_file);
      return -1;
    }
    if (file_get_deny_write (target_file)) file_deny_write (target_file);
    int w = file_write(target_file, buffer, size);
    lock_release (&file_lock);
    sema_up (&sync_file);
    return w;
  } else {
    lock_release (&file_lock);
    sema_up (&sync_file);
    return -1;
  }
}

void
seek (int fd, unsigned position)
{
  check (position);
  if (thread_current()->files[fd] == NULL) exit(-1);
  sema_down (&sync_file);
  file_seek (thread_current()->files[fd], position);
  sema_up (&sync_file);
}

unsigned
tell (int fd)
{
  if (thread_current()->files[fd] == NULL) exit(-1);
  sema_down (&sync_file);
  unsigned t = file_tell (thread_current()->files[fd]);
  sema_up (&sync_file);
  return t;
}

void
close (int fd)
{
  if (thread_current()->files[fd] == NULL) exit(-1);
  sema_down (&sync_file);
  file_close(thread_current()->files[fd]);
  thread_current()->files[fd] = NULL;
  sema_up (&sync_file);
}

void
check(const void *address) {
  if (!is_user_vaddr (address)) exit(-1);
}