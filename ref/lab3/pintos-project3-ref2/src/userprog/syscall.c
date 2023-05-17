#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/vaddr.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "process.h"

static void syscall_handler(struct intr_frame *f);
static void syscall_halt(struct intr_frame *f UNUSED);
static void syscall_exit(struct intr_frame *f);
static void syscall_write(struct intr_frame *f);
static void syscall_wait(struct intr_frame *f);
static void syscall_exec(struct intr_frame *f);
static void syscall_create(struct intr_frame *f);
static void syscall_remove(struct intr_frame *f);
static void syscall_open(struct intr_frame *f);
static void syscall_filesize(struct intr_frame *f);
static void syscall_read(struct intr_frame *f);
static void syscall_seek(struct intr_frame *f);
static void syscall_tell(struct intr_frame *f);
static void syscall_close(struct intr_frame *f);
static void check_valid_addr(const void *ptr, int size);
static void check_buffer(void *buff, unsigned size);
static struct file *get_file_from_fd(int fd);
static void check_valid_addr(const void *ptr, int size)
{

  // printf("%x %x\n", (int)ptr, pg_round_up(ptr));
  for (int i = 0; i < size; i++, ptr++)
  {
    if (!is_user_vaddr(ptr) || ptr == NULL || ptr < (void *)0x08048000)
    {
      thread_current()->exit_code = -1;
      thread_exit();
    }
    void *p = pagedir_get_page(thread_current()->pagedir, ptr);
    if (p == NULL)
    {
      thread_current()->exit_code = -1;
      thread_exit();
    }
  }
}

static void check_buffer(void *buff, unsigned size)
{
  char *ptr = (char *)buff;
  for (int i = 0; i < size; i++)
  {
    check_valid_addr((const void *)ptr, 1);
    ptr++;
  }
}

static void check_string(void *str)
{
  char *ptr = (char *)str;
  for (int i = 0;; i++)
  {
    check_valid_addr((const void *)ptr, 1);
    ptr++;
    if (*ptr == '\0')
      break;
  }
}
// An array mapping syscall numbers from syscall.h
// to the function that handles the system call.
static void (*syscalls[])(struct intr_frame *f) = {
    [SYS_HALT] syscall_halt,
    [SYS_EXIT] syscall_exit,
    [SYS_EXEC] syscall_exec,
    [SYS_WAIT] syscall_wait,
    [SYS_CREATE] syscall_create,
    [SYS_REMOVE] syscall_remove,
    [SYS_OPEN] syscall_open,
    [SYS_FILESIZE] syscall_filesize,
    [SYS_READ] syscall_read,
    [SYS_WRITE] syscall_write,
    [SYS_SEEK] syscall_seek,
    [SYS_TELL] syscall_tell,
    [SYS_CLOSE] syscall_close,
};
void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}
static int get_syscall_arg(struct intr_frame *f, int num)
{
  void *ptr = f->esp + num * 4;
  check_valid_addr(ptr, 4);
  return *(int *)ptr;
}
static void
syscall_handler(struct intr_frame *f)
{
  int syscall_type = get_syscall_arg(f, 0);
  if (syscall_type >= 0 && syscall_type < 13 && syscalls[syscall_type])
  {
    syscalls[syscall_type](f);
  }
  else
  {
    printf("unknown syscall %d\n", syscall_type);
    thread_current()->exit_code = -1;
    thread_exit();
  }
}

static void syscall_halt(struct intr_frame *f UNUSED)
{
  shutdown_power_off();
}

static void syscall_exit(struct intr_frame *f)
{
  int exit_code = get_syscall_arg(f, 1);
  thread_current()->exit_code = exit_code;
  thread_exit();
}
static void syscall_write(struct intr_frame *f)
{
  int fd = get_syscall_arg(f, 1);
  char *buffer = (char *)get_syscall_arg(f, 2);
  int size = get_syscall_arg(f, 3);
  check_buffer(buffer, size);
  if (fd == 1)
  {
    putbuf(buffer, size);
    f->eax = size;
  }
  if (fd == 0)
  {
    f->eax = -1;
    return;
  }
  struct file *_file = get_file_from_fd(fd);
  if (_file == NULL)
  {
    f->eax = -1;
    return;
  }
  sema_down(&file_sema);
  f->eax = file_write(_file, buffer, size);
  sema_up(&file_sema);
}

static void syscall_wait(struct intr_frame *f)
{
  tid_t tid = get_syscall_arg(f, 1);
  f->eax = process_wait(tid);
}

static void syscall_exec(struct intr_frame *f)
{
  char *cmd_line = (char *)get_syscall_arg(f, 1);
  check_string(cmd_line);
  f->eax = process_execute(cmd_line);
}
static void syscall_create(struct intr_frame *f)
{
  char *file_name = get_syscall_arg(f, 1);
  check_string(file_name);
  unsigned file_size = get_syscall_arg(f, 2);

  sema_down(&file_sema);
  bool res = filesys_create(file_name, file_size);
  f->eax = res;
  sema_up(&file_sema);
}
static void syscall_remove(struct intr_frame *f)
{
  char *file_name = get_syscall_arg(f, 1);
  check_string(file_name);
  unsigned file_size = get_syscall_arg(f, 2);

  sema_down(&file_sema);
  bool res = filesys_remove(file_name);
  f->eax = res;
  sema_up(&file_sema);
}
static void syscall_open(struct intr_frame *f)
{
  char *file_name = get_syscall_arg(f, 1);
  check_string(file_name);
  struct thread *t = thread_current();
  sema_down(&file_sema);
  struct file *open_file = filesys_open(file_name);
  sema_up(&file_sema);
  if (open_file == NULL)
  {
    f->eax = -1;
    return;
  }
  struct file_info *info = malloc(sizeof(struct file_info));
  info->fd = ++(t->last_fd);
  info->f = open_file;
  list_push_back(&t->file_list, &info->elem);
  f->eax = info->fd;
}
static void syscall_filesize(struct intr_frame *f)
{
  int fd = get_syscall_arg(f, 1);
  struct file *_file = get_file_from_fd(fd);
  if (_file == NULL)
  {
    f->eax = -1;
    return;
  }
  sema_down(&file_sema);
  f->eax = file_length(_file);
  sema_up(&file_sema);
}
static void syscall_read(struct intr_frame *f)
{
  int fd = get_syscall_arg(f, 1);
  void *buf = (void *)get_syscall_arg(f, 2);
  unsigned size = (unsigned)get_syscall_arg(f, 3);
  check_buffer(buf, size);
  if (fd == 0)
  {
    for (size_t i = 0; i < size; i++)
    {
      *(uint8_t *)buf = input_getc();
      buf += sizeof(uint8_t);
    }
    f->eax = size;
    return;
  }
  if (fd == 1)
  {
    f->eax = -1;
    return;
  }
  struct file *_file = get_file_from_fd(fd);
  if (_file == NULL)
  {
    f->eax = -1;
    return;
  }
  sema_down(&file_sema);
  f->eax = file_read(_file, buf, size);
  sema_up(&file_sema);
}
static void syscall_seek(struct intr_frame *f)
{
  int fd = get_syscall_arg(f, 1);
  int pos = get_syscall_arg(f, 2);
  struct file *_file = get_file_from_fd(fd);
  if (_file == NULL)
  {
    f->eax = -1;
    return;
  }
  else
  {
    sema_down(&file_sema);
    file_seek(_file, pos);
    sema_up(&file_sema);
  }
}
static void syscall_tell(struct intr_frame *f)
{
  int fd = get_syscall_arg(f, 1);
  struct file *_file = get_file_from_fd(fd);
  if (_file == NULL)
  {
    f->eax = -1;
    return;
  }
  else
  {
    sema_down(&file_sema);
    f->eax = file_tell(_file);
    sema_up(&file_sema);
  }
}
static void syscall_close(struct intr_frame *f)
{
  int fd = get_syscall_arg(f, 1);
  struct file *_file = get_file_from_fd(fd);
  if (_file == NULL)
  {
    f->eax = -1;
    return;
  }
  else
  {
    sema_down(&file_sema);
    file_close(_file);
    struct thread *t = thread_current();
    struct list_elem *e;
    for (e = list_begin(&t->file_list); e != list_end(&t->file_list);
         e = list_next(e))
    {
      struct file_info *entry = list_entry(e, struct file_info, elem);
      if (entry->fd == fd)
      {
        list_remove(&entry->elem);
        free(entry);
        break;
      }
    }
    sema_up(&file_sema);
  }
}
static struct file *get_file_from_fd(int fd)
{
  if (fd < 0)
    return NULL;
  struct thread *t = thread_current();
  struct list_elem *e;
  for (e = list_begin(&t->file_list); e != list_end(&t->file_list);
       e = list_next(e))
  {
    struct file_info *entry = list_entry(e, struct file_info, elem);
    if (entry->fd == fd)
      return entry->f;
  }
  return NULL;
}