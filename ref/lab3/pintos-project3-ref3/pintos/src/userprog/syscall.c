#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include <user/syscall.h>
#include <vm/frame.h>
#include <vm/swap.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "threads/synch.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "pagedir.h"
#include "process.h"

static void syscall_handler (struct intr_frame *);

/* Ruihang Begin */

/* ------ Declarations of System Calls Begin ------ */
static void sys_halt(void);
void sys_exit(int status);
static pid_t sys_exec(const char *cmd_line);
static int sys_wait(pid_t pid);
static bool sys_create(const char *file, unsigned initialize_size);
static bool sys_remove(const char *file);
static int sys_open(const char* filename);
static int sys_filesize(int fd);
static int sys_read(int fd, void *buffer, unsigned size);
static int sys_write(int fd, const void *buffer, unsigned size);
static void sys_seek(int fd, unsigned position);
static unsigned sys_tell(int fd);
static void sys_close(int fd);

static mapid_t sys_mmap(int fd, void *addr);
static void sys_munmap(mapid_t mapping);

static bool is_valid_user_addr(void *addr);

/* System calls for filesystem. */
static bool sys_chdir(const char *dir);
static bool sys_mkdir(const char *dir);
static bool sys_readdir(int fd, char *name);
static bool sys_isdir(int fd);
static int sys_inumber(int fd);
/* ------ Declarations of System Calls End ------ */


/* File system lock to ensure that there is at most one system call related to
 * file system at one time.
 */
struct lock filesys_lock;


/* Get the struct file_descriptor of struct thread _thread. */
static struct file_descriptor *
get_file_descriptor(struct thread *_thread, int fd) {
  struct list_elem *_elem = list_begin(&(_thread->file_descriptors));
  while (_elem != list_end(&(_thread->file_descriptors))) {
    struct file_descriptor *_fd = list_entry(_elem,
                                    struct file_descriptor, elem);
    if (_fd->fd == fd)
      return _fd;
    _elem = list_next(_elem);
  }
  return NULL;
}

/* Pin the page so that page fault will not occur. */
static struct page_table_entry * //__attribute__((optimize("-O0")))
pin_user_address(const void *user_addr, void *esp, bool grow) {
#ifdef VM
  void *upage = pg_round_down(user_addr);
  page_table_t *page_table = &thread_current()->page_table;
  uint32_t *pagedir = thread_current()->pagedir;

//  lock_acquire(&page_table_lock);
  struct page_table_entry *pte = pte_find(page_table, upage, true);

  bool new_frame = false;
  /* Check whether present. If not present, load from swap/file.
   * Very very similar to page_fault_handler().
   * Always pin the page!
   */
  if (pte != NULL) {
    pte->pinned = true;
    if (pte->status == SWAP) {
      /* Load the page from SWAP. */
      void *frame = frame_get_frame(0, upage);
      if (frame == NULL)
        sys_exit(-1);
      new_frame = true;
      swap_load(pte->swap_index, frame);
      pte->status = FRAME;
      pte->frame = frame;
      pte->swap_index = 0;
    } else if (pte->status == FILE) {
      /* Read the page from mmapped file. */
      void *frame = frame_get_frame(0, upage);
      if (frame == NULL)
        sys_exit(-1);
      new_frame = true;
      page_table_mmap_read_file(pte, frame);
      pte->status = FRAME;
      pte->frame = frame;
    } else {
      // The page is already in memory. Therefore do nothing.
      ASSERT(pte->status == FRAME)
      goto finish;
    }
  } else {
    if (grow && is_stack_access(user_addr, esp)) {
      /* Perform stack growth. */
      void *frame = frame_get_frame(0, upage);
      if (frame == NULL)
        sys_exit(-1);
      new_frame = true;
      pte = malloc(sizeof(struct page_table_entry));
      pte->upage = upage;
      pte->status = FRAME;
      pte->writable = true;
      pte->pinned = true;
      pte->frame = frame;
      pte->swap_index = 0;
      pte->file = NULL;
      pte->file_offset = 0;
      pte->read_bytes = pte->zero_bytes = 0;
      hash_insert(page_table, &pte->elem);
    } else
      sys_exit(-1);
  }

  ASSERT(new_frame)
  bool pagedir_set_result = pagedir_set_page(pagedir, pte->upage,
                                             pte->frame, pte->writable);
  ASSERT(pagedir_set_result)

finish:
//  lock_release(&page_table_lock);
  return pte;
#endif
}

/* Check whether the address given by the user program which invoked a system
 * call is valid:
 *   1. not null pointer;
 *   2. not a pointer to kernel virtual address space (above PHYS_BASE);
 *   3. not a pointer to unmapped virtual memory.
 */
static void
check_valid_user_addr(const void *user_addr, uint32_t size,
                      void *esp, bool write, bool grow) {
  for (const void *addr = user_addr; addr < user_addr + size; addr++) {
#ifdef VM
    if (!addr || !is_user_vaddr(addr))
      sys_exit(-1);
    struct page_table_entry *pte = pin_user_address(addr, esp, grow);
    ASSERT(pte != NULL)

    /* If the access wants to write, but the page is not writable, terminate. */
    if (!pte->writable && write)
      sys_exit(-1);
#else
    if (!addr
     || !is_user_vaddr(addr)
     || pagedir_get_page(thread_current()->pagedir, addr) == NULL) {
      sys_exit(-1);
      return;
      }
#endif
  }
}

/* Return the system call number. */
static uint32_t
get_syscall_number(struct intr_frame *f, void *esp) {
  check_valid_user_addr(f->esp, sizeof(uint32_t), esp, false, false);
  return *((uint32_t *)(f->esp));
}

/* Check whether the parameters of a system call are all valid.
 * And pin the pte. */
static void
check_valid_syscall_args(void** syscall_args, int num, void *esp) {
  for (int i = 0; i < num; i++)
    check_valid_user_addr(syscall_args[i], sizeof(uint32_t), esp,
                          false, false);
}

/* Check whether the address of the user string is valid.
 * And pin the pte.
 */
static void
check_valid_user_string(const void *user_string, void *esp) {
  check_valid_user_addr(user_string, sizeof(char), esp, false, true);

  int len = 0;
  while (*((char *)user_string) != '\0') {
    if (len == 0xfff) {
      // The length of user_string is more than 4KB - a single page. Reject.
      sys_exit(-1);
    }
    len++;
    user_string++;
    check_valid_user_addr(user_string, sizeof(char), esp, false, true);
  }
}

/* Check whether the address of the user buffer is valid.
 * And pin the pte.
 */
static void
check_valid_user_buffer(const void *user_buffer, unsigned size,
                        void *esp, bool write) {
  for (const void *addr = user_buffer; addr < user_buffer + size; addr++)
    check_valid_user_addr(addr, sizeof(void), esp, write, true);
}

/* Unpin pages! */
static void
unpin_user_addr(const void *user_addr, uint32_t size) {
#ifdef VM
  page_table_t *page_table = &thread_current()->page_table;
  for (const void *addr = user_addr; addr < user_addr + size; addr++) {
    void *upage = pg_round_down(addr);
    struct page_table_entry *pte = pte_find(page_table, upage, false);
    pte->pinned = false;
  }
#endif
}

static void
unpin_syscall_number(const void *esp) {
  unpin_user_addr(esp, sizeof(uint32_t));
}

static void
unpin_syscall_args(void **syscall_args, int num) {
  for (int i = 0; i < num; i++)
    unpin_user_addr(syscall_args[i], sizeof(uint32_t));
}

static void
unpin_string(const void *user_string) {
  unpin_user_addr(user_string, sizeof(char));

  while (*((char *)user_string) != '\0') {
    user_string++;
    unpin_user_addr(user_string, sizeof(char));
  }
}

static void
unpin_buffer(const void *user_buffer, unsigned size) {
  for (const void *addr = user_buffer; addr < user_buffer + size; addr++)
    unpin_user_addr(addr, sizeof(void));
}
/* Ruihang End */

void __attribute__((optimize("-O0")))
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  /* Ruihang Begin */
  lock_init(&filesys_lock);
  /* Ruihang End */
}


/* Ruihang Begin */
static void
syscall_handler (struct intr_frame *f UNUSED)
{
  void *esp = f->esp;
#ifdef VM
  /*Jiaxin Begin*/
  thread_current()->esp = esp;
  /*Jiaxin End*/
#endif

  uint32_t syscall_number = get_syscall_number(f, esp);
  void* syscall_args[3] = {f->esp + 4, f->esp + 8, f->esp + 12};

  switch (syscall_number) {
    case SYS_HALT:
      sys_halt();
      break;
    case SYS_EXIT:
      check_valid_syscall_args(syscall_args, 1, esp);
      sys_exit(*((int*)syscall_args[0]));
      unpin_syscall_args(syscall_args, 1);
      break;
    case SYS_EXEC:
      check_valid_syscall_args(syscall_args, 1, esp);
      check_valid_user_string(*((const char **)syscall_args[0]), esp);
      f->eax = sys_exec(*((const char **)syscall_args[0]));
      unpin_syscall_args(syscall_args, 1);
      unpin_string(*((const char **)syscall_args[0]));
      break;
    case SYS_WAIT:
      check_valid_syscall_args(syscall_args, 1, esp);
      f->eax = sys_wait(*((pid_t *)syscall_args[0]));
      unpin_syscall_args(syscall_args, 1);
      break;
    case SYS_CREATE:
      check_valid_syscall_args(syscall_args, 2, esp);
      check_valid_user_string(*((const char **)syscall_args[0]), esp);
      f->eax = sys_create(*((const char **)syscall_args[0]),
          *((unsigned *)syscall_args[1]));
      unpin_syscall_args(syscall_args, 2);
      unpin_string(*((const char **)syscall_args[0]));
      break;
    case SYS_REMOVE:
      check_valid_syscall_args(syscall_args, 1, esp);
      check_valid_user_string(*((const char **)syscall_args[0]), esp);
      f->eax = sys_remove(*((const char **)syscall_args[0]));
      unpin_syscall_args(syscall_args, 1);
      unpin_string(*((const char **)syscall_args[0]));
      break;
    case SYS_OPEN:
      check_valid_syscall_args(syscall_args, 1, esp);
      check_valid_user_string(*((const char **)syscall_args[0]), esp);
      f->eax = sys_open(*((const char **)syscall_args[0]));
      unpin_syscall_args(syscall_args, 1);
      unpin_string(*((const char **)syscall_args[0]));
      break;
    case SYS_FILESIZE:
      check_valid_syscall_args(syscall_args, 1, esp);
      f->eax = sys_filesize(*((int *)syscall_args[0]));
      unpin_syscall_args(syscall_args, 1);
      break;
    case SYS_READ:
      check_valid_syscall_args(syscall_args, 3, esp);
      check_valid_user_buffer(*((const void **)syscall_args[1]),
          *((unsigned *)syscall_args[2]), esp, true);

      f->eax = sys_read(*((int *)syscall_args[0]),
          *((void **)syscall_args[1]),
          *((unsigned *)syscall_args[2]));
      unpin_syscall_args(syscall_args, 3);
      unpin_buffer(*((const void **)syscall_args[1]),
                   *((unsigned *)syscall_args[2]));
      break;
    case SYS_WRITE:
      check_valid_syscall_args(syscall_args, 3, esp);
      check_valid_user_buffer(*((const void **)syscall_args[1]),
                              *((unsigned *)syscall_args[2]), esp, false);

      f->eax = sys_write(*((int *)syscall_args[0]),
                        *((const void **)syscall_args[1]),
                        *((unsigned *)syscall_args[2]));
      unpin_syscall_args(syscall_args, 3);
      unpin_buffer(*((const void **)syscall_args[1]),
                   *((unsigned *)syscall_args[2]));
      break;
    case SYS_SEEK:
      check_valid_syscall_args(syscall_args, 2, esp);
      sys_seek(*((int *)syscall_args[0]),
          *((unsigned *)syscall_args[1]));
      unpin_syscall_args(syscall_args, 2);
      break;
    case SYS_TELL:
      check_valid_syscall_args(syscall_args, 1, esp);
      f->eax = sys_tell(*((int *)syscall_args[0]));
      unpin_syscall_args(syscall_args, 1);
      break;
    case SYS_CLOSE:
      check_valid_syscall_args(syscall_args, 1, esp);
      sys_close(*((int *)syscall_args[0]));
      unpin_syscall_args(syscall_args, 1);
      break;
    case SYS_MMAP:
      check_valid_syscall_args(syscall_args, 2, esp);
      f->eax = sys_mmap(*((int *)syscall_args[0]), *((void **)syscall_args[1]));
      unpin_syscall_args(syscall_args, 2);
      break;
    case SYS_MUNMAP:
      check_valid_syscall_args(syscall_args, 1, esp);
      sys_munmap(*((mapid_t *)syscall_args[0]));
      unpin_syscall_args(syscall_args, 1);
      break;
    case SYS_CHDIR:
      check_valid_syscall_args(syscall_args, 1, esp);
      check_valid_user_string(*((const char **) syscall_args[0]), esp);
      f->eax = sys_chdir(*((const char **) syscall_args[0]));
      unpin_syscall_args(syscall_args, 1);
      unpin_string(*((const char **) syscall_args[0]));
      break;
    case SYS_MKDIR:
      check_valid_syscall_args(syscall_args, 1, esp);
      check_valid_user_string(*((const char **) syscall_args[0]), esp);
      f->eax = sys_mkdir(*((const char **) syscall_args[0]));
      unpin_syscall_args(syscall_args, 1);
      unpin_string(*((const char **) syscall_args[0]));
      break;
    case SYS_READDIR:
      check_valid_syscall_args(syscall_args, 2, esp);
      check_valid_user_buffer(*((const void **) syscall_args[1]),
                              READDIR_MAX_LEN + 1, esp, true);
      f->eax = sys_readdir(*((int *) syscall_args[0]),
                           *((char **) syscall_args[1]));
      unpin_syscall_args(syscall_args, 2);
      unpin_buffer(*((const void **) syscall_args[1]), READDIR_MAX_LEN + 1);
      break;
    case SYS_ISDIR:
      check_valid_syscall_args(syscall_args, 1, esp);
      f->eax = sys_isdir(*((int *) syscall_args[0]));
      unpin_syscall_args(syscall_args, 1);
      break;
    case SYS_INUMBER:
      check_valid_syscall_args(syscall_args, 1, esp);
      f->eax = sys_inumber(*((int *) syscall_args[0]));
      unpin_syscall_args(syscall_args, 1);
      break;
    default:
      ASSERT(false)
  }

  unpin_syscall_number(f->esp);
}

static void
sys_halt() {
  shutdown_power_off();
}

void
sys_exit(int status) {
  struct thread *cur_thread = thread_current();
  /*Jiaxin Begin*/
  //Free file resources
  while (!list_empty(&cur_thread->file_descriptors))
  {
    struct list_elem *e = list_pop_front(&cur_thread->file_descriptors);
    struct file_descriptor *fd = list_entry(e, struct file_descriptor, elem);
    file_close(fd->_file);
    free(fd);
  }
  /*Jiaxin End*/
  thread_current()->exit_code = status;

  /*Jiaxin Begin*/
  printf("%s: exit(%d)\n", thread_current()->name, status);
  /*Jiaxin End*/

  thread_exit();
}

static pid_t
sys_exec(const char *cmd_line) {
  return process_execute(cmd_line);
}
/* Ruihang End */

static int
sys_wait(pid_t pid) {
  /*Jiaxin Begin*/
  return process_wait(pid);
  /*Jiaxin end*/
}

/* Ruihang Begin */
static bool __attribute__((optimize("-O0")))
sys_create(const char *file, unsigned initialize_size) {
  lock_acquire(&filesys_lock);
  bool res = filesys_create(file, initialize_size);
  lock_release(&filesys_lock);
  return res;
}

static bool __attribute__((optimize("-O0")))
sys_remove(const char *file) {
  lock_acquire(&filesys_lock);
  int res = filesys_remove(file);
  lock_release(&filesys_lock);
  return res;
}

static int __attribute__((optimize("-O0")))
sys_open(const char* filename) {
  lock_acquire(&filesys_lock);
  /* At least one in _FILE and DIR is NULL. */
  struct file *_file = filesys_open(filename);
  struct dir* dir=filesys_opendir(filename);
  lock_release(&filesys_lock);

  /* Return -1 if the file or directory could not be opened. */
  if (_file == NULL && dir == NULL)
    return -1;

  struct file_descriptor *fd = malloc(sizeof(struct file_descriptor));
  fd->fd = thread_current()->fd_num++;
  strlcpy(fd->file_name, filename, strlen(filename));
  fd->_file = _file;
  fd->_dir=dir;
  fd->owner_thread = thread_current();
  list_push_back(&(thread_current()->file_descriptors), &(fd->elem));

  return fd->fd;
}

static int __attribute__((optimize("-O0")))
sys_filesize(int fd) {
  struct file_descriptor *_fd = get_file_descriptor(thread_current(), fd);
  /* Terminate if
   *  - FD is not opened by the current thread, or
   *  - the inode designated by _FD is a directory.
   */
  if (_fd == NULL || file_descriptor_is_dir(_fd))
    sys_exit(-1);

  lock_acquire(&filesys_lock);
  int filesize = file_length(_fd->_file);
  lock_release(&filesys_lock);
  return filesize;
}

static int __attribute__((optimize("-O0")))
sys_read(int fd, void *buffer, unsigned size) {
  /* If fd represent the stdout, terminate. */
  if (fd == STDOUT_FILENO)
    sys_exit(-1);

  unsigned res;
  uint8_t *ptr = buffer;
  if (fd == STDIN_FILENO) {
    /* Read from stdin using input_getc(). */
    res = size;
    while (size) {
      *ptr = input_getc();
      ptr++;
      size--;
    }
  } else {
    /* Read from file. */
    struct file_descriptor *_fd = get_file_descriptor(thread_current(), fd);
    /* Terminate or return -1 if
     *  - FD is not opened by the current thread, or
     *  - the inode designated by _FD is a directory.
     */
    if (_fd == NULL)
      sys_exit(-1);
    if (file_descriptor_is_dir(_fd))
      return -1;

    lock_acquire(&filesys_lock);
    res = file_read(_fd->_file, buffer, size);
    lock_release(&filesys_lock);
  }
  return (int)res;
}

static int __attribute__((optimize("-O0")))
sys_write(int fd, const void *buffer, unsigned size) {
  /* If fd represent stdin, terminate. */
  if (fd == STDIN_FILENO)
    sys_exit(-1);

  unsigned res;
  if (fd == STDOUT_FILENO) {
    /* Output to stdout using putbuf(). */
    res = size;
    putbuf(buffer, size);
  } else {
    /* Write to file. */
    struct file_descriptor *_fd = get_file_descriptor(thread_current(), fd);
    /* Terminate or return -1 if
     *  - FD is not opened by the current thread, or
     *  - the inode designated by _FD is a directory.
     */
    if (_fd == NULL)
      sys_exit(-1);
    if (file_descriptor_is_dir(_fd))
      return -1;

    lock_acquire(&filesys_lock);
    res = file_write(_fd->_file, buffer, size);
    lock_release(&filesys_lock);
  }
  return (int)res;
}

static void __attribute__((optimize("-O0")))
sys_seek(int fd, unsigned position) {
  struct file_descriptor *_fd = get_file_descriptor(thread_current(), fd);
  /* Terminate if
   *  - FD is not opened by the current thread, or
   *  - the inode designated by _FD is a directory.
   */
  if (_fd == NULL || file_descriptor_is_dir(_fd))
    sys_exit(-1);

  lock_acquire(&filesys_lock);
  file_seek(_fd->_file, position);
  lock_release(&filesys_lock);
}

static unsigned __attribute__((optimize("-O0")))
sys_tell(int fd) {
  struct file_descriptor *_fd = get_file_descriptor(thread_current(), fd);
  /* Terminate if
   *  - FD is not opened by the current thread, or
   *  - the inode designated by _FD is a directory.
   */
  if (_fd == NULL || file_descriptor_is_dir(_fd))
    sys_exit(-1);

  lock_acquire(&filesys_lock);
  unsigned res = file_tell(_fd->_file);
  lock_release(&filesys_lock);
  return res;
}

static void __attribute__((optimize("-O0")))
sys_close(int fd) {
  struct file_descriptor *_fd = get_file_descriptor(thread_current(), fd);
  /* Terminate if fd is not opened by the current thread. */
  if (_fd == NULL)
    sys_exit(-1);

  lock_acquire(&filesys_lock);
  if (_fd->_file == NULL)       /* FD designates a directory. */
    dir_close(_fd->_dir);
  else if (_fd->_dir == NULL)   /* FD designates a file. */
    file_close(_fd->_file);
  else
    ASSERT(false)
  lock_release(&filesys_lock);

  list_remove(&(_fd->elem));
  free(_fd);
}


static mapid_t
sys_mmap(int fd, void *addr) {
#ifdef VM
  if (!is_valid_user_addr(addr))
    return MAP_FAILED;

  /* FD 0 and 1 are not mappable. */
  if (fd == 0 || fd == 1)
    return MAP_FAILED;

  /* Fail if fd is not opened by the current thread. */
  struct file_descriptor *_fd = get_file_descriptor(thread_current(), fd);
  if (_fd == NULL)
    return MAP_FAILED;

  /* If addr is not page-aligned, fail. */
  if (pg_ofs(addr) != 0)
    return MAP_FAILED;

  /* If the file has 0 length, fail. */
  lock_acquire(&filesys_lock);
  int len = file_length(_fd->_file);
  lock_release(&filesys_lock);
  if (len == 0)
    return MAP_FAILED;

  /* You should use the file_reopen function to obtain a separate and
   * independent reference to the file for each of its mappings.  ------5.3.4
   */
  lock_acquire(&filesys_lock);
  struct file *file = file_reopen(_fd->_file);
  lock_release(&filesys_lock);
  off_t ofs = 0;
  uint32_t read_bytes = len;

  /* The first while-loop checks whether all pages do not overlap any existing
   * pages.
   * Return -1 if overlap happens.
   */
  void *addr_check = addr;
  while (read_bytes > 0) {
    uint32_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    if (pte_find(&thread_current()->page_table, addr_check, false) != NULL)
      return MAP_FAILED;
    read_bytes -= page_read_bytes;
    addr_check += PGSIZE;
  }

  /* The second while-loop maps pages of file to virtual address. */
  read_bytes = len;
  while (read_bytes > 0) {
    uint32_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    uint32_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Assert that the new page can always be inserted successfully, since we
     * checked overlap in the first while-loop.
     */
    ASSERT(page_table_map_file_page(file, ofs, addr,
                                  page_read_bytes,
                                  page_zero_bytes,
                                  true, true))

    read_bytes -= page_read_bytes;
    ofs += page_read_bytes;
    addr += PGSIZE;
  }

  mapid_t res = thread_current()->md_num++;
  return res;
#endif
}

static void
sys_munmap(mapid_t mapping) {
#ifdef VM
  page_table_remove_mmap(&thread_current()->mmap_descriptors, mapping);
#endif
}


static bool
is_valid_user_addr(void *addr) {
  return addr >= USER_ADDR_START && addr < PHYS_BASE;
}

static bool __attribute__((optimize("-O0")))
sys_chdir(const char *dir) {
  lock_acquire(&filesys_lock);
  /* Open the new directory. */
  struct thread *cur_thread = thread_current();
  struct dir *target_dir = filesys_opendir(dir);
  if (target_dir == NULL) {
    return false;
  }
  /* Close the old directory. */
  dir_close(cur_thread->current_dir);
  /* Set the current_dir of the current thread to the new directory. */
  cur_thread->current_dir = target_dir;
  lock_release(&filesys_lock);
  return true;
}

static bool __attribute__((optimize("-O0")))
sys_mkdir(const char* dir){
  lock_acquire(&filesys_lock);

  struct dir *d = NULL;
  char dir_name_buffer[20];
  char *dir_name = dir_name_buffer;
  bool is_dir = false;

  bool success = false;
  if (path_parser(dir, &d, &dir_name, &is_dir)) {
    /* If DIR designates the root directory, just return false. */
    if (is_dir && dir_name[0] == '\0') {
      success = false;
    } else {
      /* Create a subdirectory in D. */
      success = subdir_create(d, dir_name);
    }
  }
  dir_close(d);

  lock_release(&filesys_lock);
  return success;
}

static bool __attribute__((optimize("-O0")))
sys_readdir(int fd, char *name) {
  /* FD 0 and 1 are not readable. */
  if (fd == 0 || fd == 1)
    return false;

  lock_acquire(&filesys_lock);
  struct file_descriptor *_fd = get_file_descriptor(thread_current(), fd);
  /* Return false if fd is not opened by the current thread, or fd is not
   * a directory.
   */
  if (_fd == NULL || !file_descriptor_is_dir(_fd)) {
    lock_release(&filesys_lock);
    return false;
  }

  bool res = dir_readdir(_fd->_dir, name);
  lock_release(&filesys_lock);
  return res;
}

static bool __attribute__((optimize("-O0")))
sys_isdir(int fd) {
  /* FD 0 and 1 are not directory. */
  if (fd == 0 || fd == 1)
    return false;

  lock_acquire(&filesys_lock);
  struct file_descriptor *_fd = get_file_descriptor(thread_current(), fd);
  /* Return false if fd is not opened by the current thread, or fd is not
   * a directory.
   */
  if (_fd == NULL || !file_descriptor_is_dir(_fd)) {
    lock_release(&filesys_lock);
    return false;
  } else {
    lock_release(&filesys_lock);
    return true;
  }
}

static int __attribute__((optimize("-O0")))
sys_inumber(int fd) {
  /* FD 0 and 1 are not directory. */
  if (fd == 0 || fd == 1)
    sys_exit(-1);

  lock_acquire(&filesys_lock);
  struct file_descriptor *_fd = get_file_descriptor(thread_current(), fd);
  /* Return false if fd is not opened by the current thread. */
  if (_fd == NULL)
    sys_exit(-1);

  int res = -1;
  if (file_descriptor_is_dir(_fd))
    res = inode_get_inumber(_fd->_dir->inode);
  else
    res = inode_get_inumber(file_get_inode(_fd->_file));
  lock_release(&filesys_lock);
  return res;
}
/* Ruihang End */
