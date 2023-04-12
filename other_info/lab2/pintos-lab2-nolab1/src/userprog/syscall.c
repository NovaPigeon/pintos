#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <debug.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "process.h"
#include "pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

/* 存储所有系统调用函数的数组 */
#define SYSCALL_NUM 13
/* 指针大小 */
#define PTR_SIZE (sizeof(void *))

static void (*syscalls[SYSCALL_NUM])(struct intr_frame *);

static void syscall_handler (struct intr_frame *);

static void syscall_exec(struct intr_frame *) ;
static void syscall_halt(struct intr_frame *) NO_RETURN;
static void syscall_exit(struct intr_frame *) NO_RETURN;

static void syscall_wait(struct intr_frame *) ;
static void syscall_create(struct intr_frame *) ;
static void syscall_remove(struct intr_frame *) ;
static void syscall_open(struct intr_frame *) ;
static void syscall_filesize(struct intr_frame *) ;
static void syscall_read(struct intr_frame *) ;
static void syscall_write(struct intr_frame *) ;
static void syscall_seek(struct intr_frame *) ;
static void syscall_tell(struct intr_frame *) ;
static void syscall_close(struct intr_frame *) ;

static int get_user(const uint8_t *uadder);
static bool put_user(uint8_t *udst,uint8_t byte);
void terminate_offend_process(void) NO_RETURN;
static void *check_read_vaddr(const void*,size_t);
static void *check_write_vaddr(void *, size_t);
static void *check_str_vaddr(const char* str);
static struct thread_file *find_file(int fd);
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  
  syscalls[SYS_EXEC]=&syscall_exec;
  syscalls[SYS_HALT]=&syscall_halt;
  syscalls[SYS_EXIT]=&syscall_exit;
  syscalls[SYS_WAIT] = &syscall_wait;
  syscalls[SYS_CREATE] = &syscall_create;
  syscalls[SYS_REMOVE] = &syscall_remove;
  syscalls[SYS_OPEN] = &syscall_open;
  syscalls[SYS_WRITE] = &syscall_write;
  syscalls[SYS_SEEK] = &syscall_seek;
  syscalls[SYS_TELL] = &syscall_tell;
  syscalls[SYS_CLOSE] = &syscall_close;
  syscalls[SYS_READ] = &syscall_read;
  syscalls[SYS_FILESIZE] = &syscall_filesize;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int syscall_type=*(int *)check_read_vaddr(f->esp,sizeof(int));
  /* 若系统调用号非法，立即终止之 */
  if(syscall_type<0 || syscall_type>=SYSCALL_NUM)
    terminate_offend_process();
  syscalls[syscall_type](f);
}

/*
 * System Call: pid_t exec (const char *cmd_line)
 * - 运行 cmd_line，传递参数，并返回新进程的 ID.
 * - 如果无法加载或运行，应返回无效的 pid -1.
 * - 因此，父进程无法越过 exec 直接继续执行，他应等知道子进程是否顺利运行后才能继续，
 * 应该以适当的同步来确保这一点。 
 */
static void 
syscall_exec(struct intr_frame *f) 
{
  void* user_ptr=f->esp;
  char* cmd=*(char **)check_read_vaddr(user_ptr+PTR_SIZE,PTR_SIZE);
  check_str_vaddr(cmd);
  f->eax=process_execute(cmd);
}

/*
 * void halt (void)
 * - 终止 Pintos，使用 shutdown_power_off() (declared in devices/shutdown.h).
 * - 这应该很少使用，因为会丢失一些类似死锁之类的信息
 */
static void 
syscall_halt(struct intr_frame *f UNUSED) 
{
  shutdown_power_off();
}

/*
 * system call: void exit (int status)
 * 1. 终止当前进程，将 exit_state 交给内核
 * 2. 若其父进程正在 wait 当前进程，则 status 将会被返回给父进程， 
 * 一般来讲，若 exit_state=0，代表该进程正常返回，否则说明出现了错误
*/
static void syscall_exit(struct intr_frame *f)
{
  /* exit_state 作为 ARG0 压入栈中 */
  int exit_state=*(int *)check_read_vaddr(f->esp+PTR_SIZE,sizeof(int));
  dbg_printf("EXIT CODE: %d\n", exit_state);
  thread_current()->exit_state=exit_state;
  thread_exit();

}

/*
 * System Call: int wait (pid_t pid)
 * - 等待某个子进程结束（pid），并返回其 exit_state
 * - 如果该子进程仍活跃：
 *  - 等待他结束， 然后返回其 exit_state
 *  - 如果进程没有正常调用 exit() 以结束, 而是被内核终止（如被异常终止）, wait(pid) 应该返回 -1
 * - 父进程等待一个已经终止的子进程是完全合法的
 *  - 但是 wait 的返回仍要求是有效的，具体含义见上。
 * - 若以下任何条件为真，wait 必须立即失败并返回 -1
 *  - pid 并非调用者的直接子进程。（进程之间不存在继承关系，也就是不存在孙进程）（孤儿进程同理）
 *  - pid 不存在
 *  - 如果该子进程已经被 wait 过了
 * - 进程可以生成任意数量的子进程，以任意顺序等待他们，甚至先于子进程结束。
 *  - 应考虑所有情况
 *  - 进程的所有资源，包括其 struct thread，应该在进程终结后被释放，无论其父进程是否等待他，
 *     或者他是否先于其父进程结束。
 * - 必须确保 Pintos 在初始进程退出前不会终止
 *  - 现有的代码通过在 pintos_init() (in threads/init.c) 中调用 process_wait() 来实现
 *  - 我们建议您根据函数顶部的注释实现process_wait()，然后根据process_wwait()实现 syscall_wait()。
 */
static void 
syscall_wait(struct intr_frame *f)
{
  int pid=*(int *)check_read_vaddr(f->esp+PTR_SIZE,sizeof(int));
  f->eax=process_wait(pid);
}

/** System Call: bool create (const char *file, unsigned initial_size)
 * - 创建一个名为file的新文件，初始大小为initial_size字节。如果成功，则返回true，否则返回false。
 * - 创建新文件不会打开它：打开新文件是一个单独的操作，需要使用 syscall_open()。
 */
static void 
syscall_create(struct intr_frame *f)
{
  char* file=*(char **)check_read_vaddr(f->esp+PTR_SIZE,PTR_SIZE);
  check_str_vaddr(file);
  unsigned initial_size=*(unsigned *)
                        check_read_vaddr(f->esp+2*PTR_SIZE,sizeof(unsigned));

  lock_acquire(&filesys_lock);
  f->eax=filesys_create(file,initial_size);
  lock_release(&filesys_lock);
}

/** System Call: bool remove (const char *file)
 * - 删除名为file的文件。如果成功，则返回true，否则返回false。
 * - 无论文件是打开还是关闭，都可以删除该文件，删除打开的文件不会关闭该文件。
 */
static void
syscall_remove(struct intr_frame *f)
{
  char *file=*(char **)check_read_vaddr(f->esp+PTR_SIZE,PTR_SIZE);
  check_str_vaddr(file);

  lock_acquire(&filesys_lock);
  f->eax=filesys_remove(file);
  lock_release(&filesys_lock);
}

/** System Call: int open (const char *file)
 * - 打开名为file的文件。返回一个称为“文件描述符”（fd）的非负整数句柄，如果无法打开文件，则返回-1。
 * - 编号为0和1的文件描述符被保留给console：
 *  - fd 0（STDIN_FILENO）是标准输入，fd 1（STDOUT_FILENO）是标准输出。
 *  - 开放系统调用永远不会返回这两个文件描述符中的任何一个，但它们作为系统调用参数是有效的，如下所述。
 * - 每个进程都有一组独立的文件描述符。文件描述符不被子进程继承（与Unix语义不同）
 * - 当单个文件被多次打开时，无论是由单个进程还是不同进程打开，每次打开都会返回一个新的文件描述符。
 *   单个文件的不同文件描述符在单独的关闭调用中独立关闭，并且它们不共享文件位置。
 */
static void
syscall_open(struct intr_frame *f)
{
  char *file=*(char **)check_read_vaddr(f->esp+PTR_SIZE,PTR_SIZE);
  check_str_vaddr(file);

  /* 打开文件，若失败，则返回 -1 */
  lock_acquire(&filesys_lock);
  struct file *file_opened=filesys_open(file);
  lock_release(&filesys_lock);

  if(file_opened!=NULL)
  {
    struct thread* t_cur=thread_current();
    struct thread_file *file_info=malloc(sizeof(struct thread_file));
    file_info->fd=t_cur->max_alloc_fd+1;
    t_cur->max_alloc_fd++;
    file_info->file=file_opened;
    list_push_back(&t_cur->files,&file_info->file_elem);
    f->eax=file_info->fd;
  }
  else
    f->eax=-1;
}

/** System Call: int filesize (int fd)
 * - 返回文件描述符fd对应文件的大小，以字节为单位。
 */
static void
syscall_filesize(struct intr_frame *f)
{
  int fd=*(int *)check_read_vaddr(f->esp+PTR_SIZE,sizeof(int));
  struct thread_file *file_info=find_file(fd);
  if(file_info!=NULL)
  {
    lock_acquire(&filesys_lock);
    f->eax = file_length(file_info->file);
    lock_release(&filesys_lock);
  }
  else
    f->eax=-1;
}

/** System Call: int read (int fd, void *buffer, unsigned size)
 * - 从文件描述符fd对应的文件中读取size个字节到buffer中。
 *   返回实际读取的字节数（若到达文件结尾，则为0），或者返回-1（不是因为到达文件结尾），表示读取失败。
 * - 当fd为0时，从键盘读取输入数据，使用input_getc()函数进行读取。
 */
static void
syscall_read(struct intr_frame *f)
{
  void *user_ptr = f->esp;
  int fd = *(int *)check_read_vaddr(user_ptr + PTR_SIZE, sizeof(int));
  uint8_t *buffer = *(uint8_t **)check_read_vaddr(user_ptr + 2 * PTR_SIZE, PTR_SIZE);
  unsigned size = *(int *)check_read_vaddr(user_ptr + 3 * PTR_SIZE, sizeof(unsigned));
  check_write_vaddr(buffer,size);
  
  if(fd==STDIN_FILENO)
  {
    for(unsigned i=0;i<size;++i)
      buffer[i]=input_getc();
    f->eax=size;
  }
  else
  {
    struct thread_file *file_info=find_file(fd);
    if(file_info!=NULL)
    {
      lock_acquire(&filesys_lock);
      f->eax = file_read(file_info->file, buffer, size);
      lock_release(&filesys_lock);
    }
    else
      f->eax=-1;
  }
}

/** System Call: int write (int fd, const void *buffer, unsigned size)
 * - 将buffer中的size个字节写入到fd对应的文件中。
 * 返回实际写入的字节数，如果有些字节无法写入，则返回比size小的实际写入的字节数。
 * - 当写入到文件的末尾时，文件通常会被扩展，但当前基本的文件系统并没有实现文件增长功能。
 * 期望的行为是尽可能多地写入字节，直到文件末尾，不做扩展，并返回实际写入的字节数，如果没有字节写入则返回0。
 * - 当fd为1时，将数据写入控制台。向控制台写入文本时，应该一次性调用putbuf()函数中将buffer中的所有内容写入，
 * 至少当size不超过几百字节时应该这样做（可以将较大的buffer分成多次写入）。
 * 否则，由不同进程输出的文本可能会交错在控制台上。
 */
static void
syscall_write(struct intr_frame *f)
{
  void *user_ptr=f->esp;
  int fd = *(int *)check_read_vaddr(user_ptr + PTR_SIZE,sizeof(int));
  char *buffer = *(char **)check_read_vaddr(user_ptr + 2*PTR_SIZE ,PTR_SIZE);
  unsigned size = *(int *)check_read_vaddr(user_ptr + 3*PTR_SIZE,sizeof(unsigned));
  check_str_vaddr(buffer);
  if (fd == STDOUT_FILENO)
  {
    putbuf(buffer, size);
    f->eax = size;
  }
  else
  {
    struct thread_file *file_info=find_file(fd);
    if(file_info!=NULL)
    {
      lock_acquire(&filesys_lock);
      f->eax=file_write(file_info->file,buffer,size);
      lock_release(&filesys_lock);
    }
    else
      f->eax=-1;
  }
}

/** System Call: void seek (int fd, unsigned position)
 * - 将fd对应的文件中下一次要读或写的字节更改为从文件开头算起的position字节处（position为0表示文件开头）
 * - 如果尝试从文件的结尾位置向后读取，则会读取0个字节，表示到达文件结尾。
 * - 如果在文件的结尾位置向后写入，则文件将扩展，未写入的空间将以零填充。
 * （但在Pintos中，文件的长度是固定的，直到项目4完成为止，因此超过文件末尾写入会返回错误。）
 *  这些语义在文件系统中实现，不需要在系统调用实现中进行特殊处理。
 */
static void
syscall_seek(struct intr_frame *f)
{
  int fd = *(int *)check_read_vaddr(f->esp + PTR_SIZE, sizeof(int));
  unsigned position=*(unsigned *)check_read_vaddr(f->esp+2*PTR_SIZE,sizeof(unsigned));
  struct thread_file *file_info = find_file(fd);
  if (file_info != NULL)
  {
    lock_acquire(&filesys_lock);
    file_seek(file_info->file,position);
    lock_release(&filesys_lock);
  }
}

/** System Call: unsigned tell (int fd)
 * 返回fd对应的文件中下一个要读或写的字节的位置，以从文件开头算起的字节数表示。
 */
static void
syscall_tell(struct intr_frame *f)
{
  int fd = *(int *)check_read_vaddr(f->esp + PTR_SIZE, sizeof(int));
  struct thread_file *file_info = find_file(fd);
  if (file_info != NULL)
  {
    lock_acquire(&filesys_lock);
    f->eax = file_tell(file_info->file);
    lock_release(&filesys_lock);
  }
  else
    f->eax = -1;
}

/** System Call: void close (int fd)
 * 关闭文件描述符fd。
 * 退出或终止进程会自动关闭所有打开的文件描述符，就好像对每个文件都调用了该函数一样。
 */
static void
syscall_close(struct intr_frame *f)
{
  int fd=*(int *)check_read_vaddr(f->esp+PTR_SIZE,PTR_SIZE);
  struct thread_file *file_info=find_file(fd);
  if(file_info!=NULL)
  {
    lock_acquire(&filesys_lock);
    file_close(file_info->file);
    list_remove(&file_info->file_elem);
    free(file_info);
    lock_release(&filesys_lock);

  }
}

/**
 * 在用户虚拟地址 UADDR 读取一个字节。
 * UADDR 必须低于 PHYS_BASE。
 * 如果成功则返回字节值，如果发生段错误则返回 -1。
 */
static int
get_user(const uint8_t *uaddr)
{
  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a"(result)
      : "m"(*uaddr));
  return result;
}

/* 在用户虚拟地址 UDST 写 BYTE 个字节
   UDST 必须低于 PHYS_BASE.
   如果成功则返回 true，如果发生段错误则返回 false */
static bool
put_user(uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a"(error_code), "=m"(*udst)
      : "q"(byte));
  return error_code != -1;
}

/**
 * 系统调用的指针非法时，
 * 终止当前进程，并设置 exit_state=-1
 */
void 
terminate_offend_process(void)
{
  thread_current()->exit_state=-1;
  thread_exit();
}

/**
 * 判断从指针 ptr 开始的 size 个字节是否能合法读取
 * 若是，返回 ptr，若不是，调用 terminate_offend_process()
 * 终止进程，无返回
 */
static void *
check_read_vaddr(const void *vaddr, size_t size)
{
  /* 若 ptr 不在用户虚拟空间内，直接终止 */
  if(!is_user_vaddr(vaddr))
    terminate_offend_process();
  void *ptr=pagedir_get_page(thread_current()->pagedir,vaddr);
  if(!ptr)
    terminate_offend_process();
  
  /* 依次检查每个字节 */
  for(size_t i=0;i<size;++i)
  {
    if(get_user(vaddr+i)==-1)
      terminate_offend_process();
  }
  return (void *)vaddr;
  
}
/**
 * 判断从指针 ptr 开始的 size 个字节是否能合法写入
 * 若是，返回 ptr，若不是，调用 terminate_offend_process()
 * 终止进程，无返回
 */
static void *check_write_vaddr(void *vaddr, size_t size)
{
  /* 若 ptr 不在用户虚拟空间内，直接终止 */
  if (!is_user_vaddr(vaddr))
    terminate_offend_process();
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!ptr)
    terminate_offend_process();

  /* 依次检查每个字节 */
  for (size_t i = 0; i < size; ++i)
  {
    if (!put_user(vaddr + i,0))
      terminate_offend_process();
  }
  return (void *)vaddr;
}

/** 由于字符串的 size 不是固定的，其长度由 '\0' 标识， 
 *  所以需要特定的判断函数
 */
static void *
check_str_vaddr(const char *str)
{
  /* 若 ptr 不在用户虚拟空间内，直接终止 */
  if (!is_user_vaddr((void *)str))
    terminate_offend_process();
  void *ptr = pagedir_get_page(thread_current()->pagedir, (void *)str);
  if (!ptr)
    terminate_offend_process();

  uint8_t *str_tmp=(uint8_t *)str;
  /* 依次检查每个字节 */
  while(true)
  {
    int c=get_user(str_tmp);
    if(c==-1)
      terminate_offend_process();
    if(c=='\0')
      return (char *)str;
    str_tmp++;
  }
}

/**
 * 由 fd 获取文件
 * 若文件已经打开，则返回 thead_file 的指针，
 * 否则，返回空指针。
 */
static struct thread_file *find_file(int fd)
{
  struct list_elem *e;
  struct thread_file* file_info=NULL;
  struct list *files=&thread_current()->files;
  for(e=list_begin(files);e!=list_end(files);e=list_next(e))
  {
    file_info=list_entry(e,struct thread_file,file_elem);
    if(fd==file_info->fd)
      return file_info;
  }
  return NULL;
}