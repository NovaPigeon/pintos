#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <debug.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "process.h"
#include "pagedir.h"

/* 存储所有系统调用函数的数组 */
#define SYSCALL_NUM 20
/* 指针大小 */
#define PTR_SIZE (sizeof(void *))

static void (*syscalls[SYSCALL_NUM])(struct intr_frame *);

static void syscall_handler (struct intr_frame *);

static void syscall_exec(struct intr_frame *) NO_RETURN;
static void syscall_halt(struct intr_frame *) NO_RETURN;
static void syscall_exit(struct intr_frame *) NO_RETURN;

static void syscall_wait(struct intr_frame *) NO_RETURN;
static void syscall_create(struct intr_frame *) NO_RETURN;
static void syscall_remove(struct intr_frame *) NO_RETURN;
static void syscall_open(struct intr_frame *) NO_RETURN;
static void syscall_filesize(struct intr_frame *) NO_RETURN;
static void syscall_read(struct intr_frame *) NO_RETURN;
static void syscall_write(struct intr_frame *) NO_RETURN;
static void syscall_seek(struct intr_frame *) NO_RETURN;
static void syscall_tell(struct intr_frame *) NO_RETURN;
static void syscall_close(struct intr_frame *) NO_RETURN;

static int get_user(const uint8_t *uadder);
static bool put_user(uint8_t *udst,uint8_t byte);
void terminate_offend_process(void) NO_RETURN;
static void *check_read_vaddr(const void*,size_t);
static void *check_write_vaddr(void *, size_t);
static void *check_str_vaddr(const char* str);
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
static void 
syscall_create(struct intr_frame *f)
{

}
static void 
syscall_remove(struct intr_frame *f)
{

}
static void 
syscall_open(struct intr_frame *f)
{

}
static void 
syscall_filesize(struct intr_frame *f)
{

}
static void 
syscall_read(struct intr_frame *f)
{

}
static void 
syscall_write(struct intr_frame *f)
{
  void *user_ptr=f->esp;
  int fd = *(int *)(user_ptr + PTR_SIZE);
  char *buf = *(char **)(user_ptr + 2*PTR_SIZE );
  size_t size = *(int *)(user_ptr + 3*PTR_SIZE);

  if (fd == 1)
  {
    putbuf(buf, size);
    f->eax = size;
  }
}
static void 
syscall_seek(struct intr_frame *f)
{

}
static void 
syscall_tell(struct intr_frame *f)
{

}
static void 
syscall_close(struct intr_frame *f)
{

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