#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include "lib/kernel/list.h"
#include <stdint.h>
#include <devices/timer.h>
#include "fixed-point.h"
#include "synch.h"

/** States in a thread's life cycle. */
enum thread_status
{
   THREAD_RUNNING, /**< Running thread. */
   THREAD_READY,   /**< Not running but ready to run. */
   THREAD_BLOCKED, /**< Waiting for an event to trigger. */
   THREAD_DYING    /**< About to be destroyed. */
};

/** Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t)-1) /**< Error value for tid_t. */

/** Thread priorities. */
#define PRI_MIN 0      /**< Lowest priority. */
#define PRI_DEFAULT 31 /**< Default priority. */
#define PRI_MAX 63     /**< Highest priority. */

#define NICE_MAX 20
#define NICE_MIN -20
#define NICE_DEFAULT 0

struct thread;
struct as_child_info;
struct thread_file;

/** A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/** The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
{
   /* Owned by thread.c. */
   tid_t tid;                       /**< Thread identifier. */
   enum thread_status status;       /**< Thread state. */
   char name[16];                   /**< Name (for debugging purposes). */
   uint8_t *stack;                  /**< Saved stack pointer. */
   int priority;                    /**< Priority. */
   int prev_priority;               /**< 用于保存线程受捐献之前的优先级，在释放锁之后恢复. */
   struct list_elem allelem;        /**< List element for all threads list. */

   /* Shared between thread.c and synch.c. */
   struct list_elem elem;           /**< List element. */

   struct lock *wait_lock;          /**< 当前线程正在等待的 lock. */
   struct list hold_locks;          /**< 当前线程持有的锁的列表，按锁的捐献优先级有序排列. */

   /* mlfqs */
   int nice;
   fixed_point_t recent_cpu;

#ifdef USERPROG
   /* Owned by userprog/process.c. */
   uint32_t *pagedir;               /**< Page directory. */
#endif

   /* Owned by thread.c. */
   unsigned magic;                  /**< Detects stack overflow. */

   struct as_child_info *as_child;  /**< 记录当前进程作为子进程的信息. */
   struct list childs;              /**< 当前进程的子进程. */
   struct thread* parent;           /**< 父进程. */      
   int exit_state;                  /**< 用于记录退出状态，初始化为 0. */
   bool success;                    /**< 记录当前进程是否被成功加载/运行. */
   struct semaphore sema_exec;      /**< 实现 exec 时的同步. */

   struct list files;               /**< 存储进程打开的文件. */

   /**< 记录描述符池中已经被分配的最大文件描述符，用于分配下一个打开的文件描述符，我们设计文件描述符只增不减. */
   int max_alloc_fd;    
   struct file* exec_prog;          /**< 记录当前进程正在运行的文件，该文件无法被修改. */  
};

/**
 * 存储当前进程作为子进程的信息，因为父进程应当能在子进程消亡后仍能访问这些信息，
 * 所以不应该直接把这些信息写在 thread 里，而应另起结构体，并用 malloc
 * 将该结构体分配到堆上。
 */
struct as_child_info
{
   /* 初始化为本进程的 t_id，在进程消亡后父进程仍能访问之 */
   tid_t tid;
   /* 记录当前进程是否终止 */
   bool is_alive;
   /* 记录当前进程是否已经被 wait */
   bool is_waited;
   /* 在进程消亡后记录其 exit_state */
   int store_exit_state;
   /* 指向进程本身，当进程消亡后被置为0 */
   struct thread *process_self;
   /* 信号量，用于实现 wait 时的同步 */
   struct semaphore wait_sema;
   /* 作为子线程，供父进程访问的抓手 */
   struct list_elem as_child_elem;
};

/* 用于存储进程打开的文件的信息 */
struct thread_file
{
   /* 文件描述符 */
   int fd;
   /* 文件指针 */
   struct file* file;
   struct list_elem file_elem;

};

/** If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority, thread_func *, void *);

void thread_block(void);
void thread_unblock(struct thread *);

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

/** Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func(struct thread *t, void *aux);
void thread_foreach(thread_action_func *, void *);

int thread_get_priority(void);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

/* 比较函数，用于对 ready_list 降序排序 */
bool thread_priority_cmp(const struct list_elem *a,
                         const struct list_elem *b,
                         void *aux);
void update_ready_list(void);
void print_ready_list(void);

#endif /**< threads/thread.h */
