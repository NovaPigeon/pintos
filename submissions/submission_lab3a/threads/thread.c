#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/syscall.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif
#include "vm/page.h"
#include "vm/swap.h"
#include "vm/frame.h"
/* mlfqs */
fixed_point_t load_avg;

/** Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/** List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/** List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/** Idle thread. */
static struct thread *idle_thread;

/** Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/** Lock used by allocate_tid(). */
static struct lock tid_lock;

/** Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /**< Return address. */
    thread_func *function;      /**< Function to call. */
    void *aux;                  /**< Auxiliary data for function. */
  };

/** Statistics. */
static long long idle_ticks;    /**< # of timer ticks spent idle. */
static long long kernel_ticks;  /**< # of timer ticks in kernel threads. */
static long long user_ticks;    /**< # of timer ticks in user programs. */

/** Scheduling. */
#define TIME_SLICE 4            /**< # of timer ticks to give each thread. */
static unsigned thread_ticks;   /**< # of timer ticks since last yield. */

/** If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

/** mlfqs */

/* 更新单一线程的优先级*/
static void mlfqs_priority_update(struct thread* t,void* aux UNUSED);
/* 更新单一线程的 recent_cpu */
static void mlfqs_recent_cpu_update(struct thread* t,void* aux UNUSED);
/* 当前线程的 recent_cpu 自增1 */
static void mlfqs_recent_cpu_increase(void);
/* 更新load_avg */
static void mlfqs_load_avg_update(void);

/** Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);
  /* mlfqs 策略对于 lab 2 而言更快一点，但策略选取并不影响结果的正确性 */
  thread_mlfqs=true;
  /* 初始化文件系统的锁 */
  lock_init(&filesys_lock);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

/** Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);
  /* 初始化 load_avg */
  load_avg=INT_TO_FP(0);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/** Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;
  
  /* mlfqs
   * 每 4 ticks，更新所有线程的 priority
   * 每 1 second（TIMER_FREQ ticks）更新所有线程的 load_avg 和 recent_cpu
   * 每 1 tick，当前正在运行线程的 recent_cpu 增加 1
   */
  if(thread_mlfqs)
  {
    int64_t ticks=timer_ticks();
    mlfqs_recent_cpu_increase();
    if(ticks%TIMER_FREQ==0)
    {
      mlfqs_load_avg_update();
      thread_foreach((thread_action_func*)&mlfqs_recent_cpu_update,NULL);
    }
    if (ticks % 4 == 0)
      thread_foreach((thread_action_func *)&mlfqs_priority_update, NULL);
  }
  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/** Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/** Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* 将结构体分配到堆上 */
  t->as_child=malloc(sizeof(struct as_child_info));
  t->as_child->tid=t->tid;
  t->as_child->process_self=t;
  t->as_child->is_alive=true;
  t->as_child->store_exit_state=0;
  t->as_child->is_waited=false;
  sema_init(&t->as_child->wait_sema,0);
  list_push_back(&thread_current()->childs,&t->as_child->as_child_elem);

  old_level=intr_disable();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  intr_set_level(old_level);
  
  /* Add to run queue. */
  thread_unblock (t);
  
  old_level=intr_disable();

  /* 若有任何线程被加入 ready_list 时优先级高于当前线程的优先级，
   当前线程应当立即放弃 CPU 控制权*/
  if(thread_current()->priority < priority)
    thread_yield();
  intr_set_level(old_level);
  return tid;
}

/** Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);
  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/** Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  list_insert_ordered(&ready_list,
                      &t->elem,
                      (list_less_func*)&thread_priority_cmp,
                       NULL);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/** Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/** Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/** Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/** Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());
  
  struct thread *t_cur = thread_current();

#ifdef VM
  /* 释放扩充页表的资源 */
  vm_destroy_spage_table(t_cur->spage_table);
  t_cur->spage_table=NULL;
#endif

#ifdef USERPROG
  process_exit ();
  /* 处理终止信息 */
  printf("%s: exit(%d)\n", thread_name(), t_cur->exit_state);
#endif



  /* 关闭当前进程正在运行的文件 */
  if (t_cur->exec_prog != NULL)
  {
    lock_acquire(&filesys_lock);
    file_allow_write(t_cur->exec_prog);
    file_close(t_cur->exec_prog);
    lock_release(&filesys_lock);
  }

  /* 当进程消亡时，清空所有子进程的资源，因为他们不会再被访问 */
  struct list_elem *child_elem=list_begin(&t_cur->childs);
  struct as_child_info *child_info=NULL;
  while(!list_empty(&t_cur->childs))
  {
    child_elem = list_pop_front(&t_cur->childs);
    child_info = list_entry(child_elem, struct as_child_info, as_child_elem);
    if (child_info->is_alive == true)
      child_info->process_self->parent = NULL;
    free(child_info);
  }
  /* 进程消亡时，需要释放其打开的所有文件资源 */
  struct list_elem *elem;
  struct list *files_list=&t_cur->files;
  struct thread_file *file_info;

  lock_acquire(&filesys_lock);
  while(!list_empty(files_list))
  {
    elem=list_pop_front(files_list);
    file_info=list_entry(elem,struct thread_file,file_elem);
    file_close(file_info->file);
    free(file_info);
  }
  lock_release(&filesys_lock);

  if(t_cur->parent!=NULL)
  {
    t_cur->as_child->is_alive=false;
    /* 进程消亡后应不能再访问结构体 thread 中的信息 */
    t_cur->as_child->process_self=NULL;
    /* 将 exit_state 存储，用于父进程在子进程消亡后访问 */
    t_cur->as_child->store_exit_state = t_cur->exit_state;
    /* 将控制权交给父进程 */
    //if (t_cur->as_child->is_waited == true)
    sema_up(&t_cur->as_child->wait_sema);
    sema_up(&t_cur->sema_exec);
  }

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable();
  list_remove (&t_cur->allelem);
  t_cur->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/** Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread) 
    list_insert_ordered (&ready_list, 
                         &cur->elem,
                         (list_less_func*)&thread_priority_cmp,
                         NULL);
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/** Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/** Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
    /* A thread may raise or lower its own priority at any time, 
    but lowering its priority such that it no longer has the highest priority 
    must cause it to immediately yield the CPU. */
    /* 如果进程优先级降低，则立刻交出 CPU 控制权 */
    /* 如果在调用该函数时设置了较低的优先级，而此时当前线程其实拥有较高
       的捐赠优先级，则先改变 prev_priority, priority 不变 */
    if(thread_mlfqs)
      return;
    enum intr_level old_level=intr_disable();
    struct thread* curr_thread=thread_current();
    int old_priority=curr_thread->priority;

    /* 若当前线程持有锁，且设置较低优先级，则只改变 prev_priority 
       否则，除了改变 prev_priority，还要做其他判断 */
    curr_thread->prev_priority=new_priority;
    
    /* 若当前线程未持有锁，或设置的优先级高于当前优先级 */
    if(list_empty(&curr_thread->hold_locks) ||
       new_priority>curr_thread->priority )
    { 
       //printf("%d %d\n",curr_thread->priority,new_priority);
       curr_thread->priority=new_priority;
    }

    /* 若当前线程未持有锁，且设置的优先级低于当前优先级 */
    if(curr_thread->priority < old_priority)
      thread_yield();
    intr_set_level(old_level);
}

/** Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  if(thread_mlfqs)
    mlfqs_priority_update(thread_current(),NULL);
  return thread_current ()->priority;
}

/** Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) 
{
  /* Not yet implemented. */
  if(nice>NICE_MAX)
    thread_current()->nice=NICE_MAX;
  else if(nice<NICE_MIN)
    thread_current()->nice=NICE_MIN;
  else thread_current()->nice=nice;

  mlfqs_priority_update(thread_current(),NULL);

  thread_yield();
}

/** Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  /* Not yet implemented. */
  return thread_current()->nice;
}

/** Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  /* Not yet implemented. */
  return FP_TO_INT_ROUND_NEAREAST(MUL_FI(load_avg,100));
}

/** Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  /* Not yet implemented. */
  return FP_TO_INT_ROUND_NEAREAST(MUL_FI(thread_current()->recent_cpu,100));
}

/** Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);
  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/** Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /**< The scheduler runs with interrupts off. */
  function (aux);       /**< Execute the thread function. */
  thread_exit ();       /**< If function() returns, kill the thread. */
}

/** Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/** Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/** Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  //printf("Init %d\n",t->priority)
  t->magic = THREAD_MAGIC;

  /* lab 2 */
  t->exit_state = 0;
  list_init(&t->childs);
  list_init(&t->files);
  sema_init(&t->sema_exec, 0);
  t->success = false;
  t->max_alloc_fd=STDOUT_FILENO;

  if (t == initial_thread)
      t->parent = NULL;
  else
      t->parent = thread_current();

  /* lab 1 */

  /* 初始化当前线程 */
  list_init(&t->hold_locks);
  t->wait_lock=NULL;
  
  /*
   * The initial thread starts with a nice value of zero.
   * Other threads start with a nice value inherited from their parent thread.
   * The initial value of recent_cpu is 0 in the first thread created, 
   * or the parent's value in other new threads.
   */
  if(thread_mlfqs)
  {
    if(strcmp(t->name,"main")==0)
    {
      t->nice=NICE_DEFAULT;
      t->recent_cpu=INT_TO_FP(0);
    }
    else
    {
      t->nice=thread_get_nice();
      t->recent_cpu=DIV_FI(thread_get_recent_cpu(),100);
    }
  }
  if (!thread_mlfqs)
      t->priority = priority;
  else
      mlfqs_priority_update(t,NULL);
  t->prev_priority=t->priority;

  old_level = intr_disable ();
  list_insert_ordered(&all_list,
                      &t->allelem,
                      (list_less_func*)thread_priority_cmp,
                      NULL);
  intr_set_level (old_level);

}

/** Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/** Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (list_empty (&ready_list))
    return idle_thread;
  else
      return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/** Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/** Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));
  
  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/** Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}
bool
thread_priority_cmp(const struct list_elem *a,
                    const struct list_elem *b,
                    void *aux)
{
  aux=aux;
  struct thread* threada=list_entry(a,struct thread,elem);
  struct thread* threadb=list_entry(b,struct thread,elem);
  return threada->priority > threadb->priority;
}

void update_ready_list(void)
{
  list_sort(&ready_list,(list_less_func*)thread_priority_cmp,NULL);
}

void print_ready_list(void)
{
  printf("READY_LIST\n");
  if (list_empty(&ready_list))
    printf("READY_LIST_EMPTY\n");
  else
  {
    struct list_elem *e = list_front(&ready_list);
    while (e != list_end(&ready_list))
    {
      struct thread *t = list_entry(e, struct thread, elem);
      printf("THREAD: %s; PRI: %d;\n", t->name, t->priority);
      e = list_next(e);
    }
  }
}
/** Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);

/* MLFQS */

/* 更新单一线程的优先级
 * PRI = PRI_MAX - RECENT_CPU / 4 - 2 * NICE 
 * 每 4 ticks 发生一次
 */ 
static void mlfqs_priority_update(struct thread * t, void *aux UNUSED)
{
  if( t!=idle_thread)
  {
    int pri=PRI_MAX-FP_TO_INT_ROUND_NEAREAST(t->recent_cpu)/4-2*t->nice;
    if(pri>PRI_MAX)
      pri=PRI_MAX;
    if(pri<PRI_MIN)
      pri=PRI_MIN;
    t->priority=pri;
  }
}

/* 更新单一线程的 recent_cpu 
 * recent_cpu=(2*load_avg/(2*load_avg+1))*recent_cpu+nice, 且恒大于 0
 * 每 1 second(TIMER_FREQ*ticks) 发生一次
 */
static void mlfqs_recent_cpu_update(struct thread *t, void *aux UNUSED)
{
  if(t!=idle_thread)
  {
    fixed_point_t r_cpu=
      MUL_FF(
        DIV_FF(
          load_avg*2,
          ADD_FI(load_avg*2,1)
          ),
        t->recent_cpu
      )+INT_TO_FP(t->nice);
    if(r_cpu<0)
      r_cpu=0;
    t->recent_cpu=r_cpu;
  }
}
/* 当前线程的 recent_cpu 自增1，
 * 每 1 tick 发生一次
 */
static void mlfqs_recent_cpu_increase(void)
{
  struct thread* t=thread_current();
  if(t!=idle_thread)
    t->recent_cpu=ADD_FI(t->recent_cpu,1);
}
/* 更新load_avg
 * load_avg=(59/60)*load_avg+(1/60)*ready_threads
 * ready_threads 是正在运行中和在ready_list中的线程的数量，除了idle
 * 每 1 second 发生一次
 */
static void mlfqs_load_avg_update(void)
{
  fixed_point_t coefficient_1=DIV_FF(INT_TO_FP(59),INT_TO_FP(60));
  fixed_point_t coefficient_2=DIV_FF(INT_TO_FP(1),INT_TO_FP(60));
  int ready_threads=list_size(&ready_list);
  if(thread_current()!=idle_thread)
    ready_threads=ready_threads+1;
  load_avg=MUL_FF(coefficient_1,load_avg)+
           coefficient_2*ready_threads;
}