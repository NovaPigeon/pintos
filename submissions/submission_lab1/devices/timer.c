#include "devices/timer.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include "devices/pit.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "lib/kernel/list.h"

//#define DEBUG
/** See [8254] for hardware details of the 8254 timer chip. */

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/** Number of timer ticks since OS booted. */
static int64_t ticks;

/** Number of loops per timer tick.
   Initialized by timer_calibrate(). */
static unsigned loops_per_tick;

/** sleeping list，存放睡眠中线程的列表 */
static struct list sleeping_list;

/** 睡眠中的线程，记录在列表中的节点，剩余的睡眠时间，和线程本身 */
struct sleeping_thread
{
  struct thread* sleep_thread;
  struct list_elem elem;
  int64_t wake_time;
};

void printinfo(void);
static intr_handler_func timer_interrupt;
static bool wake_time_cmp(const struct list_elem *a,
                          const struct list_elem *b,
                          void *aux);
static bool too_many_loops (unsigned loops);
static void busy_wait (int64_t loops);
static void real_time_sleep (int64_t num, int32_t denom);
static void real_time_delay (int64_t num, int32_t denom);

/* Print debug information: sleeping list, timer ticks, current thread priority etc. */
void printinfo(void)
{
  #ifdef DEBUG
  if(list_empty(&sleeping_list))
    return;
  struct list_elem *elem_tmp = list_front(&sleeping_list);
  printf("current prio: %d\n",thread_current()->priority);
  printf("timer ticks: %08" PRIi64 "\n", timer_ticks());
  while (elem_tmp != list_end(&sleeping_list))
  {
    struct sleeping_thread *thread_tmp = list_entry(elem_tmp, struct sleeping_thread, elem);
    printf("thread %s ;
            prio: %d ;
            wake_time %08 " PRId64 ";
            tick: %08"PRId64"\n",
            thread_tmp->sleep_thread->name,
            thread_tmp->sleep_thread->priority,
            thread_tmp->wake_time,
            timer_ticks());
    elem_tmp = list_next(elem_tmp);
  }
  printf("\n\n");
  #endif
}

/** Sets up the timer to interrupt TIMER_FREQ times per second,
   and registers the corresponding interrupt. */
void
timer_init (void) 
{
  pit_configure_channel (0, 2, TIMER_FREQ);
  intr_register_ext (0x20, timer_interrupt, "8254 Timer");
  list_init(&sleeping_list);
}

/** Calibrates loops_per_tick, used to implement brief delays. */
void
timer_calibrate (void) 
{
  unsigned high_bit, test_bit;

  ASSERT (intr_get_level () == INTR_ON);
  printf ("Calibrating timer...  ");

  /* Approximate loops_per_tick as the largest power-of-two
     still less than one timer tick. */
  loops_per_tick = 1u << 10;
  while (!too_many_loops (loops_per_tick << 1)) 
    {
      loops_per_tick <<= 1;
      ASSERT (loops_per_tick != 0);
    }

  /* Refine the next 8 bits of loops_per_tick. */
  high_bit = loops_per_tick;
  for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1)
    if (!too_many_loops (high_bit | test_bit))
      loops_per_tick |= test_bit;

  printf ("%'"PRIu64" loops/s.\n", (uint64_t) loops_per_tick * TIMER_FREQ);
}

/** Returns the number of timer ticks since the OS booted. */
int64_t
timer_ticks (void) 
{
  enum intr_level old_level = intr_disable ();
  int64_t t = ticks;
  intr_set_level (old_level);
  return t;
}

/** Returns the number of timer ticks elapsed since THEN, which
   should be a value once returned by timer_ticks(). */
int64_t
timer_elapsed (int64_t then) 
{
  return timer_ticks () - then;
}

/** Sleeps for approximately TICKS timer ticks.  Interrupts must
   be turned on. */
void
timer_sleep (int64_t ticks) 
{
  ASSERT(intr_get_level()==INTR_ON);
  
  /* ticks<0 时，测试应该正常返回，而非出现 Kernel Panic */
  if(ticks<0)
    return; 
  
  /* 不知道为什么用了 malloc 之后时间有误差，
     导致 alarm_priority 样例无法通过 */
  struct sleeping_thread current_sleep_thread;
  
  /* 防止被中断 */
  enum intr_level old_level = intr_disable();
  
  /* 设置线程应当醒来的时间点，由于当下禁止中断，所以不必担心存在误差 */
  current_sleep_thread.wake_time=ticks+timer_ticks();
  /* 返回当前线程 */
  current_sleep_thread.sleep_thread=thread_current();
  
  /* 插入排序，得到有序列表，之后更新列表状态时便不必遍历 */
  list_insert_ordered(&sleeping_list,
                      &current_sleep_thread.elem,
                      (list_less_func*)&wake_time_cmp,
                      NULL);
  
  /* 打印 sleeping_list, debug */
  printinfo();
  /* 阻塞当前线程，进入睡眠状态 */
  thread_block();
  
  /* 解除防中断 */
  intr_set_level(old_level);
}

/** Sleeps for approximately MS milliseconds.  Interrupts must be
   turned on. */
void
timer_msleep (int64_t ms) 
{
  real_time_sleep (ms, 1000);
}

/** Sleeps for approximately US microseconds.  Interrupts must be
   turned on. */
void
timer_usleep (int64_t us) 
{
  real_time_sleep (us, 1000 * 1000);
}

/** Sleeps for approximately NS nanoseconds.  Interrupts must be
   turned on. */
void
timer_nsleep (int64_t ns) 
{
  real_time_sleep (ns, 1000 * 1000 * 1000);
}

/** Busy-waits for approximately MS milliseconds.  Interrupts need
   not be turned on.

   Busy waiting wastes CPU cycles, and busy waiting with
   interrupts off for the interval between timer ticks or longer
   will cause timer ticks to be lost.  Thus, use timer_msleep()
   instead if interrupts are enabled. */
void
timer_mdelay (int64_t ms) 
{
  real_time_delay (ms, 1000);
}

/** Sleeps for approximately US microseconds.  Interrupts need not
   be turned on.

   Busy waiting wastes CPU cycles, and busy waiting with
   interrupts off for the interval between timer ticks or longer
   will cause timer ticks to be lost.  Thus, use timer_usleep()
   instead if interrupts are enabled. */
void
timer_udelay (int64_t us) 
{
  real_time_delay (us, 1000 * 1000);
}

/** Sleeps execution for approximately NS nanoseconds.  Interrupts
   need not be turned on.

   Busy waiting wastes CPU cycles, and busy waiting with
   interrupts off for the interval between timer ticks or longer
   will cause timer ticks to be lost.  Thus, use timer_nsleep()
   instead if interrupts are enabled.*/
void
timer_ndelay (int64_t ns) 
{
  real_time_delay (ns, 1000 * 1000 * 1000);
}

/** Prints timer statistics. */
void
timer_print_stats (void) 
{
  printf ("Timer: %"PRId64" ticks\n", timer_ticks ());
}

/** Timer interrupt handler. */
static void
timer_interrupt (struct intr_frame *args UNUSED)
{
  ticks++;
  thread_tick ();
  
  /* 在此处更新 sleeping_list 的状态 */
  struct list_elem *elem_tmp;
  struct sleeping_thread *thread_tmp;
  /* 若当前时间大于等于睡眠线程应苏醒的时间，便将线程从列表中弹出，
  直到列表为空，或当前时间小于线程应苏醒的时间 
  因为列表是有序的，所以不必遍历所有元素 
  */
  while(!list_empty(&sleeping_list))
  {
    elem_tmp=list_front(&sleeping_list);
    thread_tmp=list_entry(elem_tmp,struct sleeping_thread,elem);
    if(ticks < thread_tmp->wake_time)
      break;
    
    /* 唤醒线程，并将之从睡眠列表中移除 */
    list_remove(elem_tmp);
    thread_unblock(thread_tmp->sleep_thread);
    
    if(thread_tmp->sleep_thread->priority > thread_current()->priority)
      intr_yield_on_return();
  }
  

  
}

/** Returns true if LOOPS iterations waits for more than one timer
   tick, otherwise false. */
static bool
too_many_loops (unsigned loops) 
{
  /* Wait for a timer tick. */
  int64_t start = ticks;
  while (ticks == start)
    barrier ();

  /* Run LOOPS loops. */
  start = ticks;
  busy_wait (loops);

  /* If the tick count changed, we iterated too long. */
  barrier ();
  return start != ticks;
}

/** Iterates through a simple loop LOOPS times, for implementing
   brief delays.

   Marked NO_INLINE because code alignment can significantly
   affect timings, so that if this function was inlined
   differently in different places the results would be difficult
   to predict. */
static void NO_INLINE
busy_wait (int64_t loops) 
{
  while (loops-- > 0)
    barrier ();
}

/** Sleep for approximately NUM/DENOM seconds. */
static void
real_time_sleep (int64_t num, int32_t denom) 
{
  /* Convert NUM/DENOM seconds into timer ticks, rounding down.
          
        (NUM / DENOM) s          
     ---------------------- = NUM * TIMER_FREQ / DENOM ticks. 
     1 s / TIMER_FREQ ticks
  */
  int64_t ticks = num * TIMER_FREQ / denom;

  ASSERT (intr_get_level () == INTR_ON);
  if (ticks > 0)
    {
      /* We're waiting for at least one full timer tick.  Use
         timer_sleep() because it will yield the CPU to other
         processes. */                
      timer_sleep (ticks); 
    }
  else 
    {
      /* Otherwise, use a busy-wait loop for more accurate
         sub-tick timing. */
      real_time_delay (num, denom); 
    }
}

/** Busy-wait for approximately NUM/DENOM seconds. */
static void
real_time_delay (int64_t num, int32_t denom)
{
  /* Scale the numerator and denominator down by 1000 to avoid
     the possibility of overflow. */
  ASSERT (denom % 1000 == 0);
  busy_wait (loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000)); 
  
}

static bool 
wake_time_cmp(const struct list_elem *a,const struct list_elem *b,void *aux)
{
  aux=aux;
  struct sleeping_thread *threada = list_entry(a,struct sleeping_thread,elem);
  struct sleeping_thread *threadb = list_entry(b,struct sleeping_thread,elem);
  return threada->wake_time < threadb->wake_time;
}
