#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <list.h>
#include <stdbool.h>

/** A counting semaphore. */
struct semaphore 
  {
    unsigned value;             /**< Current value. */
    struct list waiters;        /**< List of waiting threads. */

  };

void sema_init (struct semaphore *, unsigned value);
void sema_down (struct semaphore *);
bool sema_try_down (struct semaphore *);
void sema_up (struct semaphore *);
void sema_self_test (void);


/** Lock. */
struct lock
{
  struct thread *holder;      /**< Thread holding lock (for debugging). */
  struct semaphore semaphore; /**< Binary semaphore controlling access. */
  struct list_elem elem;      /**< 用于生成列表. */
  int donate_priority;        /**< 一个锁可能被多个线程请求，我们只关心请求的所有进程中
                                     优先度最高的即可，该变量只在锁被持有时是有效的，当锁是空闲的
                                     ，一切竞争按优先度高低来进行，而该变量会被初始化为PRI_MIN，
                                     所以没有必要维护一个请求该锁的线程的列表. */
};

void lock_init (struct lock *);
void lock_acquire (struct lock *);
bool lock_try_acquire (struct lock *);
void lock_release (struct lock *);
bool lock_held_by_current_thread (const struct lock *);
/* lock 的比较函数，用于排序 */
bool lock_priority_cmp(const struct list_elem *a,
                       const struct list_elem *b,
                       void *aux);

/** Condition variable. */
struct condition 
{
  struct list waiters;        /**< List of waiting threads. */
};

void cond_init (struct condition *);
void cond_wait (struct condition *, struct lock *);
void cond_signal (struct condition *, struct lock *);
void cond_broadcast (struct condition *, struct lock *);
/* cond waiter 的比较函数，用于排序 */
bool cond_sema_cmp(const struct list_elem *a,
                   const struct list_elem *b,
                   void *aux);
/** Optimization barrier.

   The compiler will not reorder operations across an
   optimization barrier.  See "Optimization Barriers" in the
   reference guide for more information.*/
#define barrier() asm volatile ("" : : : "memory")
/* Nested priority donation 的最大搜索深度 */
#define NEST_PRI_DONATE_DEPTH 8

#endif /**< threads/synch.h */
