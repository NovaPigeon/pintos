/** This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/** Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
*/

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/** Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
     decrement it.

   - up or "V": increment the value (and wake up one waiting
     thread, if any). */
void sema_init(struct semaphore *sema, unsigned value)
{
  ASSERT(sema != NULL);

  sema->value = value;
  list_init(&sema->waiters);
}

/** Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on.

   将 sema 的等待队列实现为优先级队列 */
void sema_down(struct semaphore *sema)
{
  enum intr_level old_level;

  ASSERT(sema != NULL);
  ASSERT(!intr_context());

  old_level = intr_disable();
  while (sema->value == 0)
  {
    list_insert_ordered(&sema->waiters,
                        &thread_current()->elem,
                        (list_less_func *)&thread_priority_cmp,
                        NULL);
    thread_block();
  }
  sema->value--;
  intr_set_level(old_level);
}

/** Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool sema_try_down(struct semaphore *sema)
{
  enum intr_level old_level;
  bool success;

  ASSERT(sema != NULL);

  old_level = intr_disable();
  if (sema->value > 0)
  {
    sema->value--;
    success = true;
  }
  else
    success = false;
  intr_set_level(old_level);

  return success;
}

/** Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void sema_up(struct semaphore *sema)
{
  enum intr_level old_level;

  ASSERT(sema != NULL);

  old_level = intr_disable();
  if (!list_empty(&sema->waiters))
  {
    list_sort(&sema->waiters, (list_less_func *)&thread_priority_cmp, NULL);
    thread_unblock(list_entry(list_pop_front(&sema->waiters),
                              struct thread, elem));
  }
  sema->value++;   
  intr_set_level(old_level);
}

static void sema_test_helper(void *sema_);

/** Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void sema_self_test(void)
{
  struct semaphore sema[2];
  int i;

  printf("Testing semaphores...");
  sema_init(&sema[0], 0);
  sema_init(&sema[1], 0);
  thread_create("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
  for (i = 0; i < 10; i++)
  {
    sema_up(&sema[0]);
    sema_down(&sema[1]);
  }
  printf("done.\n");
}

/** Thread function used by sema_self_test(). */
static void
sema_test_helper(void *sema_)
{
  struct semaphore *sema = sema_;
  int i;

  for (i = 0; i < 10; i++)
  {
    sema_down(&sema[0]);
    sema_up(&sema[1]);
  }
}

/** Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void lock_init(struct lock *lock)
{
  ASSERT(lock != NULL);

  lock->holder = NULL;
  lock->donate_priority = PRI_MIN;
  sema_init(&lock->semaphore, 1);
}

/** Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep.

   捐赠相关的行为只在 lock_acquire 和 lock_realease 两个函数中进行，
   lock_acquire :
   1. 在获取锁之前:
    - 更新锁的 donate_priority
    - 并做捐赠操作，更新持有锁的线程的 prev_priority 和 priority
    - 设置 wait_lock
    - 追溯锁的持有者，若优先级递减，则要对链条上的所有锁做捐赠操作
   2. 在获取锁之后:
    - 将锁按照 donate_priority 的顺序插入 hold_locks 的列表中
    - 更新 lock->holder
    - 将 wait_lock 置为空
   3. 每次更新锁和线程的优先级，都要更新 hold_locks 和 ready_list
   4. 因为当某个锁被释放后，优先得到它的必然是等待它的线程中优先级最高的，
   所以只需将锁的 donate_priorty 置为它自己的优先级即可，不必考虑有其它情况。

   */
void lock_acquire(struct lock *lock)
{
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(!lock_held_by_current_thread(lock));

  enum intr_level old_level;

  old_level = intr_disable();

  /* 获取当前线程 */
  struct thread *curr_thread = thread_current();

  /* 若该锁被某一线程持有 */
  if (lock->holder != NULL && !thread_mlfqs)
  {
    /* 设置等待的锁，用于处理链式捐赠的情况 */
    curr_thread->wait_lock = lock;

    /* 更新等待该锁的线程中最大的优先级 */
    if (curr_thread->priority > lock->donate_priority)
    {
      lock->donate_priority = curr_thread->priority;

      /* 同样的，需要对持有锁的队列重新排序 */
      list_sort(&lock->holder->hold_locks,
                (list_less_func *)&lock_priority_cmp,
                NULL);
    }

    /* 捐赠 */
    if (lock->donate_priority > lock->holder->priority)
    {
      // printf("Thread %s donate %d to Thread %s\n", curr_thread->name, curr_thread->priority, lock->holder->name);
      /* 若有多重捐赠的情况存在，只记录第一次改变时线程的优先级为 prev_priority */
      if (lock->holder->prev_priority == lock->holder->priority)
        lock->holder->prev_priority = lock->holder->priority;

      lock->holder->priority = lock->donate_priority;
    
      /* 若被被捐赠的线程在 ready_list 中，需要对 ready_list 重新排序 */
      if (lock->holder->status == THREAD_READY)
        update_ready_list();
    }
    /* Nested priority donation */
    int depth = 0; /*< 记录递归搜索的深度，最多为 8 . */
    struct thread *thread_holder = lock->holder;
    struct thread *thread_next;
    while (thread_holder->wait_lock != NULL && depth < NEST_PRI_DONATE_DEPTH)
    {
      thread_next = thread_holder->wait_lock->holder;

      /* 若 donate chain 上的线程优先级递减，则做相应的捐赠操作 */
      if (thread_next->priority < thread_holder->priority)
      {
        thread_holder->wait_lock->donate_priority = thread_holder->priority;

        /* 对相应的列表做重排操作 */
        list_sort(&thread_holder->wait_lock->holder->hold_locks,
                  (list_less_func *)&lock_priority_cmp,
                  NULL);

        /* 若被捐赠的线程以前未接受过捐赠，则需记录其原始优先度 */
        if (thread_next->priority == thread_next->prev_priority)
          thread_next->prev_priority = thread_holder->priority;

        thread_next->priority = thread_holder->priority;

        /* 若被捐赠的线程在 ready_list 中，则需进行重排操作 */
        if (thread_next->status == THREAD_READY)
          update_ready_list();

        thread_holder = thread_next;
        depth++;
      }
      else
        break;
    }
  }
  intr_set_level(old_level);

  /* 获取锁 */
  sema_down(&lock->semaphore);

  old_level = intr_disable();

  if (!thread_mlfqs)
  {

    /* 当前线程不再等待锁 */
    curr_thread->wait_lock = NULL;
    /* 将锁的 donate_priority 更新为当前线程的优先级 */
    lock->donate_priority = curr_thread->priority;
    /* 将该锁插入线程拥有锁的列表，并做降序排序 */
    list_insert_ordered(&curr_thread->hold_locks,
                        &lock->elem,
                        (list_less_func *)&lock_priority_cmp,
                        NULL);
  }

  /* 设置当前锁的拥有者 */
  lock->holder = curr_thread;

  intr_set_level(old_level);
}

/** Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool lock_try_acquire(struct lock *lock)
{
  bool success;

  ASSERT(lock != NULL);
  ASSERT(!lock_held_by_current_thread(lock));

  success = sema_try_down(&lock->semaphore);
  if (success)
    lock->holder = thread_current();
  return success;
}

/** Releases LOCK, which must be owned by the current thread.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler.

   释放锁之前：
   1. 将当前锁从其持有者的列表中移除
   2. 设置该锁持有者的优先级，应是其持有的所有锁的捐赠优先级和基础优先级中最大的
   3. 将锁的捐赠优先级初始化
   4. 将锁的持有者置为空 */
void lock_release(struct lock *lock)
{
  ASSERT(lock != NULL);
  ASSERT(lock_held_by_current_thread(lock));
  enum intr_level old_level = intr_disable();
  /* 取当前线程 */
  struct thread *curr_thread = thread_current();

  if (!thread_mlfqs)
  {
    /* 从持有锁的列表中弹出当前锁 */
    list_remove(&lock->elem);

    /* 将该锁的捐赠优先级置为0 */
    lock->donate_priority = PRI_MIN;

    int hold_priority = PRI_MIN;

    /* 若列表非空，取出当前最大的捐赠优先级(列表有序，取队首即可) */
    if (!list_empty(&curr_thread->hold_locks))
      hold_priority = list_entry(
                          list_front(&curr_thread->hold_locks),
                          struct lock,
                          elem)
                          ->donate_priority;

    /* 还原当前进程的优先级 */
    if (hold_priority > curr_thread->prev_priority)
      curr_thread->priority = hold_priority;
    else
      curr_thread->priority = curr_thread->prev_priority;
    
    
  }
  /* 将该锁的持有者置为空 */
  lock->holder = NULL;
  sema_up(&lock->semaphore);
  intr_set_level(old_level);
}

/** Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool lock_held_by_current_thread(const struct lock *lock)
{
  ASSERT(lock != NULL);

  return lock->holder == thread_current();
}

/** One semaphore in a list. */
struct semaphore_elem
{
  struct list_elem elem;      /**< List element. */
  struct semaphore semaphore; /**< This semaphore. */
};

/** Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void cond_init(struct condition *cond)
{
  ASSERT(cond != NULL);

  list_init(&cond->waiters);
}

/** Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void cond_wait(struct condition *cond, struct lock *lock)
{
  struct semaphore_elem waiter;

  ASSERT(cond != NULL);
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(lock_held_by_current_thread(lock));

  sema_init(&waiter.semaphore, 0);
  list_push_back(&cond->waiters, &waiter.elem);
  lock_release(lock);
  sema_down(&waiter.semaphore);
  lock_acquire(lock);
}

/** If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler.

   将 condition 的队列修改为优先级队列 */
void cond_signal(struct condition *cond, struct lock *lock UNUSED)
{
  ASSERT(cond != NULL);
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(lock_held_by_current_thread(lock));

  if (!list_empty(&cond->waiters))
  {
    list_sort(&cond->waiters, (list_less_func *)&cond_sema_cmp, NULL);
    sema_up(&list_entry(list_pop_front(&cond->waiters),
                        struct semaphore_elem, elem)
                 ->semaphore);
  }
}

/** Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_broadcast(struct condition *cond, struct lock *lock)
{
  ASSERT(cond != NULL);
  ASSERT(lock != NULL);

  while (!list_empty(&cond->waiters))
    cond_signal(cond, lock);
}

/* lock 的比较函数，用于排序 */
bool lock_priority_cmp(const struct list_elem *a,
                       const struct list_elem *b,
                       void *aux)
{
  aux = aux;
  struct lock *locka = list_entry(a, struct lock, elem);
  struct lock *lockb = list_entry(b, struct lock, elem);
  return locka->donate_priority > lockb->donate_priority;
}
/* cond waiter 的比较函数，用于排序 */
bool cond_sema_cmp(const struct list_elem *a,
                   const struct list_elem *b,
                   void *aux)
{
  aux = aux;
  struct semaphore_elem *sema_a = list_entry(a, struct semaphore_elem, elem);
  struct semaphore_elem *sema_b = list_entry(b, struct semaphore_elem, elem);
  return list_entry(list_front(&sema_a->semaphore.waiters), struct thread, elem)->priority > list_entry(list_front(&sema_b->semaphore.waiters), struct thread, elem)->priority;
}