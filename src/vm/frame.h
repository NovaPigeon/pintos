#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "lib/kernel/hash.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/synch.h"

struct frame_info
{
    /* 是否允许被置换出去 */
    bool pinned;
    /* 物理页地址 */
    void *frame_addr;
    /* 虚拟页地址 */
    void *page_addr;
    /* 页表地址 */
    uint32_t *pte;
    /* 指向所属进程的指针 */
    struct thread *owner_thread;
    /* 物理页以哈希表的形式组织 */
    struct hash_elem hash_e;
    /* 时钟列表的句柄 */
    struct list_elem list_e;
};

/* 物理页表，以物理页地址为索引 */
struct hash frame_table;

/* 各物理页的时钟列表，用于时钟算法选取要驱逐的页 */
struct list clock_list;

/* 时钟指针 */
struct list_elem *clock_hand;

/* 支持多进程操作物理页表的同步，只需要在 frame.h 中定义的全局函数的首尾处加锁即可 */
struct lock lock_frames;

/* 初始化物理页系统 */
void vm_frame_init(void);

/** 从 USER_POOL 分配空白的物理页，并将相应的信息插入物理页表中，
 * 若物理页已满，则选取合适的物理页，将其驱逐到 swap slot 中
 * 返回空闲页的地址 */
void *vm_frame_alloc(enum palloc_flags flag,void *page_addr);

/* 释放物理地址指向的页表项，若 is_free=true，则释放物理页 */
void vm_frame_free(void *frame_addr,bool is_free);

/* 设置 pinned 项 */
void vm_frame_set_pinned(void *frame_addr,bool pinned);

#endif //VM_FRAME_H