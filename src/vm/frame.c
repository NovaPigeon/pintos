#include "vm/frame.h"
#include "vm/swap.h"
#include "vm/page.h"
#include "debug.h"
#include "string.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/pte.h"
#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"
#include "userprog/pagedir.h"


/* 哈希表 */
static bool frame_hash_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static unsigned frame_hash(const struct hash_elem *e, void* aux UNUSED);

/* 根据物理页地址从物理页表中获取信息 */
static struct frame_info *find_frame(void *frame_addr);

/* 驱逐物理页，将其信息存入 swap slot 中 */
static void vm_frame_evict(void);
/* 为了保证 frame_alloc 是原子的，需要实现无锁的 free 函数 */
static void vm_frame_free_wo_lock(void *frame_addr, bool is_free);

/* 初始化物理页系统 */
void vm_frame_init(void)
{
    lock_init(&lock_frames);
    lock_acquire(&lock_frames);
    list_init(&clock_list);
    hash_init(&frame_table,(hash_hash_func*)frame_hash,(hash_less_func*)frame_hash_less,NULL);
    clock_hand=NULL;
    lock_release(&lock_frames);
}

/** 从 USER_POOL 分配空白的物理页，并将相应的信息插入物理页表中，
 * 若物理页已满，则选取合适的物理页，将其驱逐到 swap slot 中
 * 返回空闲页的地址 */
void *
vm_frame_alloc(enum palloc_flags flag,void *page_addr)
{
    lock_acquire(&lock_frames);
    void *frame_addr=palloc_get_page(PAL_USER | flag);
    if(frame_addr==NULL)
    {
        /* 内存已满，需要驱逐物理页 */
        vm_frame_evict();
        /* 重新尝试分配物理页 */
        frame_addr=palloc_get_page(PAL_USER | flag);
        if(frame_addr==NULL)
            PANIC("Unbelievable! Evict a frame successfully but palloc a new page failed.");
    }

    struct frame_info *f=(struct frame_info *)malloc(sizeof(struct frame_info));
    if(f==NULL)
    {
        lock_release(&lock_frames);
        return NULL;
    }
    
    f->page_addr=page_addr;
    f->frame_addr=frame_addr;
    f->owner_thread=thread_current();
    /* 还未被加载的物理页暂时不能被驱逐 */
    f->pinned=true;

    /* 插入列表项 */
    hash_insert(&frame_table,&f->hash_e);

    /* 用于实现时钟算法 */
    list_push_back(&clock_list,&f->list_e);

    lock_release(&lock_frames);
    return frame_addr;
}

/* 释放物理地址指向的页表项，若 is_free=true，则释放物理页 */
void vm_frame_free(void *frame_addr,bool is_free)
{
    lock_acquire(&lock_frames);
    /* 获取对应的物理页，若不在物理页表中，则 PANIC */
    struct frame_info *f=find_frame(frame_addr);
    if(f==NULL)
        PANIC("The frame to free dosen't exist!");

    /* 从物理页表中删除对应页 */
    hash_delete(&frame_table,&f->hash_e);

    /* 从时钟列表中移除相应项 */
    list_remove(&f->list_e);

    /* 释放分配的空间 */
    if(is_free)
        palloc_free_page(frame_addr);
    free(f);
    lock_release(&lock_frames);
}

/* 为了保证 frame_alloc 是原子的，需要实现无锁的 free 函数 */
static void 
vm_frame_free_wo_lock(void *frame_addr, bool is_free)
{
    /* 获取对应的物理页，若不在物理页表中，则 PANIC */
    struct frame_info *f = find_frame(frame_addr);
    if (f == NULL)
        PANIC("The frame to free dosen't exist!");

    /* 从物理页表中删除对应页 */
    hash_delete(&frame_table, &f->hash_e);

    /* 从时钟列表中移除相应项 */
    list_remove(&f->list_e);

    /* 释放分配的空间 */
    if (is_free)
        palloc_free_page(frame_addr);
    free(f);
}

/* 设置 pinned 项 */
void 
vm_frame_set_pinned(void *frame_addr, bool pinned)
{
    lock_acquire(&lock_frames);
    struct frame_info *f=find_frame(frame_addr);
    if(f==NULL)
        PANIC("The frame to set pinned dosen't exist!");
    f->pinned=pinned;
    lock_release(&lock_frames);
}

/* 驱逐物理页，将其信息存入 swap slot 中(使用时钟算法) */
static void
vm_frame_evict()
{
    
    struct frame_info *f_evict;
    struct thread *t_cur=thread_current();
    /* 1. 寻找要被驱逐的物理页 */
    size_t frame_table_size=hash_size(&frame_table);
    ASSERT(frame_table_size!=0);
    ASSERT(!list_empty(&clock_list));
    /* 遍历两遍，确保没有遗漏 */
    for(size_t i=0;i<=2*frame_table_size;++i)
    {
        /* 更新时钟指针，并找到对应的页表项，时钟指针的更新是循环往复的 */
        if(clock_hand==NULL||clock_hand==list_end(&clock_list))
            clock_hand=list_begin(&clock_list);
        else
            clock_hand=list_next(clock_hand);
        
        f_evict=list_entry(clock_hand,struct frame_info,list_e);

        /* 判断时钟页是否可被驱逐 */
        if(f_evict->pinned==true)
            continue;
        if(pagedir_is_accessed(t_cur->pagedir,f_evict->page_addr))
        {
            pagedir_set_accessed(t_cur->pagedir,f_evict->page_addr,false);
            continue;
        }
        break;
    }

    /* 2. 驱逐该物理页，并将相应的内容存入交换槽中 */
    pagedir_clear_page(f_evict->owner_thread->pagedir,f_evict->page_addr);

    /* 根据原始页表，设置 dirty 位 */
    bool dirty= false ||
                pagedir_is_dirty(f_evict->owner_thread->pagedir,f_evict->page_addr)||
                pagedir_is_dirty(f_evict->owner_thread->pagedir,f_evict->frame_addr);
    vm_spte_set_dirty(f_evict->owner_thread->spage_table,f_evict->page_addr,dirty);

    /* 将要驱逐的页存入交换槽中，并设置虚拟页表的相应项 */
    swap_index_t swap_index=vm_swap_out(f_evict->frame_addr);
    vm_insert_swap_spte(f_evict->owner_thread->spage_table,f_evict->page_addr,swap_index);

    /* 将驱逐的页从物理页表中删除 */
    vm_frame_free_wo_lock(f_evict->frame_addr,true);
    
}

/* 定义哈希表中的比较操作 */
static bool 
frame_hash_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    const struct frame_info *fa=hash_entry(a,struct frame_info,hash_e);
    const struct frame_info *fb=hash_entry(b,struct frame_info,hash_e);
    return fa->frame_addr < fb->frame_addr;
}

/* 定义哈希映射，以物理页地址为索引 */
static unsigned 
frame_hash(const struct hash_elem *e, void *aux UNUSED)
{
    struct frame_info *f=hash_entry(e,struct frame_info,hash_e);
    return hash_bytes(&f->frame_addr,sizeof(f->frame_addr));
}

/* 根据物理页地址从物理页表中获取信息 */
static struct frame_info *
find_frame(void *frame_addr)
{
    /*  由于哈希表是以物理页地址为索引的，
        根据相关函数定义，只需要构造一个临时的 frame，并设置其物理页地址
        就可以以其为句柄找到物理页表中的相应项 */
    struct frame_info tmp_f;
    struct hash_elem *e;
    tmp_f.frame_addr=frame_addr;
    
    e=hash_find(&frame_table,&tmp_f.hash_e);
    
    if(e!=NULL)
        return hash_entry(e,struct frame_info,hash_e);
    else
        return NULL;
}