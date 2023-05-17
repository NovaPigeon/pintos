#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "filesys/off_t.h"
#include "filesys/file.h"
#include "devices/block.h"
#include "lib/stdint.h"
#include "lib/kernel/hash.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "vm/swap.h"
#include "vm/frame.h"

#define STACK_SIZE 0x800000

/* 记录 page 在何处 */
enum page_status
{
    PAGE_BLANK, /* 空白页，只存在于页表中 */
    PAGE_FRAME, /* 在物理内存中 */
    PAGE_SWAP,  /* 在 swap slot(disk) 中 */
    PAGE_FILE   /* 在文件系统中 */
};

union spte_data
{
    struct
    {
        /* PAGE_FRAME */
        void *frame_addr;
    }frame_data;

    struct
    {
        /* PAGE_SWAP */
        bool swap_writable;
        swap_index_t swap_index;
    }swap_data;

    struct
    {
        /* PAGE_FILE */
        /* 是否可写 */
        bool writable;
        /* 文件 */
        struct file *file;
        /* 文件偏移量 */
        off_t file_offset;
        /* read_bytes+zero_bytes=PG_SIZE，
        一般将 page_addr+read_bytes 开始的 zero_bytes 置为 0 */
        uint32_t read_bytes;
        uint32_t zero_bytes;
    }file_data;

};

/* 补充页表项 */
struct supplemental_pte
{
    /* 用户虚拟地址 */
    void *page_addr;
    /* 该页所在位置 */
    enum page_status status;
    /* 因为页表以哈希表的形式组织，所以 pte 需要提供哈希表的句柄 */
    struct hash_elem hash_e;
    /* 是否被修改过 */
    bool dirty;
    /* 是否可写 */
    bool writable;

    /* PAGE_FRAME */
    void *frame_addr;

    /* PAGE_SWAP */
    swap_index_t swap_index;

    /* PAGE_FILE */
    /* 文件 */
    struct file *file;
    /* 文件偏移量 */
    off_t file_offset;
    /* read_bytes+zero_bytes=PG_SIZE，
    一般将 page_addr+read_bytes 开始的 zero_bytes 置为 0 */
    uint32_t read_bytes;
    uint32_t zero_bytes;
};

/* 为每个进程都创建一个 supplemental page table */
struct hash *vm_create_spage_table(void);
/* 在进程结束时，销毁页表，并释放持有的空间资源 */
void vm_destroy_spage_table(struct hash *spage_table);
/* 以虚拟页地址为索引，在页表中查询相应的表项 */
struct supplemental_pte *vm_find_spte(struct hash *spage_table, void *page_addr);

/* 在补充页表中插入一个 on frame 的页表项 */
bool vm_instert_blank_spte(struct hash *spage_table,
                           void *page_addr);

/* 在补充页表中插入一个 on frame 的页表项 */
bool vm_instert_frame_spte(struct hash *spage_table,
                           void *page_addr,
                           void *frame_addr);
/* 将补充页表中 on frame 的页表项改为 on swap（不可能凭空插入，只可能是转化得）  */
bool vm_insert_swap_spte(struct hash *spage_table,
                         void *page_addr,
                         swap_index_t swap_index);
/* 在补充页表中插入一个 on file 的页表项 */
bool vm_insert_file_spte(struct hash *spage_table,
                         void *page_addr,
                         struct file * file,
                         off_t file_offset,
                         uint32_t read_bytes,
                         uint32_t zero_bytes,
                         bool writable);

/* 将对应的页表项加载到物理内存中 */
bool vm_load_page(struct hash *spage_table,void *page_addr,uint32_t *pagedir);

/* 设置相应页表项的 dirty 位 */
bool vm_spte_set_dirty(struct hash *spage_table,void *page_addr,bool dirty);

/* 设置虚拟页表项对应物理页的 pinned 位 */
void vm_spte_set_pinned(struct hash *spage_table,void *page_addr,bool pinned);

#endif // VM_PAGE_H