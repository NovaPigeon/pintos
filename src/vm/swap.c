#include "lib/kernel/bitmap.h"
#include "lib/stdbool.h"
#include "lib/stddef.h"
#include "lib/inttypes.h"
#include "devices/block.h"
#include "vm/swap.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
/* 使用 block 来实现 swap */

/* 交换槽 */
static struct block *swap_slots;
/* 位图，表明某个槽是否空闲 */
static struct bitmap *swap_slots_available;
/* 每页所包含扇区的数目 */
static const size_t SECTORS_PER_PAGE=PGSIZE/BLOCK_SECTOR_SIZE;
/* 交换槽中的页块数量 */
static size_t swap_slots_size(void);


/* 初始化交换槽系统 */
void 
vm_swap_init(void)
{
    /* 初始化交换槽 */
    swap_slots=block_get_role(BLOCK_SWAP);
    if(swap_slots==NULL)
        PANIC("Can not initialize swap slots!");
    /* 初始化标记交换槽可用性的位图，初始时将每位标为 true(空闲)*/
    swap_slots_available=bitmap_create(swap_slots_size());
    if(swap_slots_available==NULL)
        PANIC("Can not initialize swap slots availability bitmap!");
    bitmap_set_all(swap_slots_available,true);
}

/* 将内存中的页写入交换槽，返回交换槽的序号 */
swap_index_t 
vm_swap_out(void *frame_addr)
{
    /* 寻找某个空闲的页 */
    swap_index_t swap_index=bitmap_scan(
        swap_slots_available,
        0,  /* 从序号 0 开始搜索 */
        1,  /* 寻找连续长度为 1 的满足条件的空闲块 */
        true
    );
    if(swap_index==BITMAP_ERROR)
        return SWAP_ERROR;
    
    /* 将物理内存中的页写入交换槽中(按扇区) */
    for(swap_index_t i=0;i<SECTORS_PER_PAGE;++i)
    {
        block_write(
            swap_slots,
            swap_index*SECTORS_PER_PAGE+i, /* 扇区序号 */
            frame_addr+i*BLOCK_SECTOR_SIZE /* 开始地址 */
            );
    }
    /* 将对应的页设置为不可写 */
    bitmap_set(swap_slots_available,swap_index,false);
    return swap_index;
}

/* 将交换槽中的页读入物理内存中 */
void 
vm_swap_in(swap_index_t swap_index, void *frame_addr)
{
    /* 交换槽序号越界 */
    if(swap_index>=swap_slots_size())
        PANIC("SWAP IN: The slot index out of size of slots.");
    /* 从空白的交换槽读取内容，是非法的 */
    if(bitmap_test(swap_slots_available,swap_index)==true)
        PANIC("SWAP IN: Read from the blank slot.");
    /* 将交换槽中的内容写入物理页中(按扇区) */
    for(swap_index_t i=0;i<SECTORS_PER_PAGE;++i)
    {
        block_read(
            swap_slots,
            swap_index*SECTORS_PER_PAGE+i,
            frame_addr+BLOCK_SECTOR_SIZE*i
        );
    }
    /* 将对应的槽设置为空闲 */
    bitmap_set(swap_slots_available, swap_index, true);
}

/* 释放某个交换槽 */
void 
vm_swap_free_slot(swap_index_t swap_index)
{
    /* 交换槽序号越界 */
    if (swap_index >= swap_slots_size())
        PANIC("SWAP FREE: The slot index out of size of slots.");
    /* 试图将本就空闲的页设置为空闲 */
    if (bitmap_test(swap_slots_available, swap_index) == true)
        PANIC("SWAP FREE: Try to free a blank swap slot.");
    bitmap_set(swap_slots_available,swap_index,true);
}

/* 交换槽中的页块数量 */
static size_t 
swap_slots_size(void)
{
    return block_size(swap_slots)/SECTORS_PER_PAGE;
}
