#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/off_t.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "vm/page.h"
#include "lib/string.h"

/* 哈希表 */
static bool spage_hash_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static unsigned spage_hash(const struct hash_elem *e, void *aux UNUSED);
static void spage_hash_destroy(struct hash_elem *e,void *aux UNUSED);

/* 加载物理页 */
static bool load_blank_page(struct supplemental_pte *spte, uint32_t *pagedir);
static bool load_page_from_swap(struct supplemental_pte *spte,uint32_t *pagedir);
static bool load_page_from_filesys(struct supplemental_pte *spte,uint32_t *pagedir);

/* 为每个进程都创建一个 supplemental page table */
struct hash *
vm_create_spage_table(void)
{
    struct hash* spage_table=(struct hash *)malloc(sizeof(struct hash));
    ASSERT(spage_table!=NULL);
    hash_init(spage_table,(hash_hash_func *)spage_hash,(hash_less_func *)spage_hash_less,NULL);
    return spage_table;
}
/* 在进程结束时，销毁页表，并释放持有的空间资源 */
void vm_destroy_spage_table(struct hash *spage_table)
{
    ASSERT(spage_table!=NULL);
    hash_destroy(spage_table,(hash_action_func *)spage_hash_destroy);
    free(spage_table);   
}
/* 以虚拟页地址为索引，在页表中查询相应的表项 */
struct supplemental_pte *vm_find_spte(struct hash *spage_table, void *page_addr)
{
    struct hash_elem *hash_e;
    struct supplemental_pte spte;
    spte.page_addr=page_addr;
    hash_e=hash_find(spage_table,&spte.hash_e);
    if(hash_e==NULL)
        return NULL;
    return hash_entry(hash_e,struct supplemental_pte,hash_e);
}
/* 在补充页表中插入一个空白页的页表项，空白页只存在于页表中，只当需要加载时才被加载到物理内存中 */
bool 
vm_instert_blank_spte(struct hash *spage_table,
                      void *page_addr)
{
    struct supplemental_pte *spte =
        (struct supplemental_pte *)malloc(sizeof(struct supplemental_pte));

    /* 初始化页表项，将与当前页表状态不相关的项置为空 */
    spte->page_addr = page_addr;
    spte->frame_addr = NULL;
    spte->dirty = false;
    spte->status = PAGE_BLANK;
    spte->file = NULL;
    spte->swap_index = -1;
    spte->writable=true;

    /* 将 spte 插入补充页表中 */
    if (hash_insert(spage_table, &spte->hash_e) == NULL)
        /* 如果返回值为空，说明未发生哈希碰撞 */
        return true;
    else
    {
        /* 否则，当前项已经在页表中，但这是不可能的 */
        PANIC("Unbelievable! The blank page has been in the supple_page table!");
        free(spte);
        return false;
    }
}

/* 在补充页表中插入一个 on frame 的页表项 */
bool 
vm_instert_frame_spte(struct hash *spage_table,
                      void *page_addr,
                      void *frame_addr)
{
    struct supplemental_pte *spte=
        (struct supplemental_pte *)malloc(sizeof(struct supplemental_pte));

    /* 初始化页表项，将与当前页表状态不相关的项置为空 */
    spte->page_addr=page_addr;
    spte->frame_addr=frame_addr;
    spte->dirty=false;
    spte->status=PAGE_FRAME;
    spte->file=NULL;
    spte->swap_index=-1;
    spte->writable=true;

    /* 将 spte 插入补充页表中 */
    if(hash_insert(spage_table,&spte->hash_e)==NULL)
        /* 如果返回值为空，说明未发生哈希碰撞 */
        return true;
    else
    {
        /* 否则，当前项已经在页表中 */
        free(spte);
        return false;
    }
}
/* 将补充页表中 on frame 的页表项改为 on swap（不可能凭空插入，只可能是转化得）  */
bool 
vm_insert_swap_spte(struct hash *spage_table,
                    void *page_addr,
                    swap_index_t swap_index)
{
    /* 只有已存在的物理页才可能被驱逐入交换槽中 */
    struct supplemental_pte *spte=vm_find_spte(spage_table,page_addr);
    if(spte==NULL)
        return false;
    spte->frame_addr=NULL;
    spte->swap_index=swap_index;
    spte->status=PAGE_SWAP;
    spte->file=NULL;
    return true;
}
/* 在补充页表中插入一个 on file 的页表项 */
bool 
vm_insert_file_spte(struct hash *spage_table,
                    void *page_addr,
                    struct file *file,
                    off_t file_offset,
                    uint32_t read_bytes,
                    uint32_t zero_bytes,
                    bool writable)
{
    struct supplemental_pte *spte =
        (struct supplemental_pte *)malloc(sizeof(struct supplemental_pte));
    /* 初始化页表项，将与当前页表状态不相关的项置为空 */
    spte->dirty=false;
    spte->status = PAGE_FILE;

    spte->frame_addr=NULL;
    spte->page_addr=page_addr;

    spte->file = file;
    spte->file_offset = file_offset;
    spte->read_bytes=read_bytes;
    spte->zero_bytes=zero_bytes;
    spte->writable=writable;

    spte->swap_index=-1;

    /* 将 spte 插入补充页表中 */
    if (hash_insert(spage_table, &spte->hash_e) == NULL)
        /* 如果返回值为空，说明未发生哈希碰撞 */
        return true;
    else
    {
        /* 否则，当前项已经在页表中，但这是不可能的 */
        PANIC("Unbelievable !The page from filesys has been in the supple_page table !");
        free(spte);
        return false;
    }
}

/* 将对应的页表项加载到物理内存中 */
bool 
vm_load_page(struct hash *spage_table, void *page_addr, uint32_t *pagedir)
{
    struct supplemental_pte *spte=vm_find_spte(spage_table,page_addr);
    if(spte==NULL)
        return false;

    bool load_success;
    switch (spte->status)
    {
    case PAGE_BLANK:
        load_success=load_blank_page(spte,pagedir);
        break;
    case PAGE_FRAME:
        /* 若已经在物理内存中，则无需加载 */
        load_success=true;
        break;
    case PAGE_SWAP:
        load_success=load_page_from_swap(spte,pagedir);
        break;
    case PAGE_FILE:
        load_success=load_page_from_filesys(spte,pagedir);
        break;
    default:
        NOT_REACHED();
        break;
    }
    return load_success;

}

/* 设置相应页表项的 dirty 位 */
bool 
vm_spte_set_dirty(struct hash *spage_table, void *page_addr, bool dirty)
{
    struct supplemental_pte *spte=vm_find_spte(spage_table,page_addr);
    if(spte==NULL)
        PANIC("The spte to set DIRTY dosen't exist!");
    spte->dirty=spte->dirty||dirty;
    return true;
}

/* 设置虚拟页表项对应物理页的 pinned 位 */
void 
vm_spte_set_pinned(struct hash *spage_table, void *page_addr, bool pinned)
{
    struct supplemental_pte *spte=vm_find_spte(spage_table,page_addr);
    if(spte==NULL)
    {
        if(pinned==true)
            return;
        PANIC("The page to unpin dosen't exist!");
    }
    if(spte->status!=PAGE_FRAME && pinned==true)
        PANIC("The page to set pinned dosen't on frame!");
    if(spte->status==PAGE_FRAME)
        vm_frame_set_pinned(spte->frame_addr,pinned);
}
/* 定义哈希表中的比较操作 */
static bool
spage_hash_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    const struct supplemental_pte *spte_a = hash_entry(a, struct supplemental_pte, hash_e);
    const struct supplemental_pte *spte_b = hash_entry(b, struct supplemental_pte, hash_e);
    return spte_a->page_addr < spte_b->page_addr;
}

/* 定义哈希映射，以虚拟页地址为索引 */
static unsigned
spage_hash(const struct hash_elem *e, void *aux UNUSED)
{
    struct supplemental_pte *spte = hash_entry(e, struct supplemental_pte, hash_e);
    return hash_bytes(&spte->page_addr, sizeof(spte->page_addr));
}
/* 当一个进程终止时，应当释放其拥有的所有页，无论是在 frame/swap slot 中 */
static void spage_hash_destroy(struct hash_elem *e, void *aux UNUSED)
{
    struct supplemental_pte *spte=hash_entry(e,struct supplemental_pte,hash_e);
    if(spte->status==PAGE_FRAME)
    {   
        ASSERT(spte->frame_addr!=NULL);
        /* 释放物理内存 */
        vm_frame_free(spte->frame_addr,false);
    }
    else if(spte->status==PAGE_SWAP)
        /* 只要将交换槽设置为空闲可写就行，不必将对应的槽清零 */
        vm_swap_free_slot(spte->swap_index);
    
    /* 释放分配的页表空间 */
    free(spte);
}

/* 加载空白页 */
static bool 
load_blank_page(struct supplemental_pte *spte, uint32_t *pagedir)
{
    /* 分配新的物理页 */
    void *frame_addr = vm_frame_alloc(PAL_USER, spte->page_addr);
    if (frame_addr == NULL)
        return false;
    /* 将该物理页置为空 */
    memset(frame_addr,0,PGSIZE);
    /* 在原始页表中添加从虚拟页到物理页的映射 */
    if (!pagedir_set_page(pagedir, spte->page_addr, frame_addr, true))
    {
        vm_frame_free(frame_addr,true);
        return false;
    }
    /* 修改 spte 的成员项 */
    spte->status = PAGE_FRAME;
    spte->frame_addr = frame_addr;

    /* 恢复原始页表中的 dirty 项 */
    pagedir_set_dirty(pagedir, frame_addr, false);

    vm_frame_set_pinned(frame_addr, false);
    return true;
}

/* 加载物理页 */
static bool 
load_page_from_swap(struct supplemental_pte *spte,uint32_t *pagedir)
{
    /* 分配新的物理页 */
    void *frame_addr=vm_frame_alloc(PAL_USER,spte->page_addr);
    if(frame_addr==NULL)
        return false;
    /* 将对应的交换槽中的内容换入物理页中 */
    vm_swap_in(spte->swap_index,frame_addr);
    /* 在原始页表中添加从虚拟页到物理页的映射 */
    if(!pagedir_set_page(pagedir,spte->page_addr,frame_addr,true))
    {
        vm_frame_free(frame_addr,true);
        return false;
    }
    /* 修改 spte 的成员项 */
    spte->status=PAGE_FRAME;
    spte->frame_addr=frame_addr;

    /* 恢复原始页表中的 dirty 项 */
    pagedir_set_dirty(pagedir,frame_addr,false);

    vm_frame_set_pinned(frame_addr,false);
    return true;

}
/* 从文件系统中加载特定的页 */
static bool 
load_page_from_filesys(struct supplemental_pte *spte,uint32_t *pagedir)
{
    /* 分配新的物理页 */
    void *frame_addr = vm_frame_alloc(PAL_USER, spte->page_addr);
    if (frame_addr == NULL)
        return false;
    
    /* 将文件中相应的内容加载到物理内存中 */
    file_seek(spte->file,spte->file_offset);
    if(file_read(spte->file,frame_addr,spte->read_bytes)!=(int)spte->read_bytes)
    {
        vm_frame_free(frame_addr,true);
        return false;
    }

    ASSERT((spte->read_bytes+spte->zero_bytes)%PGSIZE==0);
    memset(frame_addr+spte->read_bytes,0,spte->zero_bytes);

    /* 在原始页表中添加从虚拟页到物理页的映射 */
    /* !!! 忘记设置writable了，debug 了好久呜呜呜呜 */
    if (!pagedir_set_page(pagedir, spte->page_addr, frame_addr, spte->writable))
    {
        vm_frame_free(frame_addr,true);
        return false;
    }
    /* 修改 spte 的成员项 */
    spte->status = PAGE_FRAME;
    spte->frame_addr = frame_addr;

    /* 恢复原始页表中的 dirty 项 */
    pagedir_set_dirty(pagedir, frame_addr, false);
    vm_frame_set_pinned(frame_addr, false);
    return true;
}