#include "lib/kernel/hash.h"
#include "lib/stdint.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/mmap.h"
#include "vm/page.h"
#include "vm/swap.h"

/* 哈希表 */
static bool mmfiles_hash_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static unsigned mmfiles_hash(const struct hash_elem *e, void *aux UNUSED);
static void mmfiles_hash_destroy(struct hash_elem *e, void *aux UNUSED);

/* 为每个进程都创建一个被映射的文件的哈希表，以 mapid 为索引 */
struct hash *
vm_create_mmfiles_table(void)
{
    struct hash *mmap_files=(struct hash *)malloc(sizeof(struct hash));
    ASSERT(mmap_files!=NULL);
    hash_init(mmap_files,(hash_hash_func *)mmfiles_hash,(hash_less_func *)mmfiles_hash_less,NULL);
    return mmap_files;
}
/* 在进程结束时，销毁 mmfiles table，并释放其持有的资源 */
void vm_destroy_mmfiles_table(struct hash *mmap_files)
{
    hash_destroy(mmap_files,(hash_action_func *)mmfiles_hash_destroy);
    free(mmap_files);
}

/* 在 mmfiles table 中插入一项 */
mapid_t 
vm_mmfile_insert(struct thread *t, struct file *file, void *uvaddr, size_t size)
{
    struct mmap_file *mmfile=(struct mmap_file *)malloc(sizeof(struct mmap_file));
    if(mmfile==NULL)
        return MMERROR;
    mmfile->mapid=t->max_alloc_mapid;
    t->max_alloc_mapid++;
    mmfile->file=file;
    mmfile->uvaddr=uvaddr;
    mmfile->size=size;
    if(hash_insert(t->mmap_files,&mmfile->hash_e)!=NULL)
        return MMERROR;
    return mmfile->mapid;
        
}
/* 在 mmfiles table 中移除一项，并释放其资源 */
void 
vm_mmfile_unmap(struct thread *t, mapid_t mapid)
{
    struct mmap_file mmfile_tmp;
    struct hash_elem *hash_e;
    mmfile_tmp.mapid=mapid;
    hash_e=hash_delete(t->mmap_files,&mmfile_tmp.hash_e);
    if(hash_e!=NULL)
        mmfiles_hash_destroy(hash_e,NULL);

}

/* 根据 mapid，找到对应的 mmap_file */
struct mmap_file *
vm_find_mmfile(struct hash *mmfiles, mapid_t mapid)
{
    struct mmap_file mmfile_tmp;
    struct hash_elem *hash_e;
    mmfile_tmp.mapid=mapid;
    hash_e=hash_find(mmfiles,&mmfile_tmp.hash_e);
    if(hash_e==NULL)
        return NULL;
    return hash_entry(hash_e,struct mmap_file,hash_e);
}

static bool 
mmfiles_hash_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    const struct mmap_file *mmfile_a=hash_entry(a,struct mmap_file,hash_e);
    const struct mmap_file *mmfile_b = hash_entry(b, struct mmap_file, hash_e);
    return mmfile_a->mapid<mmfile_b->mapid;
}

static unsigned 
mmfiles_hash(const struct hash_elem *e, void *aux UNUSED)
{
    const struct mmap_file *mmfile=hash_entry(e,struct mmap_file,hash_e);
    return hash_int(mmfile->mapid);
}

static void 
mmfiles_hash_destroy(struct hash_elem *e, void *aux UNUSED)
{
    lock_acquire(&filesys_lock);
    struct mmap_file *mmfile=hash_entry(e,struct mmap_file,hash_e);
    ASSERT(mmfile!=NULL);
    struct file *file=mmfile->file;
    struct thread *t_cur=thread_current();
    struct supplemental_pte *spte;
    bool dirty;
    size_t offset=0;
    size_t file_size=mmfile->size;
    size_t write_bytes;
    uint32_t *pagedir=t_cur->pagedir;
    void *page_addr;
    /* 遍历文件所映射到的所有虚拟页，释放其所拥有的资源，若该页被写过，则将内容写回文件中 */
    for(;offset<file_size;offset+=PGSIZE)
    {   
        /* 找到当前虚拟页 */
        page_addr=mmfile->uvaddr+offset;
        
        /* 该页所需处理的字节数（注意尾项） */
        if(offset+PGSIZE<file_size)
            write_bytes=PGSIZE;
        else
            write_bytes=file_size-offset;
        
        /* 获取扩充页表项相关信息 */
        spte=vm_find_spte(t_cur->spage_table,page_addr);
        ASSERT(spte!=NULL);

        /** 若该页在物理内存中
         * 1. 固定对应的 frame，防止在 unmap 的过程中对应的 frame 被驱逐 
         * 2. 获取对应页的 dirty 项，若为真，说明该页被写过，需要将修改过的内容写回文件中，
         * 若为假，则只需要释放对应的物理页，并解除到该页的地址映射*/
        if(spte->status==PAGE_FRAME)
        {
            ASSERT(spte->frame_addr!=NULL);
            vm_frame_set_pinned(spte->frame_addr,true);

            dirty=spte->dirty||
                  pagedir_is_dirty(pagedir,spte->frame_addr)||
                  pagedir_is_dirty(pagedir,spte->page_addr);

            if(dirty)
                file_write_at(file,spte->page_addr,write_bytes,offset);

            vm_frame_free(spte->frame_addr,true);
            pagedir_clear_page(pagedir,spte->page_addr);
        }
        /** 若该页在交换槽中
         * 1. 获取对应页的 dirty 项。
         * 2. 若 dirty 项为真，则将 swap slot 中的内容写入临时页中，然后再将临时页中的内容写到文件中
         * 3. 否则，单纯释放交换槽即可。       
         * */
        else if(spte->status==PAGE_SWAP)
        {
            dirty=spte->dirty||
                  pagedir_is_dirty(pagedir,spte->page_addr);
                  
            if(dirty)
            {
                void *page_tmp = palloc_get_page(0); 
                vm_swap_in(spte->swap_index, page_tmp);
                file_write_at(file, page_tmp, write_bytes, offset);
                palloc_free_page(page_tmp);
            }
            else
                vm_swap_free_slot(spte->swap_index);
        }
        /* 需要将对应页表项从页表中删除，防止无效访问 */
        hash_delete(t_cur->spage_table,&spte->hash_e);
        free(spte);

    }
    /* 关闭文件，并释放相应资源 */
    file_close(mmfile->file);
    free(mmfile);
    lock_release(&filesys_lock);
    
}