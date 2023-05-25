#ifndef VM_MMAP_H
#define VM_MMAP_H

#include "lib/kernel/hash.h"
#include "lib/stdint.h"
#include "lib/stdbool.h"
#include "filesys/file.h"
#include "threads/thread.h"

typedef int mapid_t;
#define MMERROR -1
/* 存储 mmap 到内存中的文件信息 */
struct mmap_file
{
    /* 被映射的文件的标识符，进程独有 */
    mapid_t mapid;
    /* 文件指针 */
    struct file *file;
    /* 文件在用户虚拟内存中的开始地址 */
    void *uvaddr;
    /* 文件大小 */
    size_t size;
    /* 作为进程中 mmap_files 哈希表的句柄 */
    struct hash_elem hash_e;
};

/* 为每个进程都创建一个被映射的文件的哈希表，以 mapid 为索引 */
struct hash *vm_create_mmfiles_table(void);
/* 在进程结束时，销毁 mmfiles table，并释放其持有的资源 */
void vm_destroy_mmfiles_table(struct hash *mmap_files);
/* 在 mmfiles table 中插入一项 */
mapid_t vm_mmfile_insert(struct thread *t,struct file *file,void *uvaddr,size_t size);
/* 在 mmfiles table 中移除一项，并释放其资源 */
void vm_mmfile_unmap(struct thread *t,mapid_t mapid);
/* 根据 mapid，找到对应的 mmap_file */
struct mmap_file *vm_find_mmfile(struct hash *mmfiles,mapid_t mapid);
#endif //VM_MMAP_H