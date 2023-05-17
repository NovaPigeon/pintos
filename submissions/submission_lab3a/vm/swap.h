#ifndef VM_SWAP_H
#define VM_SWAP_H

typedef uint32_t swap_index_t;

#define SWAP_ERROR SIZE_MAX

/* 使用 block 来实现 swap */

/* 初始化交换槽系统 */
void vm_swap_init(void);

/* 将内存中的页写入交换槽，返回交换槽的序号 */
swap_index_t vm_swap_out(void *frame_addr);

/* 将交换槽中的页读入物理内存中 */
void vm_swap_in(swap_index_t swap_index,void *frame_addr);

/* 释放某个交换槽 */
void vm_swap_free_slot(swap_index_t swap_index);


#endif //VM_SWAP_H