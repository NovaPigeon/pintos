#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

static char zeros[BLOCK_SECTOR_SIZE];

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}



void inode_add_thread_open(struct inode* inode, thread* thread1){
#ifdef VM
  list_push_back(&inode->threads_open,&thread1->exec_open_elem);
#endif
}

//thread* inode_get_open_thread(struct inode* inode){
//  list_elem * elem=list_front(&inode->threads_open);
//  return list_entry(elem,thread,exec_open_elem);
//}

  static bool get_new_table_page(block_sector_t* sector,int initialized){
    bool success=free_map_allocate(1,sector);
    if (!success) {
      return false;
    }
    inode_table_disk table_buffer;
    table_buffer.next_block=-1;
    for (int j = 0; j < PTR_NUM_BLOCK && success; j++) {
      if(j<initialized) {
        success&=free_map_allocate(1, &table_buffer.ptr[j]);
        if (!success) {
          break;
        }
        cache_write(table_buffer.ptr[j], zeros);
      } else {
        table_buffer.ptr[j]=-1;
      }
    }
    cache_write(*sector,&table_buffer);
    return success;
  }
  
/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(struct inode *inode, off_t pos,
                                       bool read) {
  
  ASSERT (inode != NULL);
  if (pos >= inode->data.length && read) {
    return -1;
  }
  unsigned tableno=(pos/BLOCK_SECTOR_SIZE)/PTR_NUM_BLOCK;
  unsigned offset_last_page=pos/BLOCK_SECTOR_SIZE-tableno*PTR_NUM_BLOCK;
  block_sector_t next=inode->data.start;
  inode_table_disk table_buffer;
  if (next == -1) {
    int initialized=(tableno==0)?offset_last_page+1:PTR_NUM_BLOCK;
    if(!get_new_table_page(&inode->data.start,initialized)){
      return -1;
    }
    next=inode->data.start;
  }
  for (int i = 0; i < tableno; i++) {
    cache_read(next,&table_buffer);
    if (table_buffer.ptr[PTR_NUM_BLOCK - 1] == -1) {
      for (int j = 0; j < PTR_NUM_BLOCK; j++) {
        if(!free_map_allocate(1, &table_buffer.ptr[j])){
          return -1;
        }
        cache_write(table_buffer.ptr[j], zeros);
      }
      cache_write(next,&table_buffer);
    }
    if (table_buffer.next_block == -1) {
      int initialized=(i==tableno-1)?offset_last_page+1:PTR_NUM_BLOCK;
      if(!get_new_table_page(&table_buffer.next_block,initialized)) {
        return -1;
      }
      cache_write(next,&table_buffer);
    }
    next=table_buffer.next_block;
  }
  if(pos >= inode->data.length) {
    inode->data.length=pos+1;
    cache_write(inode->sector, &inode->data);
  }
  cache_read(next,&table_buffer);
  if (table_buffer.ptr[offset_last_page] == -1) {
    for (int i = 0; i <= offset_last_page; i++) {
      if (table_buffer.ptr[i] == -1) {
        if(!free_map_allocate(1,&table_buffer.ptr[i])){
          return -1;
        }
      }
    }
    cache_write(next,&table_buffer);
  }
  return table_buffer.ptr[offset_last_page];
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}
/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = true;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      int table_blocks=DIV_ROUND_UP(sectors,PTR_NUM_BLOCK);
      inode_table_disk table_buffer;
      memset(&table_buffer,-1,sizeof(table_buffer));
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->start=-1;
      block_sector_t prev_ptr=sector;
      for (int i = 0; i < table_blocks && success; i++) {
        block_sector_t*next_ptr=i==0?&disk_inode->start:&table_buffer.next_block;
        int initialized;
        if (i == table_blocks - 1) {
          initialized=sectors-(table_blocks-1)*PTR_NUM_BLOCK;
        } else {
          initialized=PTR_NUM_BLOCK;
        }
        success&=get_new_table_page(next_ptr,initialized);
        if(i!=0){
          cache_write(prev_ptr, &table_buffer);
        }
        prev_ptr=*next_ptr;
        cache_read(*next_ptr,&table_buffer);
      }
      cache_write(sector,disk_inode);
      free (disk_inode);
  } else {
    success=false;
  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  list_init(&inode->threads_open);
  cache_read(inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          inode_disk inode_buffer;
          inode_table_disk table_buffer;
          cache_read(inode->sector, &inode_buffer);
          free_map_release (inode->sector, 1);
          block_sector_t next=inode_buffer.start;
          while (next != -1) {
            cache_read(next, &table_buffer);
            for (int i = 0; i < PTR_NUM_BLOCK; i++) {
              if(table_buffer.ptr[i]==-1) {
                break;
              }
              free_map_release(table_buffer.ptr[i],1);
            }
            free_map_release(next,1);
            next=table_buffer.next_block;
          }
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector(inode, offset, 1);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          cache_read( sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          cache_read( sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector(inode, offset, 0);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          cache_write (sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            cache_read( sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          cache_write ( sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

/*Jiaxin Begin*/

void
inode_set_dir(struct inode *inode)
{
  inode->data.isdir = true;
  cache_write(inode->sector, &inode->data);
}

bool
inode_is_root(struct inode *inode) {
  return inode->sector == ROOT_DIR_SECTOR;
}

bool
inode_isdir(struct inode *inode)
{
  return inode->data.isdir;
}
/*Jiaxin End*/

int inode_get_opencnt(struct inode* inode){
  return inode->open_cnt;
}