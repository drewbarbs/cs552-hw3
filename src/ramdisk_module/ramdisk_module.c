/*
 * Ramdisk module
 */
#include <linux/module.h>
#include <linux/proc_fs.h> /* We are making a procfs entry */
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/sched.h> /* Get current */
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/errno.h> /* error codes */
#include <asm/uaccess.h> /* gives us get/put_user functions */
#include "ramdisk_module.h"
#include "constants.h"
#include "data_structures.h"

MODULE_LICENSE("GPL");

/* *** Forward declarations of ramdisk functions *** */
static int ramdisk_ioctl(struct inode *inode, struct file *filp, 
			 unsigned int cmd, unsigned long arg);
/* Helper Routines */
static int rd_init(void);
static bool rd_initialized(void);
static int  create_file_descriptor_table(pid_t pid);
static file_descriptor_table_t *get_file_descriptor_table(pid_t pid);
static void delete_file_descriptor_table(pid_t pid);
static int create_file_descriptor_table_entry(file_descriptor_table_t *fdt,
					      file_object_t fo);
static file_object_t get_file_descriptor_table_entry(file_descriptor_table_t *fdt,
						     unsigned short fd);
static int set_file_descriptor_table_entry(file_descriptor_table_t *fdt,
						     unsigned short fd, file_object_t fo);
static void delete_file_descriptor_table_entry(file_descriptor_table_t *fdt,
					       unsigned short fd);
static size_t get_file_descriptor_table_size(file_descriptor_table_t *fdt,
					     unsigned short fd);
static index_node_t *get_free_index_node(void);
static index_node_t *get_parent_index_node(const char *pathname); // DOESNT TRASH PATHNAME
static index_node_t *get_index_node(const char *pathname);
static void *get_free_data_block(void);
static void release_data_block(void *data_block_ptr);
static void release_all_data_blocks(index_node_t *index_node);
static int add_directory_entry(index_node_t *parent_inode,
				directory_entry_t new_entry); /* Insert directory entry,
								 add increment size */
static offset_info_t get_offset_info(index_node_t *inode, int offset);
static void *get_byte_address(index_node_t *inode, int offset);
/* Routines for implementing ramdisk API */
static int rd_creat(const char *usr_str);
static int rd_mkdir(const char *usr_str);
static int rd_open(const pid_t pid, const char *usr_str);
static int rd_close(const pid_t pid, const int fd);
static int rd_read(const pid_t pid, const rd_rwfile_arg_t *usr_arg);
static int rd_write(const pid_t pid, const rd_rwfile_arg_t *usr_arg);
static int rd_lseek(const pid_t pid, const rd_seek_arg_t *usr_arg);
static int rd_unlink(const char *usr_str);
static int rd_readdir(const pid_t pid, const rd_readdir_arg_t *usr_arg);

/* *** Debug Functions *** */
static void debug_print_fdt_pids(void);

/* *** Declarations of procfs data routines */
static int procfs_open(struct inode *inode, struct file *file);
static int procfs_close(struct inode *inode, struct file *file);
static struct file_operations ramdisk_file_ops = {
  .owner = THIS_MODULE,
  .read = NULL,
  .write = NULL,
  .open = procfs_open,
  .release = procfs_close,
};
static struct proc_dir_entry *proc_entry;

/* *** Declarations of ramdisk synchronization */
DEFINE_RWLOCK(rd_init_rwlock);
/* Locks to ensure consistent view of ramdisk memory */
DEFINE_SPINLOCK(super_block_spinlock);
DEFINE_SPINLOCK(block_bitmap_spinlock);
DEFINE_RWLOCK(index_nodes_rwlock);
DEFINE_RWLOCK(file_descriptor_tables_rwlock);

/* Declarations of ramdisk data structures */
static bool rd_initialized_flag = false;
static super_block_t *super_block = NULL;
static index_node_t *index_nodes = NULL; // 256 blocks/64 bytes per inode = 1024 inodes
static void *block_bitmap = NULL; // 4 blocks => block_bitmap is 1024 bytes long
static void *data_blocks = NULL; // len(data_blocks) == 7931 blocks
static LIST_HEAD(file_descriptor_tables);

#define INODE_PTR(index) ((void *) index_nodes + index * INODE_SZ)
#define BLOCK_START(byte_address) ((void *)byte_address - (((unsigned long) ((void *)byte_address - data_blocks)) % BLK_SZ))
#define BLOCK_END(byte_address) (BLOCK_START(byte_address) + BLK_SZ)

/**
 *
 * Setting up the /proc file system entry
 *
 */

/*
 * Increment usage count on /proc/ramdisk file open
 */
static int procfs_open(struct inode *inode, struct file *file)
{
  printk(KERN_DEBUG "Ramdisk module opening by %d (parent %d, real_parent %d, thread group %d)\n", current->pid, current->parent->pid, current->real_parent->pid, current->tgid);
  try_module_get(THIS_MODULE);
  return 0;
}

/*
 * Decrement usage count on /proc/ramdisk file close
 */

static int procfs_close(struct inode *inode, struct file *file)
{
  int i = 0;
  file_descriptor_table_t *fdt = NULL;
  file_object_t fo;
  printk(KERN_DEBUG "Ramdisk module being closed by %d (parent %d, real_parent %d, thread group %d)\n", current->pid, current->parent->pid, current->real_parent->pid, current->tgid);
  fdt =  get_file_descriptor_table(current->pid);
  /* Here, I assume that the no other thread will be accessing this fdt */
  if (fdt != NULL) {
    for (i = 0; i < fdt->entries_length; i++) {
      fo = get_file_descriptor_table_entry(fdt, i);
      if (fo.index_node != NULL)
	read_unlock(&fo.index_node->file_lock);
    }
    delete_file_descriptor_table(current->pid);
  }
  module_put(THIS_MODULE);
  return 0;
}
static int __init initialization_routine(void) {
  printk(KERN_INFO "Loading ramdisk module\n");
  ramdisk_file_ops.ioctl = ramdisk_ioctl;

  /* Start create proc entry */
  proc_entry = create_proc_entry("ramdisk", 0444, NULL);
  if(!proc_entry) {
    printk(KERN_ERR "Error creating /proc entry. \n");
    return 1;
  }
  proc_entry->proc_fops = &ramdisk_file_ops;

  return 0;
}

static void __exit cleanup_routine(void) {
  /* Because of the try_get_module and put_module
   * calls in the procfs_open/close functions,
   * no other thread should have access to this 
   * module while this is executing
   */
  file_descriptor_table_t *p = NULL, *next = NULL;
  remove_proc_entry("ramdisk", NULL);
  printk(KERN_INFO "Cleaning up ramdisk module\n");
  /* The only other persistent, dynamically allocated
   * memory in the ramdisk is used for fdt's, all of 
   * which should have been destroyed in order for us
   * to reach this point. We will double check anyways.
   */
  list_for_each_entry_safe(p, next, &file_descriptor_tables, list) {
    printk(KERN_DEBUG "Deleting fdt for process %d\n", p->owner);
    delete_file_descriptor_table(p->owner);
  }
  if (super_block != NULL) {
    printk(KERN_INFO "Freeing ramdisk memory\n");
    vfree(super_block);
  }
  return;
}

/*
 * ioctl() entry point
 *
 */
static int ramdisk_ioctl(struct inode *inode, struct file *filp,
			 unsigned int cmd, unsigned long arg) 
{
  offset_info_t offset_info;
  printk(KERN_INFO "Called ioctl\n");
  if (cmd != RD_INIT && !rd_initialized()) {
    printk(KERN_ERR "Ramdisk called before being initialized\n");
    return -1;
  }

  switch (cmd) {
  case RD_INIT:
    return rd_init();
  case RD_CREAT:
    //
    break;
  case DBG_PRINT_FDT_PIDS:
    debug_print_fdt_pids();
    break;
  case DBG_MK_FDT:
    create_file_descriptor_table(current->pid);
    break;
  case DBG_RM_FDT:
    delete_file_descriptor_table((pid_t) arg);
    break;
  /* case DBG_TEST_OFFSET_INFO: */
  /*   offset_info = get_offset_info((int) arg); */
  /*   printk(KERN_DEBUG "Data blocks start at %p\n", data_blocks); */
  /*   printk(KERN_DEBUG "Offset %d\n", (int) arg); */
  /*   printk(KERN_DEBUG "This block starts at %p\n", offset_info.block_start); */
  /*   printk(KERN_DEBUG "The data starts at %p\n", offset_info.data_start); */
  /*   printk(KERN_DEBUG "This block ends at %p\n", offset_info.block_end); */
  /*   break; */
  default:
    return -EINVAL;
  }
  return 0;
}

/**
 *
 *  Functions for working with ramdisk data structures
 *
 * 
 */

/* *** File descriptor table functions***  */

/*
  Create a file descriptor table for the process identified by pid.
  returns 0 on success, -errno on error;
*/
static int create_file_descriptor_table(pid_t pid)
{
  file_descriptor_table_t *fdt = NULL;
  file_object_t *entries = NULL;
  size_t init_num_entry_bytes = sizeof(file_object_t) * INIT_FDT_LEN;

  /* Check if a file descriptor table for this process already exists */
  if (get_file_descriptor_table(pid) != NULL) {
    printk(KERN_ERR "Attempted to create fdt for process %d that already has one\n", pid);
    return -EEXIST;
  }
  
  /* Allocate memory for the new file descriptor table, return on failure */
  fdt = (file_descriptor_table_t *) kmalloc(sizeof(file_descriptor_table_t), GFP_KERNEL);
  if (fdt == NULL) {
    printk(KERN_ERR "Failed to allocate fdt for process %d\n", pid);
    return -ENOMEM;
  }
  entries = (file_object_t *) kmalloc(init_num_entry_bytes, GFP_KERNEL);
  if (entries == NULL) {
    printk(KERN_ERR "Failed to allocate entries array for fdt for process %d\n", pid);
    kfree(fdt);
    return -ENOMEM;
  }
  memset(entries, 0, init_num_entry_bytes);
  
  /* Initialize new file descriptor table */
  fdt->owner = pid;
  fdt->entries = entries;
  fdt->entries_length = INIT_FDT_LEN;
  fdt->num_free_entries = INIT_FDT_LEN;

  /* Insert new fdt into file_descriptor_tables_list */
  write_lock(&file_descriptor_tables_rwlock);
  list_add(&fdt->list, &file_descriptor_tables);
  write_unlock(&file_descriptor_tables_rwlock);
  return 0;
}

/*
  Get a pointer to the file descriptor table owned associated with pid
  returns NULL if no such table exists
 */
static file_descriptor_table_t *get_file_descriptor_table(pid_t pid)
{
  file_descriptor_table_t *p = NULL, *target = NULL;
  read_lock(&file_descriptor_tables_rwlock);
  list_for_each_entry(p, &file_descriptor_tables, list) {
    if (p->owner == pid) {
      target = p;
      break;
    }
  }
  read_unlock(&file_descriptor_tables_rwlock);  
  return target;
}

/*
  Removes the file descripor table associated with pid
 */
static void delete_file_descriptor_table(pid_t pid) {
  file_descriptor_table_t *fdt = get_file_descriptor_table(pid);
  if (fdt == NULL) {
    printk(KERN_ERR "Attempted to remove nonexistant fdt for process %d\n", pid);
    return;
  }
  /* Remove fdt from list */
  write_lock(&file_descriptor_tables_rwlock);
  list_del(&fdt->list);
  write_unlock(&file_descriptor_tables_rwlock);
  /* Deallocate memory set aside for fdt */
  kfree(fdt->entries);
  kfree(fdt);
}

static void debug_print_fdt_pids() {
  file_descriptor_table_t *p;
  printk(KERN_DEBUG "About to print processes that have fdts");
  read_lock(&file_descriptor_tables_rwlock);
  list_for_each_entry(p, &file_descriptor_tables, list) {
    printk(KERN_DEBUG "Process %d\n", p->owner);
  }
  read_unlock(&file_descriptor_tables_rwlock);
}

/*
 * Given a pointer to a process' file descriptor table, adds the given
 * file object to the table, and returns the file descriptor corresponding
 * to this new entry, or -errno on error
 */
static int create_file_descriptor_table_entry(file_descriptor_table_t *fdt,
							 file_object_t fo)
{
  int entry_index = 0;
  file_object_t *p = NULL, *dest = NULL;
  /* TODO: write_lock(fdt_rwlock) */
  /* Check if we need to allocate larger array/copy over current array */
  if (fdt->num_free_entries <= 0) {
    /* TODO: write_unlock(fdt_rwlock) */
    return -ENOMEM; /* TODO: in this case, try to allocate larger array/cpy old one */
  }  
  /* Search for empty entry in array, assumes that all empty entries are null'd out */
  for (entry_index = 0; entry_index < fdt->entries_length; entry_index++) {
    p = fdt->entries + entry_index;
    if (p->index_node == NULL) {
      dest = p;
      break;
    }
  }
  if (dest == NULL) {
    printk(KERN_ERR "Couldn't find empty entry, despite checking num_free_entries\n");
    /* write_unlock(fdt_rwlock) */
    return -ENOMEM;
  }
  dest->index_node = fo.index_node;
  dest->file_position = fo.file_position;
  return entry_index;
}

/*
 * Returns the file_object associated with the given file descriptor in the given
 * file descriptor table. If the file descriptor is invalid, then a null file object
 * (all fields have NULL/0 value) is returned
 */
static file_object_t get_file_descriptor_table_entry(file_descriptor_table_t *fdt,
						     unsigned short fd)
{
  file_object_t ret = { .index_node = NULL, .file_position = 0 };
  /* TODO: read_lock(fdt_rwlock) */
  if (fd >= (fdt->entries_length)) {
    /* TODO: read_unlock(fdt_rwlock) */
    return ret;
  }
  ret.index_node = fdt->entries[fd].index_node;
  ret.file_position = fdt->entries[fd].file_position;
  return ret;
}

/*
 * Sets the file descriptor table entry assocated with the given file descriptor
 * to the given file_object value.
 *
 * Returns 0 on success, -errno on error
 */
static int set_file_descriptor_table_entry(file_descriptor_table_t *fdt,
						     unsigned short fd, file_object_t fo)
{
  /* TODO: write_lock(fdt_rwlock) */
  /* Check that the given file object has a valid index node pointer */
  if ((unsigned long) fo.index_node < (unsigned long) index_nodes
      || (unsigned long) fo.index_node >= (unsigned long) block_bitmap
      || (((unsigned long) fo.index_node - (unsigned long)index_nodes) % INODE_SZ != 0)
      || fd > fdt->entries_length) {
    /* TODO: write_unlock(fdt_rwlock) */
    return -EINVAL;
  }
  fdt->entries[fd] = fo;
  /* TODO: write_unlock(fdt_rwlock) */
  return 0;
}

/*
 * Deletes the file descriptor table entry assocated with the given file descriptor
 */
static void delete_file_descriptor_table_entry(file_descriptor_table_t *fdt,
					       unsigned short fd)
{
  file_object_t null_file_object = { .index_node = NULL, .file_position = 0 };
  set_file_descriptor_table_entry(fdt, fd, null_file_object);
  return;
}
static size_t get_file_descriptor_table_size(file_descriptor_table_t *fdt,
					     unsigned short fd)
{
  size_t fdt_size;
  /* TODO: read_lock(fdt_rwlock) */
  fdt_size = fdt->entries_length - fdt->entries_length;
  /* TODO: read_unlock(fdt_rwlock) */
  return fdt_size;
}

/* Returns a pointer to a free index_node_t, if one exists,
   NULL on error
*/
static index_node_t *get_free_index_node()
{
  int i = 0;
  index_node_t *new_inode = NULL, *p = NULL;
  /* Make sure there is a free inode/ decrement inodes counter in
   * superblock
   */
  spin_lock(&super_block_spinlock);
  if (super_block->num_free_inodes == 0) {
    spin_unlock(&super_block_spinlock);
    return NULL;
  }
  super_block->num_free_inodes--;
  spin_unlock(&super_block_spinlock);
  /* Look for an UNALLOCATED inode */
  for (i = 0; i < NUM_INODES; i++) {
    p = (index_node_t *) ((void *) index_nodes + 64 * i);
    if (write_trylock(&p->file_lock)) {
      if (p->type == UNALLOCATED) {
	new_inode = p;
	new_inode->type = ALLOCATED;
	write_unlock(&new_inode->file_lock);
	break;
      } else
	write_unlock(&p->file_lock);
    }
  }
  /* We should have been able to find such an inode */
  if (new_inode == NULL) {
    printk(KERN_ERR "get_free_index_node failed to find free inode,"
	   " despite having first checked the super block counter\n");
  }

  return new_inode;
}

/*
 * Returns the index node of directory containing the file
 * indicated by pathname, or NULL on error.
 *
 * IMPORTANT: pathname should be a string in kernel space
 */
static index_node_t *get_parent_index_node(const char *pathname)
{
  char *pathname_copy;
  char *token;
  index_node_t *parent;
  
  pathname_copy = (char *) kcalloc(strlen(pathname) + 1, sizeof(char), GFP_KERNEL);
  strncpy(pathname_copy, pathname, strlen(pathname) - strlen(strrchr(pathname, '/')));

  parent = get_index_node(pathname_copy);
  kfree(pathname_copy);
  return parent;
}

static index_node_t *get_index_node(const char *pathname)
{
  char *pathname_copy, *token, *tokenize;
  index_node_t *curr = index_nodes;
  directory_entry_t *dir_entry = NULL;
  int i = 0;
  if (strlen(pathname) == 0)
    return NULL;
  if (strlen(pathname) == 1 && pathname[0] == '/')
    return index_nodes; // Points to root index node
  
  pathname_copy = (char *) kcalloc(strlen(pathname) + 1, sizeof(char), GFP_KERNEL);
  strncpy(pathname_copy, pathname, strlen(pathname));
  tokenize = pathname_copy + 1; // skip the first forward slash
  while ((token = strsep(&tokenize, "/")) != NULL) {
    if (curr->type != DIR) {
      break;
    }
    for (i = 0; i < curr->size / sizeof(directory_entry_t); i++) {
      dir_entry = get_byte_address(curr, i * sizeof(directory_entry_t));
      if (strncmp(dir_entry->filename, token, MAX_FILE_NAME_LEN) == 0) {
	curr = INODE_PTR(dir_entry->index_node_number);
	break;
      }
    }
  }
  kfree(pathname_copy);
  /* if (token != NULL) */
  /*   return NULL; */
  /* return  */

  return (token == NULL ? curr : NULL);
}

/*
 * Returns a pointer to a free data block, or NULL if one is
 * not available
 */
static void *get_free_data_block()
{
  unsigned long block_num = 0;
  void *block_address = NULL;
  spin_lock(&super_block_spinlock);
  if (super_block->num_free_blocks == 0) {
    spin_unlock(&super_block_spinlock);
    return NULL;
  }
  super_block->num_free_blocks--;  
  spin_unlock(&super_block_spinlock);
  spin_lock(&block_bitmap_spinlock);
  block_num = find_first_bit(block_bitmap, NUM_BLKS_BITMAP * BLK_SZ * 8);
  if (block_num == NUM_BLKS_BITMAP * BLK_SZ * 8) {
    printk(KERN_ERR "Uh oh. The super block said there was a free block, "
	   "but the block bitmap says otherwise...\n");
    spin_unlock(&block_bitmap_spinlock);
    return NULL;
  }
  set_bit(block_num, block_bitmap);
  spin_unlock(&block_bitmap_spinlock);
  block_address = data_blocks + block_num * BLK_SZ;
  memset(block_address, 0, BLK_SZ);
  return block_address;
}

/*
 *  Frees the data block pointed to by data_block_ptr to be
 *  re-allocated. DO NOT CALL THIS FUNCTION WHILE HOLDNG
 *  super_block_spinlock OR block_bitmap_spinlock
 */
static void release_data_block(void *data_block_ptr)
{
  int block_num;
  if (data_block_ptr == NULL) {
    printk(KERN_ERR "Asked to release NULL data block\n");
    return;
  }
  block_num = (data_block_ptr - data_blocks) / BLK_SZ;
  spin_lock(&super_block_spinlock);
  super_block->num_free_blocks++;  
  spin_unlock(&super_block_spinlock);
  spin_lock(&block_bitmap_spinlock);
  clear_bit(block_num, block_bitmap);
  spin_unlock(&block_bitmap_spinlock);
  return;
}

/**
 *
 * Functions for implementing the ramdisk API
 *
 */

/* returns a boolean value indicating whether ramdisk is ready for use */
bool rd_initialized() 
{
  bool ret;
  read_lock(&rd_init_rwlock);
  ret = rd_initialized_flag;
  read_unlock(&rd_init_rwlock);
  return ret;
}

/* Initializaton routine must be called once to initialize ramdisk memory before
   other functions are called. 
   return 0 on success, an errno otherwise */
int rd_init()
{
  const super_block_t init_super_block = {.num_free_blocks = NUM_BLKS_DATA,
					  .num_free_inodes = NUM_BLKS_INODE*BLK_SZ/INODE_SZ};
  const index_node_t root_inode = { .type = DIR,
				    .size = 0,
				    .file_lock = RW_LOCK_UNLOCKED,
				    .direct = { NULL },
				    .single_indirect = NULL,
				    .double_indirect = NULL};
  if (rd_initialized()) {
    return -EALREADY;
  }
  write_lock(&rd_init_rwlock);
  printk(KERN_INFO "Initializing ramdisk\n");
  super_block = (super_block_t *) vmalloc(RD_SZ);
  if (!super_block) {
    printk(KERN_ERR "vmalloc for ramdisk space failed\n");
    write_unlock(&rd_init_rwlock);
    return -ENOMEM;
  }
  memset((void *) super_block, 0, RD_SZ);
  index_nodes = (index_node_t *) ((void *) super_block + BLK_SZ);
  block_bitmap = ((void *)index_nodes + NUM_BLKS_INODE * INODE_SZ);
  data_blocks = block_bitmap + NUM_BLKS_BITMAP * BLK_SZ;
  *super_block = init_super_block;
  rd_initialized_flag = true;
  index_nodes[0] = root_inode;
  write_unlock(&rd_init_rwlock);
  return 0;
}

/*
 * Returns a (struct offset_info) that gives the address of the offset'th
 * byte of the data associated with inode (along with the start and end addresses
 * of the containing data block), or an all NULL (struct offset_info) on error
 */
static offset_info_t get_offset_info(index_node_t *inode, int offset)
{
  int data_block_num, indirect_block_num, dbl_indirect_block_num, offset_into_block;
  offset_info_t offset_info = {
    .block_start = NULL,
    .data_start = NULL,
    .block_end = NULL
  };
  if (offset >= inode->size )
    return offset_info;
  
  data_block_num = offset / BLK_SZ; // integer divison
  offset_into_block = offset % BLK_SZ;
  read_lock(&inode->file_lock);
  
  if (data_block_num < DIRECT) {
    /* if(inode->direct[data_block_num] == NULL) { */
    /*   read_unlock(inode->file_lock); */
    /*   printk(KERN_ERR "Tried to get address of invalid offset " */
    /* 	     "%d into index node #%d\n", offset, */
    /* 	     ((long) inode - (long) index_nodes) / INODE_SZ); */
    /*   return offset_info; */
    /* } */
    offset_info.block_start = inode->direct[data_block_num];
    /* offset_info.data_start = inode->direct[data_block_num] + offset_into_block; */
    /* offset_info.block_end = inode->direct[data_block_num] + BLK_SZ; */
  } else if (data_block_num < DIRECT + PTRS_PB) {
    /* if (inode->single_indirect == NULL) { */
    /*   read_unlock(inode->file_lock); */
    /*   printk(KERN_ERR "Tried to get address of invalid offset " */
    /* 	     "%d into index node #%d\n", offset, */
    /* 	     ((long) inode - (long) index_nodes) / INODE_SZ); */
    /*   return offset_info; */

    /* } */
    indirect_block_num = data_block_num - DIRECT;
    offset_info.block_start = inode->single_indirect->data[indirect_block_num];
  } else {// data_block_num < DIRECT + PTRS_PB(1 + PTRS_PB)
    dbl_indirect_block_num = (data_block_num - (DIRECT + PTRS_PB)) / PTRS_PB; //integer division
    indirect_block_num = data_block_num - (DIRECT + PTRS_PB) - dbl_indirect_block_num * PTRS_PB;
    offset_info.block_start = inode->double_indirect->indirect_blocks[dbl_indirect_block_num]->
						    data[indirect_block_num];
  }
  offset_info.data_start = offset_info.block_start + offset_into_block;
  offset_info.block_end = offset_info.block_start + BLK_SZ;
  read_unlock(&inode->file_lock);
  return offset_info;
}

/*
 * Returns the address of the offset'th
 * byte of the data associated with inode (along with the start and end addresses
 * of the containing data block), or NULL on error
 */
static void *get_byte_address(index_node_t *inode, int offset)
{
  int data_block_num, indirect_block_num, dbl_indirect_block_num, offset_into_block;
  void *offset_address = NULL, *block_start_address;
  if (offset >= inode->size )
    return offset_address;
  
  data_block_num = offset / BLK_SZ; // integer divison
  offset_into_block = offset % BLK_SZ;
  read_lock(&inode->file_lock);
  
  if (data_block_num < DIRECT) {
    block_start_address = inode->direct[data_block_num];
  } else if (data_block_num < DIRECT + PTRS_PB) {
    indirect_block_num = data_block_num - DIRECT;
    block_start_address = inode->single_indirect->data[indirect_block_num];
  } else {// data_block_num < DIRECT + PTRS_PB(1 + PTRS_PB)
    dbl_indirect_block_num = (data_block_num - (DIRECT + PTRS_PB)) / PTRS_PB; //integer division
    indirect_block_num = data_block_num - (DIRECT + PTRS_PB) - dbl_indirect_block_num * PTRS_PB;
    block_start_address = inode->double_indirect->indirect_blocks[dbl_indirect_block_num]->
						    data[indirect_block_num];
  }
  offset_address = block_start_address + offset_into_block;
  read_unlock(&inode->file_lock);
  return offset_address;
}




static int rd_creat(const char *usr_str)
{
  /* int status = 0, i = 0; */
  /* index_node_t *new_inode = NULL; */
  /*   directory_entry_t *cur_dir_entry; */
  /* char new_path_name[MAX_FILE_NAME_LEN] = { '\0' }; */
  /* size_t usr_str_len = strnlen_user(usr_str, MAX_FILE_NAME_LEN); */
  /* if (usr_str_len == 0 || !access_ok(VERIFY_READ, usr_str, MAX_FILE_NAME_LEN)) */
  /*   return -EINVAL; */
  /* /\* Make sure there is a free inode/ decrement inodes counter in */
  /*  * superblock */
  /*  *\/ */
  /* new_inode = get_free_index_node(); */
  /* if (new_inode == NULL) */
  /*   return -ENOMEM; */
  /* strncpy_from_user(new_path_name, usr_str, MAX_FILE_NAME_LEN); */
  /* parent_inode = get_parent_index_node(new_path_name); */

  /* parent_inode->size += sizeof(directory_entry_t); */

  /* /\* for (i = 0; i < MAX_NUM_DIR_ENTRIES; i++) { *\/ */

  /* /\*   block_ptr *\/ */

  /* /\* } *\/ */

  /* if (status <= 0) */
  /*   return status; */
  

  
  return 0;
}

static int rd_mkdir(const char *usr_str)
{
  /* index_node_t new_index_node = { */
  /*   .type = DIR, */
  /*   .size = 0, */
  /*   .file_lock = RW_LOCK_UNLOCKED, */
  /*   .direct = { NULL }; */
  /*   .single_indirect = NULL, */
  /*   .double_indirect = NULL */
  /* }; */
  /* directory_entry_t new_directory_entry = { */
  /*   .filename = { '\0' }, */
  /*   .index_node_number = 0 */
  /* }; */

  /* /\* Check input is valid *\/ */
  /* pathname = copy_from_user(usr_str); */
  /* parent = get_parent_index_node(pathname);   */
  /* if (parent == NULL) */
  /*   return -EINVAL; */

  /* new_inode_ptr = get_free_index_node(); */
  /* *new_inode_ptr = new_index_node; */
  /* new_directory_entry.index_node_number = (new_inode_ptr - index_nodes) / INODE_SZ; */
  /* strncpy(strrchr(pathname, '/'), &new_directory_entry.filename); */

  /* write_lock(&new_inode_ptr->file_lock); */
  /* add_directory_entry(parent, new_directory_entry); */
  /* write_unlock(&new_inode->file_lock); */
  return 0;
}

static int rd_unlink(const char *usr_str)
{
  char *pathname = NULL, *filename = NULL;
  index_node_t *inode, *parent;
  directory_entry_t *curr_dir_entry = NULL, *next_dir_block_ptr = NULL;
  void *block_to_release = NULL;
  int num_blocks, i = 0, j = 0, bytes_defragged = 0;
  size_t usr_strlen = strlen_user(usr_str);
  bool block_empty = true;
  const index_node_t clean_inode = { .type = DIR,
				    .size = 0,
				    .file_lock = RW_LOCK_UNLOCKED,
				    .direct = { NULL },
				    .single_indirect = NULL,
				    .double_indirect = NULL};
  /* usr_strlen <= 2 implies only valid pathname it could be is '/',
     which can't be unlinked
  */
  if (usr_strlen <= 2 || !access_ok(VERIFY_READ, usr_str, strlen_user(usr_str)))
    return -EINVAL;
  pathname = kcalloc(usr_strlen, sizeof(char), GFP_KERNEL);
  strncpy_from_user(pathname, usr_str, usr_strlen);
  /* Remove trailing forward slash, if it exists */
  if (pathname[usr_strlen-1] == '/')
    pathname[usr_strlen-1] = '\0';

  if ((inode = get_index_node(pathname)) == NULL) {
    kfree(pathname);
    return -ENOENT;
  }
  if (write_trylock(&inode->file_lock) == 0) {
    kfree(pathname);
    return -EACCES; // File must be open for reading currently
  }
 
  parent = get_parent_index_node(pathname);

  /* If parent != NULL , remove dir entry for inode. */
  if (parent != NULL) {
    filename = kcalloc(usr_strlen, sizeof(char), GFP_KERNEL);
    strcpy(strrchr(pathname, '/') + 1, filename);
    write_lock(&parent->file_lock);
    for (i = 0; i < parent->size; i += sizeof(directory_entry_t)) {
      curr_dir_entry = get_byte_address(parent, i);
      if (strncmp(curr_dir_entry->filename, filename, MAX_FILE_NAME_LEN) == 0) {
	memset(curr_dir_entry->filename, 0, MAX_FILE_NAME_LEN);
	curr_dir_entry->index_node_number = 0;
	parent->size -= sizeof(directory_entry_t);
	if ((unsigned long) (curr_dir_entry + 1) < (unsigned long) BLOCK_END(curr_dir_entry)) {
	  memmove(curr_dir_entry, curr_dir_entry + 1, (BLOCK_END(curr_dir_entry) - (void *) curr_dir_entry) - 1);
	}
	bytes_defragged = i * sizeof(directory_entry_t) + (int) (BLOCK_END(curr_dir_entry) - (void *)curr_dir_entry - sizeof(directory_entry_t));
	curr_dir_entry = (directory_entry_t *) BLOCK_END(curr_dir_entry) - 1;
	while (bytes_defragged < parent->size) {
	  next_dir_block_ptr = get_byte_address(parent, bytes_defragged + sizeof(directory_entry_t));
	  memcpy(curr_dir_entry, next_dir_block_ptr, sizeof(directory_entry_t));
	  memmove(next_dir_block_ptr, next_dir_block_ptr + 1, BLK_SZ - sizeof(directory_entry_t));
	  bytes_defragged += BLK_SZ;
	  curr_dir_entry = (directory_entry_t *) BLOCK_END(next_dir_block_ptr) - 1;
	}

	/* If no directory entries remaining in this block,
	   release it for reallocation
	*/
	/* for (dir_block_it_ptr = BLOCK_START(curr_dir_entry); */
	/*      j < BLOCK_START(curr_dir_entry) + BLK_SZ; j++) { */
	/*   if (strlen(dir_block_it_ptr->filename) != 1 || dir_block_it_ptr->index_node_number !=0) { */
	/*     block_empty = false; */
	/*     break; */
	/*   } */
	/* } */
	/* if (block_empty) */
	/*   release_data_block(BLOCK_START(curr_dir_entry)); */
	break;
      }
    }
    write_unlock(&parent->file_lock);
    kfree(filename);
  }
  /* Release all data blocks associated with this file */
  num_blocks = inode->size/ BLK_SZ;
  while (num_blocks != 0) {
    block_to_release = get_byte_address(inode, (num_blocks - 1) * BLK_SZ);
    release_data_block(block_to_release);
    num_blocks--;
  }
  *inode = clean_inode;
  spin_lock(&super_block_spinlock);
  super_block->num_free_inodes++;
  spin_unlock(&super_block_spinlock);
  kfree(pathname);
  return 0;
}

module_init(initialization_routine);
module_exit(cleanup_routine);
