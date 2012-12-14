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
static int delete_file_descriptor_table_entry(file_descriptor_table_t *fdt,
					       unsigned short fd);
static size_t get_file_descriptor_table_size(file_descriptor_table_t *fdt,
					     unsigned short fd);
static index_node_t *get_free_index_node(void);
static index_node_t *get_parent_index_node(const char *pathname); // DOESNT TRASH PATHNAME
static index_node_t *get_index_node(const char *pathname);
static index_node_t *get_inode(size_t no);
static void *get_free_data_block(void);
static void release_data_block(void *data_block_ptr);
static directory_entry_t* get_directory_entry(index_node_t* inode, int index);
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
static int temp = 0;
static LIST_HEAD(file_descriptor_tables);

#define INODE_PTR(index) (index_node_t *) (((void *) index_nodes) + index * INODE_SZ)
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
  //printk(KERN_DEBUG "Ramdisk module opening by %d (parent %d, real_parent %d, thread group %d)\n", current->pid, current->parent->pid, current->real_parent->pid, current->tgid);
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
  //printk(KERN_DEBUG "Ramdisk module being closed by %d (parent %d, real_parent %d, thread group %d)\n", current->pid, current->parent->pid, current->real_parent->pid, current->tgid);
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
    //printk(KERN_ERR "Error creating /proc entry. \n");
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
  //printk(KERN_INFO "Cleaning up ramdisk module\n");
  /* The only other persistent, dynamically allocated
   * memory in the ramdisk is used for fdt's, all of 
   * which should have been destroyed in order for us
   * to reach this point. We will double check anyways.
   */
  list_for_each_entry_safe(p, next, &file_descriptor_tables, list) {
    //printk(KERN_DEBUG "Deleting fdt for process %d\n", p->owner);
    delete_file_descriptor_table(p->owner);
  }
  if (super_block != NULL) {
    //printk(KERN_INFO "Freeing ramdisk memory\n");
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
  //printk(KERN_INFO "Called ioctl\n");
  if (cmd != RD_INIT && !rd_initialized()) {
    //printk(KERN_ERR "Ramdisk called before being initialized\n");
    return -1;
  }
  
  int i;

  switch (cmd) {
  case RD_INIT:
    rd_init();
    /* rd_mkdir("/hello"); */
    /* rd_mkdir("/hello/world"); */
    /* if (get_index_node("/hello/world")) printk("I found it\n"); */
    /* rd_unlink("/hello/world"); */
    /* if (get_index_node("/hello/world")) printk("I cannot found it\n"); */
   break;
  case RD_CREAT:
    return rd_creat((char *) arg);
  case RD_OPEN:
    return rd_open(current->pid, (char *) arg);
  case RD_CLOSE:
    return rd_close(current->pid, (int) arg);
  case RD_MKDIR:
    return rd_mkdir((char *) arg);
  case RD_UNLINK:
    return rd_unlink((char *) arg);
  case RD_READDIR:
    return rd_readdir(current->pid, (rd_readdir_arg_t *) arg);
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
    //printk("Unrecognized cmd %u\n", cmd);
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
    //printk(KERN_ERR "Attempted to create fdt for process %d that already has one\n", pid);
    return -EEXIST;
  }
  
  /* Allocate memory for the new file descriptor table, return on failure */
  fdt = (file_descriptor_table_t *) kmalloc(sizeof(file_descriptor_table_t), GFP_KERNEL);
  if (fdt == NULL) {
    //printk(KERN_ERR "Failed to allocate fdt for process %d\n", pid);
    return -ENOMEM;
  }
  entries = (file_object_t *) kmalloc(init_num_entry_bytes, GFP_KERNEL);
  if (entries == NULL) {
    //printk(KERN_ERR "Failed to allocate entries array for fdt for process %d\n", pid);
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
  return fdt;
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
   if (p!=NULL && p->owner == pid) {
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
    //printk(KERN_ERR "Attempted to remove nonexistant fdt for process %d\n", pid);
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
  //printk(KERN_DEBUG "About to print processes that have fdts");
  read_lock(&file_descriptor_tables_rwlock);
  list_for_each_entry(p, &file_descriptor_tables, list) {
    //printk(KERN_DEBUG "Process %d\n", p->owner);
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
    p = (fdt->entries) + entry_index;
    if (p->index_node == NULL) {
      dest = p;
      break;
    }
  }
  if (dest == NULL) {
    //printk(KERN_ERR "Couldn't find empty entry, despite num_free_entries returning\n");
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
  /* if ((unsigned long) fo.index_node < (unsigned long) index_nodes */
  /*     || (unsigned long) fo.index_node >= (unsigned long) block_bitmap */
  /*     || (((unsigned long) fo.index_node - (unsigned long)index_nodes) % INODE_SZ != 0) */
  /*     || fd > fdt->entries_length) { */
  /*   /\* TODO: write_unlock(fdt_rwlock) *\/ */
  /*   return -EINVAL; */
  /*} else*/
  if (fdt->entries[fd].index_node == NULL) {
    return -EINVAL;
  }
  fdt->entries[fd] = fo;
  /* TODO: write_unlock(fdt_rwlock) */
  return 0;

}

/*
 * Deletes the file descriptor table entry assocated with the given file descriptor
 */
static int delete_file_descriptor_table_entry(file_descriptor_table_t *fdt,
					       unsigned short fd)
{
  file_object_t null_file_object = { .index_node = NULL, .file_position = 0 };
  return set_file_descriptor_table_entry(fdt, fd, null_file_object);
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
    p = get_inode(i);
    //printk("Get_free_index_node checking if node %d (%p) is free\n", i,p);
    if (write_trylock(&p->file_lock)) {
      if (p->type == UNALLOCATED) {
	new_inode = p;
	new_inode->type = ALLOCATED;
	write_unlock(&new_inode->file_lock);
	break;
      } else {
	write_unlock(&p->file_lock);
      }
    }
  }
  /* We should have been able to find such an inode */
  if (new_inode == NULL) {
    //printk(KERN_ERR "get_free_index_node failed to find free inode,"
    //	   " despite having first checked the super block counter: %d\n", super_block->num_free_inodes);
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
  char *pathname_copy = NULL, *filename = NULL;
  index_node_t *parent;
  filename = strrchr(pathname, '/');
  if (filename == NULL)
    return NULL;
  if (strcmp(filename, pathname) == 0) { // Parent is root node
    return index_nodes;
  }
  pathname_copy = (char *) kcalloc(strlen(pathname) + 1, sizeof(char), GFP_KERNEL);
  strncpy(pathname_copy, pathname, strlen(pathname) - strlen(filename));
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
  bool found_prev_inode = true; // start with index_nodes
  curr = index_nodes;
  //printk("Called get_index_node with pathname %s\n", pathname);
  //printk("Printing entries in root index_node %p\n", curr);
  for (i = 0; i < curr->size / sizeof(directory_entry_t); i++) {
    dir_entry = get_directory_entry(curr, i);
    //printk("%s , inode # %d , address: %p , type : %d\n", dir_entry->filename, dir_entry->index_node_number, get_inode(dir_entry->index_node_number), get_inode(dir_entry->index_node_number)->type);
  }

  if (strlen(pathname) == 1 && pathname[0] != '/')
    return NULL;
  if (strlen(pathname) == 1 && pathname[0] == '/') { //strlen in kernel space -includes- trailing NULL
    //printk("Returning the root index node because I was aksed for %s\n", pathname);
    return index_nodes; // Points to root index node
  }
  
  pathname_copy = (char *) kcalloc(strlen(pathname) + 1, sizeof(char), GFP_KERNEL);
  strncpy(pathname_copy, pathname, strlen(pathname));
  tokenize = pathname_copy + 1; // skip the first forward slash

  while ((token = strsep(&tokenize, "/")) != NULL) {
    if (curr->type != DIR || !found_prev_inode) {
      //printk("Breaking out\n");
      break;
    }
    //printk("Token is %s\n", token);
    found_prev_inode = false;
    for (i = 0; i < curr->size / sizeof(directory_entry_t); i++) {
      dir_entry = get_byte_address(curr, i * sizeof(directory_entry_t));
      //printk("Comparing to %s\n", dir_entry->filename);
      if (strncmp(dir_entry->filename, token, MAX_FILE_NAME_LEN) == 0) {
	found_prev_inode = true;
	curr = INODE_PTR(dir_entry->index_node_number);
	break;
      } 
    }
  } 
  kfree(pathname_copy);
  /* if (token != NULL) */
  /*   return NULL; */
  //printk("Root inode: %p\n", index_nodes);
  //printk("inode 2: %p\n", (void *)index_nodes + INODE_SZ);
  //printk("inode 3: %p\n", (void *)index_nodes + 2 * INODE_SZ);
  //printk("Curr : %p\n", curr);
  //printk("Bool expression : %d\n", token == NULL && found_prev_inode);
  return (token == NULL && found_prev_inode ? curr : NULL);
  /* int i; */
  /* index_node_t *node = NULL; */
  
  /* if (strlen(pathname) == 0) */
  /*   return index_nodes; */
  
  /* char *parent_pathname = (char *) kcalloc(strlen(pathname) + 1, sizeof(char), GFP_KERNEL); */
  /* const char *filename = strrchr(pathname, '/') + 1; */
  /* int filename_length = strlen(filename); */
  /* if (filename_length < MAX_FILE_NAME_LEN) { */
  /*   strncpy(parent_pathname, pathname, strlen(pathname) - filename_length - 1); */
  /*   index_node_t *parent_node = get_index_node(parent_pathname); */
  /*   if (parent_node != NULL) { */
  /*     for (i = 0; i < parent_node->size / DIR_ENTRY_SZ; ++i) { */
  /* 	    directory_entry_t *entry = get_directory_entry(parent_node, i); */
  /* 	    if (strncmp(entry->filename, filename, MAX_FILE_NAME_LEN) == 0) { */
  /* 		  node = get_inode(entry->index_node_number); */
  /* 		  break; */
  /* 		} */
  /* 	  } */
  /* 	} */
  /* } */
  /* kfree(parent_pathname); */
  /* return node; */
}

static directory_entry_t* get_directory_entry(index_node_t* inode, int index)
{
  if (inode->type != DIR || inode->size / DIR_ENTRY_SZ <= index) {
    //printk("Inode %p\n", inode);
    //printk("Size  %d Type: %d\n", inode->size, inode->type);
    return NULL;
  }
  return (directory_entry_t *)get_byte_address(inode, index * sizeof(directory_entry_t));
}

/*
 * Returns a pointer to a free data block, or NULL if one is
 * not available
 */
static void *get_free_data_block()
{
  unsigned long block_num = 0;
  void *block_address = NULL;
  //printk("Calling get_free_data_block, data_blocks : %p\n", data_blocks);
  spin_lock(&super_block_spinlock);
  if (super_block->num_free_blocks == 0) {
    spin_unlock(&super_block_spinlock);
    return NULL;
  }
  super_block->num_free_blocks--;  
  spin_unlock(&super_block_spinlock);
  spin_lock(&block_bitmap_spinlock);
  block_num = find_first_zero_bit(block_bitmap, NUM_BLKS_BITMAP * BLK_SZ * 8);
  if (block_num == NUM_BLKS_BITMAP * BLK_SZ * 8) {
    //printk(KERN_ERR "Uh oh. The super block said there was a free block, "
    //   "but the block bitmap says otherwise...\n");
    spin_unlock(&block_bitmap_spinlock);
    return NULL;
  }
  //printk("Got zero bit at block num %d\n", block_num);
  set_bit(block_num, block_bitmap);
  spin_unlock(&block_bitmap_spinlock);
  block_address = data_blocks + block_num * BLK_SZ;
  memset(block_address, 0, BLK_SZ);
  //printk("Get free data block returning with %p\n", block_address);
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
    //printk(KERN_ERR "Asked to release NULL data block\n");
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
  const index_node_t regular_inode = { .type = UNALLOCATED,
				    .size = 0,
				    .file_lock = RW_LOCK_UNLOCKED,
				    .direct = { NULL },
				    .single_indirect = NULL,
				    .double_indirect = NULL};
  int i = 0;
  index_node_t *inode = NULL;
  if (rd_initialized()) {
    return -EALREADY;
  }
  write_lock(&rd_init_rwlock);
  //printk(KERN_INFO "Initializing ramdisk\n");
  super_block = (super_block_t *) vmalloc(RD_SZ);
  if (!super_block) {
    //printk(KERN_ERR "vmalloc for ramdisk space failed\n");
    write_unlock(&rd_init_rwlock);
    return -ENOMEM;
  }
  memset((void *) super_block, 0, RD_SZ);
  index_nodes = (index_node_t *) ((void *) super_block + BLK_SZ);
  block_bitmap = ((void *)index_nodes + NUM_BLKS_INODE * BLK_SZ);
  data_blocks = block_bitmap + NUM_BLKS_BITMAP * BLK_SZ;
  *super_block = init_super_block;
  rd_initialized_flag = true;
  index_nodes[0] = root_inode;
  for (i = 1; i < NUM_INODES; i++) {
    inode = get_inode(i);
   *inode = regular_inode;
  }
  write_unlock(&rd_init_rwlock);
  return 0;
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
  const index_node_t new_index_node = {
    .type = REG,
    .size = 0,
    .file_lock = RW_LOCK_UNLOCKED,
    .direct = { NULL },
    .single_indirect = NULL,
    .double_indirect = NULL
  };
  directory_entry_t new_directory_entry = {
    .filename = { '\0' },
    .index_node_number = 0
  };
  char *pathname = NULL;
  size_t usr_str_len = strlen_user(usr_str);

  if (usr_str_len <= 2 || !access_ok(VERIFY_READ, usr_str, MAX_FILE_NAME_LEN))
    return -EINVAL;
  pathname = kcalloc(usr_str_len, sizeof(char), GFP_KERNEL);
  if (pathname == NULL) 
    return -1;
  strncpy_from_user(pathname, usr_str, usr_str_len);

  index_node_t *parent = get_parent_index_node(pathname);
  if (parent == NULL || parent->type != DIR) {
    kfree(pathname);
    return -EINVAL;
  }

  if (parent->size >= MAX_FILE_SIZE) {
    kfree(pathname);
    return -EFBIG;
  }
  /* TODO: get filelock on parent */
  index_node_t *new_inode_ptr = get_free_index_node();
  if (new_inode_ptr == NULL) {
    kfree(pathname);
    return -EFBIG;
  }
  *new_inode_ptr = new_index_node;
  directory_entry_t *entry;
  if (parent->size % BLK_SZ == 0) {
    entry = get_free_data_block();
    if (parent->size < DIRECT * BLK_SZ){
      parent->direct[parent->size / BLK_SZ] = entry;
    } else if (parent->size < BLK_SZ * (DIRECT + PTRS_PB)) {
      if (parent->size == DIRECT * BLK_SZ) {
	indirect_block_t *indirect_block = get_free_data_block();
	if (indirect_block == NULL) {
	  kfree(pathname);
	  return -EFBIG;
	}
	parent->single_indirect = indirect_block;
	indirect_block->data[0] = (void *) entry;
      } else {
	parent->single_indirect->
	  data[(parent->size / BLK_SZ) - DIRECT] = (void *) entry;
      }
    } else {
      if (parent->size == BLK_SZ * (DIRECT + PTRS_PB)) {
	double_indirect_block_t *double_indirect_block = get_free_data_block();
	indirect_block_t *indirect_block = get_free_data_block();
	if (indirect_block == NULL || double_indirect_block == NULL) {
	  if (indirect_block != NULL)
	    release_data_block(indirect_block);
	  if (double_indirect_block != NULL)
	    release_data_block(double_indirect_block);
	  kfree(pathname);
	  release_data_block(entry);
	  return -EFBIG;
	}
	parent->double_indirect = double_indirect_block;
	double_indirect_block->indirect_blocks[0] = indirect_block;
	indirect_block->data[0] = (void *) entry;
      } else if ((parent->size - BLK_SZ*(DIRECT + PTRS_PB)) % (PTRS_PB * BLK_SZ) != 0) {
	  /* Need to insert entry in prexisting indirect block */
	  int indirect_block_index =
	    (parent->size - BLK_SZ*(DIRECT + PTRS_PB)) / (PTRS_PB * BLK_SZ);
	  int index_in_indirect_block =
	    (parent->size - BLK_SZ*(DIRECT + PTRS_PB)) % (PTRS_PB * BLK_SZ);
	  parent->double_indirect->indirect_blocks[indirect_block_index]
	    ->data[index_in_indirect_block] = (void *) entry;
      } else if ((parent->size - BLK_SZ*(DIRECT + PTRS_PB)) % (PTRS_PB * BLK_SZ) == 0) {
	indirect_block_t *indirect_block = get_free_data_block();
	if (indirect_block == NULL) {
	  release_data_block(entry);
	  kfree(pathname);
	  return -EFBIG;
	}
	int indirect_block_index =
	  (parent->size - BLK_SZ*(DIRECT + PTRS_PB)) / (PTRS_PB * BLK_SZ);
	int index_in_indirect_block = 0;
	parent->double_indirect->indirect_blocks[indirect_block_index]
	  ->data[index_in_indirect_block] = (void *) entry;
      } else {
	//printk(KERN_ERR "Unexpected case in mkdir\n");
	kfree(pathname);
	return -EFBIG;
      }
    }
  } else {
    entry = get_directory_entry(parent, parent->size / DIR_ENTRY_SZ - 1) + 1;
  }
  entry->index_node_number = ((void *) new_inode_ptr - (void *)index_nodes) / INODE_SZ;
  strncpy(entry->filename, strrchr(pathname, '/') + 1, MAX_FILE_NAME_LEN);
  parent->size += DIR_ENTRY_SZ;
  kfree(pathname);
  return 0;
}

static int rd_mkdir(const char *usr_str)
{
  const index_node_t new_index_node = {
    .type = DIR,
    .size = 0,
    .file_lock = RW_LOCK_UNLOCKED,
    .direct = { NULL },
    .single_indirect = NULL,
    .double_indirect = NULL
  };
  directory_entry_t new_directory_entry = {
    .filename = { '\0' },
    .index_node_number = 0
  };
  char *pathname = NULL;
  size_t usr_str_len = strlen_user(usr_str);

  if (usr_str_len <= 2 || !access_ok(VERIFY_READ, usr_str, MAX_FILE_NAME_LEN))
    return -EINVAL;
  pathname = kcalloc(usr_str_len, sizeof(char), GFP_KERNEL);
  if (pathname == NULL) 
    return -1;
  strncpy_from_user(pathname, usr_str, usr_str_len);

  index_node_t *parent = get_parent_index_node(pathname);
  if (parent == NULL || parent->type != DIR) {
    kfree(pathname);
    return -EINVAL;
  }

  if (parent->size >= MAX_FILE_SIZE) {
    kfree(pathname);
    return -EFBIG;
  }
  /* TODO: get filelock on parent */
  index_node_t *new_inode_ptr = get_free_index_node();
  if (new_inode_ptr == NULL) {
    kfree(pathname);
    return -EFBIG;
  }
  /* Link to new index node in parent */
  *new_inode_ptr = new_index_node;
  directory_entry_t *entry;
  if (parent->size % BLK_SZ == 0) { 
    /* Need new directory entry block */
    entry = get_free_data_block();
    if (parent->size < DIRECT * BLK_SZ) {
      /* Can link to new block from one of the DIRECT pointers */
      parent->direct[parent->size / BLK_SZ] = entry;
    } else if (parent->size < BLK_SZ * (DIRECT + PTRS_PB)) {
      /* Can link to new block from one of the INDIRECT pointers */
      if (parent->size == DIRECT * BLK_SZ) {
	/* Need to make the INDIRECT block */
	indirect_block_t *indirect_block = get_free_data_block();
	if (indirect_block == NULL) {
	  kfree(pathname);
	  return -EFBIG;
	} 
	parent->single_indirect = indirect_block;
	indirect_block->data[0] = (void *) entry;
      } else {
	/* Indirect block already exists */
	parent->single_indirect->
	  data[(parent->size / BLK_SZ) - DIRECT] = (void *) entry;
      }
    } else {
      /* Need to link to new block from an INDIRECT block, that is
	 pointed to from the DOUBLE_INDIRECT block */
      if (parent->size == BLK_SZ * (DIRECT + PTRS_PB)) {
	/* Need to create the DOUBLE INDIRECT block */
	double_indirect_block_t *double_indirect_block = get_free_data_block();
	indirect_block_t *indirect_block = get_free_data_block();
	if (indirect_block == NULL || double_indirect_block == NULL) {
	  if (indirect_block != NULL)
	    release_data_block(indirect_block);
	  if (double_indirect_block != NULL)
	    release_data_block(double_indirect_block);
	  kfree(pathname);
	  release_data_block(entry);
	  return -EFBIG;
	}
	parent->double_indirect = double_indirect_block;
	double_indirect_block->indirect_blocks[0] = indirect_block;
	indirect_block->data[0] = (void *) entry;
      } else if ((parent->size - BLK_SZ*(DIRECT + PTRS_PB)) % (PTRS_PB * BLK_SZ) != 0) {
	  /* Can point to the new block from  a prexisting indirect block */
	  int indirect_block_index =
	    (parent->size - BLK_SZ*(DIRECT + PTRS_PB)) / (PTRS_PB * BLK_SZ);
	  int index_in_indirect_block =
	    (parent->size - BLK_SZ*(DIRECT + PTRS_PB)) % (PTRS_PB * BLK_SZ);
	  parent->double_indirect->indirect_blocks[indirect_block_index]
	    ->data[index_in_indirect_block] = (void *) entry;
      } else if ((parent->size - BLK_SZ*(DIRECT + PTRS_PB)) % (PTRS_PB * BLK_SZ) == 0) {
	/* Need to create a new indirect block to point to the new block */
	indirect_block_t *indirect_block = get_free_data_block();
	if (indirect_block == NULL) {
	  release_data_block(entry);
	  kfree(pathname);
	  return -EFBIG;
	}
	int indirect_block_index =
	  (parent->size - BLK_SZ*(DIRECT + PTRS_PB)) / (PTRS_PB * BLK_SZ);
	int index_in_indirect_block = 0;
	parent->double_indirect->indirect_blocks[indirect_block_index]
	  ->data[index_in_indirect_block] = (void *) entry;
      } else {
	//printk(KERN_ERR "Unexpected case in mkdir\n");
	kfree(pathname);
	return -EFBIG;
      }
    }
  } else {
    entry = get_directory_entry(parent, parent->size / DIR_ENTRY_SZ - 1) + 1;
  }
  entry->index_node_number = ((void *) new_inode_ptr - (void *)index_nodes) / INODE_SZ;
  strncpy(entry->filename, strrchr(pathname, '/') + 1, MAX_FILE_NAME_LEN);
  parent->size += DIR_ENTRY_SZ;
  kfree(pathname);
  return 0;
}

static index_node_t *get_inode(size_t index)
{
  return (index_node_t *)(((void*)index_nodes) + INODE_SZ * index);
}

static int rd_unlink(const char *usr_str)
{	
  int i;
  char *pathname = NULL;
  size_t usr_strlen = strlen_user(usr_str);
  index_node_t *node = NULL;
  if (usr_strlen <= 2)
    return -EINVAL;
  pathname = kcalloc(usr_strlen, sizeof(char), GFP_KERNEL);
  strncpy_from_user(pathname, usr_str, usr_strlen);
  /* Remove trailing forward slash, if it exists */
  if (pathname[usr_strlen-1] == '/')
    pathname[usr_strlen-1] = '\0';

  index_node_t *parent_node = get_parent_index_node(pathname);
  /* TODO: get writelock for both parent and node */
  if (parent_node != NULL) {
    int last_entry_index = parent_node->size / DIR_ENTRY_SZ - 1;
    const char *filename = strrchr(pathname, '/') + 1;
    for (i = 0; i <= last_entry_index; ++i) {
      directory_entry_t *entry = get_directory_entry(parent_node, i);
      if (strncmp(entry->filename, filename, MAX_FILE_NAME_LEN) == 0) {
	node = get_inode(entry->index_node_number);
	if (node->type == DIR) {
	  if (node->size != 0) {
	    kfree(pathname);
	    return -EINVAL;
	  }
	} else {
	  /* Release all datablocks */
	  int num_blocks = node->size/ BLK_SZ;
	  void *block_to_release = NULL;
	  while (num_blocks != 0) {
	    block_to_release = get_byte_address(node, (num_blocks - 1) * BLK_SZ);
	    release_data_block(block_to_release);
	    num_blocks--;
	  }
	}
				
	// Init node
	//	memset(node, 0, INODE_SZ);
	const index_node_t clean_inode = { .type = UNALLOCATED,
				    .size = 0,
				    .file_lock = RW_LOCK_UNLOCKED,
				    .direct = { NULL },
				    .single_indirect = NULL,
				    .double_indirect = NULL};
	*node = clean_inode;
	
	// Delete Entry
	directory_entry_t *last_entry = get_directory_entry(parent_node, last_entry_index);
	if (entry != last_entry)
	  *entry = *last_entry;
	parent_node->size -= DIR_ENTRY_SZ;
	if (parent_node->size % BLK_SZ == 0) {
	  release_data_block(last_entry);
	  // Remove last location(DIRECT)
	  if (parent_node->size / BLK_SZ < DIRECT) {
	    parent_node->direct[parent_node->size / BLK_SZ] = 0;
	  } else { // IF more than 8
	    // TODO
	  }
	}
	break;
      }
    }
  } 
  kfree(pathname);
  if (node == NULL) {// Couldn't find an inode for this pathname
    return -EINVAL;
  }
  spin_lock(&super_block_spinlock);
  super_block->num_free_inodes++;
  spin_unlock(&super_block_spinlock);
  return 0;
}

static int rd_open(const pid_t pid, const char *usr_str)
{
 /*TODO: acquire readlock on index node */
  char *pathname = NULL;
  size_t usr_strlen = strlen_user(usr_str);
  int ret;
  pathname = kcalloc(usr_strlen, sizeof(char), GFP_KERNEL);
  strncpy_from_user(pathname, usr_str, usr_strlen);
  //printk("Opening %s\n", pathname);

  /* Remove trailing forward slash, if it exists */
  if (usr_strlen > 2 && pathname[usr_strlen-1] == '/')
    pathname[usr_strlen-1] = '\0';
  
  index_node_t *node = get_index_node(pathname);
  kfree(pathname);
  if (node == NULL)
    return -EINVAL;
  file_object_t new_fo = {
    .index_node = node,
    .file_position = 0
  };
  file_descriptor_table_t *fdt = get_file_descriptor_table(pid);
  if (fdt == NULL)
    fdt = create_file_descriptor_table(pid);
  if (fdt == NULL) {
    //printk("Failed to create fdt for process %d\n", pid);
    return -1;
  }
  ret = create_file_descriptor_table_entry(fdt, new_fo);
  return ret;
}

static int rd_close(const pid_t pid, const int fd)
{
 /* TODO: read_unlock the rwlock on this file */
  file_descriptor_table_t *fdt = get_file_descriptor_table(pid);
  if (fdt == NULL) {
    return -EINVAL;
  }
  return delete_file_descriptor_table_entry(fdt, fd);
}

static int rd_readdir(const pid_t pid, const rd_readdir_arg_t *usr_arg)
{
  int i, status = 0;
  file_descriptor_table_t *fdt = get_file_descriptor_table(pid);
  rd_readdir_arg_t *read_arg= NULL;
  directory_entry_t *entry = NULL;
  if (fdt == NULL)
    return -1;
  read_arg = kcalloc(1, sizeof(rd_readdir_arg_t), GFP_KERNEL);
  if (read_arg == NULL)
    return -1;
  copy_from_user(read_arg, usr_arg, sizeof(rd_readdir_arg_t));
  if (status != 0 || !access_ok(VERIFY_WRITE, usr_arg->address, MAX_FILE_NAME_LEN)) {
    kfree(read_arg);
    return -EINVAL;
  }
  file_object_t fo = get_file_descriptor_table_entry(fdt, read_arg->fd);
  if (fo.index_node == NULL)
    return -1;
  /* Check if we're at EOF */
  if (fo.index_node->size == 0 || fo.index_node->size == fo.file_position)
    return 0;
  //printk("Fo has index node : %p\n", fo.index_node);
  //printk("inode->direct[0]: %p\n", fo.index_node->direct[0]);
  //printk("Filename at that address : %s\n", ((directory_entry_t *) fo.index_node->direct[0])->filename);
  //printk("Fileposition in inode address: %d\n", fo.file_position);
  entry = get_directory_entry(fo.index_node, fo.file_position / DIR_ENTRY_SZ);
  //printk("Reading entry %p\n", entry);
  //printk("Filename : %s\n", entry->filename);
  /* usr_arg->address = entry->filename; */
  status = copy_to_user(read_arg->address, entry->filename, MAX_FILE_NAME_LEN);
  fo.file_position += DIR_ENTRY_SZ;
  set_file_descriptor_table_entry(fdt, read_arg->fd, fo);
  kfree(read_arg);
  return 1;
}

module_init(initialization_routine);
module_exit(cleanup_routine);
