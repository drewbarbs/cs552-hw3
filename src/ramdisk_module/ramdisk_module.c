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
static int super_block_init(void);
static int rd_init(void);
static int ramdisk_ioctl(struct inode *inode, struct file *filp, 
			 unsigned int cmd, unsigned long arg);
static bool rd_initialized(void);
static int  create_file_descriptor_table(pid_t pid);
static file_descriptor_table_t *get_file_descriptor_table(pid_t pid);
static void delete_file_descriptor_table(pid_t pid);
static int create_file_descriptor_table_entry(file_descriptor_table_t *fdt,
							 file_object_t fo);
static file_object_t get_file_descriptor_table_entry(file_descriptor_table_t *fdt,
						     unsigned short fd);
static file_object_t set_file_descriptor_table_entry(file_descriptor_table_t *fdt,
						     unsigned short fd, file_object_t fo);
static void delete_file_descriptor_table_entry(file_descriptor_table_t *fdt,
					       unsigned short fd);
static size_t get_file_descriptor_table_size(file_descriptor_table_t *fdt,
					     unsigned short fd);
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
//DEFINE_RWLOCK(data_blocks_rwlock);
DEFINE_RWLOCK(file_descriptor_tables_rwlock);

/* Declarations of ramdisk data structures */
static super_block_t *super_block = NULL;
static index_node_t *index_nodes = NULL; // 256 blocks/64 bytes per inode = 1024 inodes
static void *block_bitmap = NULL; // 4 blocks => block_bitmap is 1024 bytes long
static void *data_blocks = NULL; // len(data_blocks) == 7931 blocks
static LIST_HEAD(file_descriptor_tables);

/* directory_entry_t * root_dir_p = (directory_entry_t *) (data_blocks + block_num * BLK_SZ); */
/* directory_entry_t first_entry = root_dir_p[0]; */
/* char *first_filename = first_entry */


/* (directory_entry_t *) data_blocks */

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
  printk(KERN_DEBUG "Ramdisk module opening by %d\n", current->pid);
  try_module_get(THIS_MODULE);
  return 0;
}

/*
 * Decrement usage count on /proc/ramdisk file close
 */

static int procfs_close(struct inode *inode, struct file *file)
{
  file_descriptor_table_t *fdt = NULL;
  printk(KERN_DEBUG "Ramdisk module closing by %d\n", current->pid);
  fdt =  get_file_descriptor_table(current->pid);
   if (fdt != NULL)
     delete_file_descriptor_table(fdt);
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
  /* list_for_each_entry_safe(p, next, &file_descriptor_tables, list) { */
  /*   printk(KERN_DEBUG "Deleting fdt for process %d\n", p->owner); */
  /*   delete_file_descriptor_table(p->owner); */
  /* } */
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
  printk(KERN_INFO "Called ioctl\n");
  if (cmd != RD_INIT && !rd_initialized()) {
    printk(KERN_ERR "Ramdisk called before being initialized\n");
    return -1;
  }

  switch (cmd) {
  case RD_INIT:
    return rd_init();
  case DBG_PRINT_FDT_PIDS:
    debug_print_fdt_pids();
    break;
  case DBG_MK_FDT:
    create_file_descriptor_table(current->pid);
    break;
  case DBG_RM_FDT:
    delete_file_descriptor_table((pid_t) arg);
    break;
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
  ret = super_block != NULL;
  read_unlock(&rd_init_rwlock);
  return ret;
}

/* Initializaton routine must be called once to initialize ramdisk memory before
   other functions are called. 
   return 0 on success, an errno otherwise */
int rd_init()
{
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
  write_unlock(&rd_init_rwlock);  
  return 0;
}

module_init(initialization_routine);
module_exit(cleanup_routine);
