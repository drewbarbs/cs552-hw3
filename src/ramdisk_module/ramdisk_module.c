/*
 * Ramdisk module
 */
#include <linux/module.h>
#include <linux/bitops.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/errno.h> /* error codes */
#include <linux/proc_fs.h> /* We are making a procfs entry */
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

/* *** Declarations of ramdisk synchronization data *** */

/* rd_init_lock protects critical section of rd_init(), ensures ramdisk is initialized
   only once */
DEFINE_SPINLOCK(rd_init_spinlock);
/* Locks to ensure consistent view of ramdisk memory */
DEFINE_SPINLOCK(super_block_spinlock);
DEFINE_SPINLOCK(block_bitmap_rwlock);
DEFINE_RWLOCK(index_nodes_rwlock);
DEFINE_RWLOCK(data_blocks_rwlock);
DEFINE_RWLOCK(file_descriptor_tables_rwlock);

/* Declarations of ramdisk data structures */
static super_block_t *super_block = NULL;
static index_node_t *index_nodes = NULL; // 256 blocks/64 bytes per inode = 1024 inodes
static void *block_bitmap = NULL; // 4 blocks => block_bitmap is 1024 bytes long
static void *data_blocks = NULL; // len(data_blocks) == 7931 blocks
static LIST_HEAD(file_descriptor_tables);
static struct file_operations ramdisk_file_ops;
static struct proc_dir_entry *proc_entry;


/* directory_entry_t * root_dir_p = (directory_entry_t *) (data_blocks + block_num * BLK_SZ); */
/* directory_entry_t first_entry = root_dir_p[0]; */
/* char *first_filename = first_entry */


/* (directory_entry_t *) data_blocks */

static int __init initialization_routine(void) {
  printk(KERN_INFO "Loading module\n");

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
  printk(KERN_INFO "Dumping ramdisk module\n");
  if (super_block != NULL) {
    printk(KERN_INFO "Freeing ramdisk memory\n");
    vfree(super_block);
  }
  remove_proc_entry("ramdisk", NULL);

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
  default:
    return -EINVAL;
  }
  return 0;
}

/* Initializaton routine must be called once to initialize ramdisk memory before
   other functions are called. 
   return 0 on success, an errno otherwise */
int rd_init()
{
  spin_lock(&rd_init_spinlock);
  if (super_block != NULL) {
    spin_unlock(&rd_init_spinlock);
    return -EALREADY;
  }
  printk(KERN_INFO "Initializing ramdisk\n");
  super_block = (super_block_t *) vmalloc(RD_SZ);
  if (!super_block) {
    printk(KERN_ERR "vmalloc for ramdisk space failed\n");
    spin_unlock(&rd_init_spinlock);
    return -ENOMEM;
  }
  memset((void *) super_block, 0, RD_SZ);
  index_nodes = (index_node_t *) ((void *) super_block + BLK_SZ);
  block_bitmap = ((void *)index_nodes + NUM_BLKS_INODE * INODE_SZ);
  data_blocks = block_bitmap + NUM_BLKS_BITMAP * BLK_SZ;
  spin_unlock(&rd_init_spinlock);  
  return 0;
}

/* returns a boolean value indicating whether ramdisk is ready for use */
bool rd_initialized() 
{
  return super_block != NULL;
}




module_init(initialization_routine);
module_exit(cleanup_routine);
