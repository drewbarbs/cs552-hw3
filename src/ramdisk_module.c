/*
 * Ramdisk module
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/errno.h> /* error codes */
#include <linux/proc_fs.h> /* We are making a procfs entry */
#include <asm/uaccess.h> /* gives us get/put_user functions */
#include "ramdisk_module.h"
#include "constants.h"
#include "data_structures.h"

MODULE_LICENSE("GPL");

static super_block_t *super_block = NULL;
static index_node_t *index_nodes = NULL; // 256 blocks/64 bytes per inode = 1024 inodes
static void *block_bitmap = NULL; // 4 blocks => block_bitmap is 1024 bytes long
static void *data_blocks = NULL; // len(data_blocks) == 7931 blocks


/* directory_entry_t * root_dir_p = (directory_entry_t *) (data_blocks + block_num * BLK_SZ); */
/* directory_entry_t first_entry = root_dir_p[0]; */
/* char *first_filename = first_entry */


/* (directory_entry_t *) data_blocks */


static int ramdisk_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg);

static struct file_operations ramdisk_file_ops;
static struct proc_dir_entry *proc_entry;

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

/***
 * ioctl() entry point
 */
static int ramdisk_ioctl(struct inode *inode, struct file *filp,
			       unsigned int cmd, unsigned long arg) 
{
  printk("Called ioctl\n");
  switch (cmd) {

  case RD_INIT:
    if (super_block != NULL)
      return -EALREADY;
    printk(KERN_INFO "Initializing ramdisk\n");
    super_block = (super_block_t *) vmalloc(RD_SZ);
    if (!super_block) {
      printk(KERN_ERR "vmalloc for ramdisk space failed\n");
      return -ENOMEM;
    }
    index_nodes = (index_node_t *) ((void *) super_block + BLK_SZ);
    block_bitmap = ((void *)index_nodes + NUM_BLKS_INODE * INODE_SZ);
    data_blocks = block_bitmap + NUM_BLKS_BITMAP * BLK_SZ;
    break;
 default:
    return -EINVAL;
  }
  return 0;
}

module_init(initialization_routine);
module_exit(cleanup_routine);
