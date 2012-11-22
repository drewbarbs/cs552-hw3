/*
 * Ramdisk module
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h> /* error codes */
#include <linux/proc_fs.h> /* We are making a procfs entry */
#include <asm/uaccess.h> /* gives us get/put_user functions */
#include "data_structures.h"

MODULE_LICENSE("GPL");

#define RD_INIT 1

static super_block_t *super_block;
static index_node_t *index_nodes; // 1024 index nodes
static void *block_bitmap;
static void *data_blocks; // len(data_blocks) == 7552 blocks


directory_entry_t * root_dir_p = (directory_entry_t *) (data_blocks + block_num * BLK_SZ);
directory_entry_t first_entry = root_dir_p[0];
char *first_filename = first_entry


(directory_entry_t *) data_blocks


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
  printk(KERN_INFO "Dumping module\n");
  remove_proc_entry("ramdisk", NULL);

  return;
}

/***
 * ioctl() entry point
 */
static int ramdisk_ioctl(struct inode *inode, struct file *filp,
			       unsigned int cmd, unsigned long arg) 
{
  char input = '\0';
  switch (cmd) {

  case RD_INIT:
    ptr = vmalloc(2mb);
    super_block = ptr;
    index_nodes = ptr + BLK_SZ;
    block_bitmap = (ptr + BLK_SZ) + 256 * BLK_SZ; // = index_nodes + 256 * BLK_SZ
    data_blocks = (ptr + BLK_SZ) + 256 * BLK_SZ + 4 * BLK_SZ; // = block_bitmap + 4 * BLK_SZ


 default:
    return -EINVAL;
  }
  return 0;
}

module_init(initialization_routine);
module_exit(cleanup_routine);
