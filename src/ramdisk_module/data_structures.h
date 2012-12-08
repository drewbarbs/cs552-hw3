#ifndef DATA_STRUCTURES_H
#define DATA_STRUCTURES_H
#include <linux/list.h>
#include "constants.h"

typedef struct rd_super_block {
  int num_free_blocks;
  int num_free_inodes;
  /* Additional info? (struct can be as large as BLK_SZ bytes) */
} super_block_t;

typedef enum FILE_TYPE {
  dir,
  reg
} file_type_t;

typedef struct indirect_block {
  void *data[PTRS_PB];
} indirect_block_t;

typedef struct double_indirect_block_t {
  indirect_block_t *indirect_blocks[PTRS_PB];
} double_indirect_block_t;

typedef struct index_node {
  file_type_t type;
  int size;
  void *direct[DIRECT];
  indirect_block_t *single_indirect;
  double_indirect_block_t *double_indirect;
} index_node_t;

typedef struct directory_entry {
  char *filename; /* 14 bytes including null terminator */
  unsigned short index_node_number; // 2 bytes
} directory_entry_t;

typedef struct file_object {
  off_t file_position;
  index_node_t *index_node;
} file_object_t;

/* file_descriptor_table_t should be an -opaque- type */
typedef struct file_descriptor_table {
  struct list_head list;
  file_object_t *entries;
  pid_t owner; //pid of the process the fdt belongs to
  size_t total_num_entries;
  size_t num_entries_assigned;
} file_descriptor_table_t;

/* Directory -block- has BLK_SZ / sizeof(directory_entry_t)
   directory entries == 16 entries */
#endif
