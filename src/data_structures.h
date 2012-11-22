#define MAX_FILES 1023
#define BLK_SZ 256
#define DIRECT 8
#define PTR_SZ 4
#define PTRS_PB (BLK_SZ / PTR_SZ)

typedef struct super_block {
  int num_free_blocks;
  int num_free_inodes;
  /* Additional info? (struct can be as large as BLK_SZ bytes) */
} super_block_t;

enum FILE_TYPE {
  dir,
  reg
} file_type_t;

typedef struct indirect_block {
  void *data[PTRS_PB];
} indirect_block_t;

typedef struct double_indirect_block_t {
  indirect_block_t *indirect_blocks[PTRS_PB];
} indirect_block_t;

typedef struct index_node {
  file_type_t type;
  int size;
  void *direct[DIRECT];
  indirect_block_t *single_indirect;
  double_indirect_block_t *double_indirect;
} index_node_t;

typedef struct directory_entry {
  char *filename; /* 14 bytes including null terminator */
  unsigned short index_node_num; // 2 bytes
} directory_entry_t;

/* Directory -block- has BLK_SZ / sizeof(directory_entry_t)
   directory entries == 16 entries */
