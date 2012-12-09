#ifndef CONSTANTS_H
#define CONSTANTS_H

#define RD_SZ 0x200000 // (= 0x400 * 0x400)
#define MAX_FILES 1023
#define BLK_SZ 256
#define DIRECT 8
#define PTR_SZ 4
#define PTRS_PB (BLK_SZ / PTR_SZ)
#define NUM_BLKS_INODE 256
#define INODE_SZ 64
#define NUM_INODES NUM_BLKS_INODE * (BLK_SZ / INODE_SZ)
#define NUM_BLKS_BITMAP 4
#define NUM_BLKS_DATA ((RD_SZ - BLK_SZ *(1 + NUM_BLKS_INODE + NUM_BLKS_BITMAP)) / BLK_SZ)
#define DIR_ENTRY_SZ 16
#define DIR_ENTRIES_PB (BLK_SZ / DIR_ENTRY_SZ)
#define MAX_FILE_NAME_LEN 14 // Including null terminator
#define MAX_FILE_SIZE BLK_SZ * (DIRECT + PTRS_PB + PTRS_PB*PTRS_PB)
#define INIT_FDT_LEN 64
#endif
