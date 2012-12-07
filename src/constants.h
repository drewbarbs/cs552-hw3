#ifndef CONSTANTS_H
#define CONSTANTS_H

#define RD_SZ 0x200000 // (= 0x400 * 0x400)
#define MAX_FILES 1023
#define BLK_SZ 256
#define DIRECT 8
#define PTR_SZ 4
#define PTRS_PB (BLK_SZ / PTR_SZ)

#endif
