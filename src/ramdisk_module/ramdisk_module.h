/*
 * Defines necessary info for accessing ramdisk through
 * ioctls
 *
 */
#ifndef RAMDISK_MODULE_H
#define RAMDISK_MODULE_H
#include <linux/ioctl.h>

typedef struct rd_rwfile_arg {
  char *address;
  int fd;
  int num_bytes;
} rd_rwfile_arg_t;

typedef struct rd_seek_arg {
  int fd;
  int offset;
} rd_seek_arg_t;

typedef struct rd_readdir_arg {
  char *address;
  int fd;
} rd_readdir_arg_t;

/* Major device number used for ioctls */
#define MAJOR_NUM 100
#define RD_INIT _IO(MAJOR_NUM, 0)
#define RD_CREAT _IOW(MAJOR_NUM, 1, char *)
#define RD_MKDIR _IOW(MAJOR_NUM, 2, char *)
#define RD_OPEN _IOW(MAJOR_NUM, 3, char *)
#define RD_CLOSE _IO(MAJOR_NUM, 4)
#define RD_READ _IOWR(MAJOR_NUM, 5, struct rd_rwfile_arg)
#define RD_WRITE _IOW(MAJOR_NUM, 6, struct rd_rwfile_arg)
#define RD_LSEEK _IOW(MAJOR_NUM, 7, struct rd_seek_arg)
#define RD_UNLINK _IOW(MAJOR_NUM, 8, char *)
#define RD_READDIR _IOWR(MAJOR_NUM, 9, char *)
#define DBG_PRINT_FDT_PIDS _IO(MAJOR_NUM, 9 + 1)
#define DBG_MK_FDT _IO(MAJOR_NUM, 9 + 2)
#define DBG_RM_FDT _IO(MAJOR_NUM, 9 + 3)
#define DBG_TEST_OFFSET_INFO _IO(MAJOR_NUM, 9 + 4)
#endif
