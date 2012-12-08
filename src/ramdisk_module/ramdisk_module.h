#ifndef RAMDISK_MODULE_H
#define RAMDISK_MODULE_H

/* Major device number used for ioctls */
#define MAJOR_NUM 100
#define RD_INIT _IO(MAJOR_NUM, 0)
#define DBG_PRINT_FDT_PIDS _IO(MAJOR_NUM, 0 + 1)
#define DBG_MK_FDT _IO(MAJOR_NUM, 0 + 2)
#define DBG_RM_FDT _IO(MAJOR_NUM, 0 + 3)
#endif
