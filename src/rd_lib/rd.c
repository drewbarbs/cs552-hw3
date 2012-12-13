#include <stdlib.h>
#ifdef DEBUG
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#endif
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "rd.h"
#include "../ramdisk_module/ramdisk_module.h"

static int rd_init(void);
static int fd = -1;

int rd_init()
{
  int rdfile = -1, retval = -1;
  if (fd != -1)
    return 0;
  rdfile = open("/proc/ramdisk", 0);
  if (rdfile == -1)
    return -1;
  retval = ioctl(rdfile, RD_INIT, NULL);
  if (retval == 0 || errno == EALREADY)
    fd = rdfile;
  return retval;
}

int rd_creat(char *pathname)
{
  if (rd_init() < 0)
    return -1;
  
  return 0;
}

#ifdef DEBUG
int main(int argc, char *argv[])
{
  rd_init();
  if (argc > 1 && strcmp(argv[1], "c") == 0)
    ioctl(fd, DBG_MK_FDT, NULL);  
  else if (argc > 1 && strcmp(argv[1], "d") == 0) {
    ioctl(fd, DBG_RM_FDT, atoi(argv[2]));
  }else if (argc > 1 && strcmp(argv[1], "p") == 0)
    ioctl(fd, DBG_PRINT_FDT_PIDS, NULL);
  else
    printf("Usage: ./a.out [cdp] <pid> (only if deleting)\n");
  
      return 0;
}
#endif
