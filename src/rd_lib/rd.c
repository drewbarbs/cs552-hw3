#include <stdlib.h>
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
