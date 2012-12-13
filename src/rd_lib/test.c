#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include "rd.h"
#include "../ramdisk_module/ramdisk_module.h"

int main() {

	int rdfile = -1, retval = -1;
  rdfile = open("/proc/ramdisk", 0);
  if (rdfile == -1)
    return -1;
  retval = ioctl(rdfile, RD_INIT, NULL);
  return retval;
}

