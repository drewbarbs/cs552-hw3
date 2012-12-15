#include <stdlib.h>
#ifdef DEBUG
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#endif
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "rd.h"
#include "../ramdisk_module/ramdisk_module.h"

static int rd_init(void);
static int rdfd = -1;

int rd_init()
{
  int rdfile = -1, retval = -1;
  if (rdfd != -1)
    return 0;
  rdfile = open("/proc/ramdisk", 0);
  if (rdfile == -1)
    return -1;
  retval = ioctl(rdfile, RD_INIT, NULL);
  if (retval == 0 || errno == EALREADY)
    rdfd = rdfile;
  return retval;
}

int rd_creat(char *pathname)
{
  int ret = 0;
  if (rd_init() < 0)
    return -1;
  if ((ret = ioctl(rdfd, RD_CREAT, pathname)) < 0)
    perror("rd_creat\n");
  return ret;
}

int rd_mkdir(char *pathname)
{
  int ret = 0;
  if (rd_init() < 0)
    return -1;
  if ((ret = ioctl(rdfd, RD_MKDIR, pathname)) < 0) {
    perror("rd_mkdir\n");
  }
  return ret;
}

int rd_open(char *pathname)
{
  int ret = 0;
  if (rd_init() < 0)
    return -1;
  if ((ret = ioctl(rdfd, RD_OPEN, pathname)) < 0)
    perror("rd_open\n");
  return ret;
}

int rd_close(int fd)
{
  int ret = 0;
  if (rd_init() < 0)
    return -1;
  if ((ret = ioctl(rdfd, RD_CLOSE, fd)) < 0)
    perror("rd_close\n");
  return ret;
}

int rd_read(int fd, char *address, int num_bytes)
{
  int ret = 0;
  rd_rwfile_arg_t arg = {
    .address = address,
    .fd = fd,
    .num_bytes = num_bytes
  };
  if (rd_init() < 0)
    return -1;
  if ((ret = ioctl(rdfd, RD_READ, &arg)) < 0)
    perror("rd_read\n");
  return ret;
}

int rd_write(int fd, char *address, int num_bytes)
{
  int ret = 0;
  rd_rwfile_arg_t arg = {
    .address = address,
    .fd = fd,
    .num_bytes = num_bytes
  };
  if (rd_init() < 0)
    return -1;
  if ((ret = ioctl(rdfd, RD_WRITE, &arg)) < 0)
    perror("rd_write\n");
  return ret;
}

int rd_lseek(int fd, int offset)
{
  int ret = 0;
  rd_seek_arg_t arg = {
    .fd = fd,
    .offset = offset
  };
  if (rd_init() < 0)
    return -1;
  if ((ret = ioctl(rdfd, RD_LSEEK, &arg)) < 0)
    perror("rd_lseek\n");
  return ret;
}

int rd_unlink(char *pathname)
{
  int ret = 0;
  if (rd_init() < 0)
    return -1;
  if ((ret = ioctl(rdfd, RD_UNLINK, pathname)) < 0)
    perror("rd_unlink\n");
  return ret;
}

int rd_readdir(int fd, char *address)
{
  int ret = 0;
  rd_readdir_arg_t arg = {
    .address = address,
    .fd = fd
  };
  if (rd_init() < 0)
    return -1;
  if ((ret = ioctl(rdfd, RD_READDIR, &arg)) < 0)
    perror("rd_readdir\n");
  return ret;
}

#ifdef DEBUG
int main(int argc, char *argv[])
{

  printf("%d\n", rd_unlink("/dir1/dir2"));
  /* char pathname[80] = {'\0'}; */
  /* char buf[80] = {'\0'}; */
  /* int i = 0, handle = -1; */
  /* FILE *fl; */
  /* rd_init(); */

  /* handle = rd_open("/"); */
  
  /* for (i = 0; i < 600; i++) { */
  /*   printf("%d %s | ", rd_readdir(handle, buf), buf); */
  /* } */

  return 0;
}
#endif
