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

#ifdef MULTI_THREAD
pthread_t t1;
pthread_t t2;  
pthread_attr_t attr1;
pthread_attr_t attr2;
#endif

void thread_func(void *arg)
{
  printf("Thread %d about to open ramdisk\n", (int) arg);
  int fd;
  fd = open("/proc/ramdisk", 0);
  ioctl(fd, DBG_MK_FDT, NULL);  
  printf("Thread %d about to close ramdisk\n", (int) arg);
  close(fd);
  while (1) {}
  return;
}
int main(int argc, char *argv[])
{

#ifdef FORK
  pid_t child;
#endif  

#ifdef MULTI_THREAD
  pthread_attr_init(&attr1);
  pthread_attr_init(&attr2);
  pthread_create(&t1, &attr1, thread_func, 1);
  pthread_create(&t2, &attr2, thread_func, 2);
  sleep(2);
#endif
  printf("My pid: %d, parent pid: %d, process group id: %d \nAbout to rd_init()\n", getpid(), getppid(),getpgrp());  

  rd_init();

#ifdef FORK
  if ((child = fork()) == 0) {
    printf("In child with pid: %d, parent pid: %d, process group id: %d \nAbout to close()\n", getpid(), getppid(),getpgrp());
    close(fd);
  } else {


#endif
  if (argc > 1 && strcmp(argv[1], "c") == 0)
    ioctl(fd, DBG_MK_FDT, NULL);  
  else if (argc > 1 && strcmp(argv[1], "d") == 0) {
    ioctl(fd, DBG_RM_FDT, atoi(argv[2]));
  }else if (argc > 1 && strcmp(argv[1], "p") == 0)
    ioctl(fd, DBG_PRINT_FDT_PIDS, NULL);
  else
    printf("Usage: ./a.out [cdp] <pid> (only if deleting)\n");
  
  pthread_exit(0);
  /*while (1) {}  */
#ifdef FORK
  }
#endif
      return 0;
}
#endif
