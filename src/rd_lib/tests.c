#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "rd.h"

#define RAND_WRITE_AND_SEEK
#define UNLINK
#define EXCESSIVE_WRITE_REQUEST
#define WRITE_TO_DIR

#define MAX_FILES 1023
#define BLK_SZ 256		
#define DIRECT 8		
#define PTR_SZ 4		
#define PTRS_PB  (BLK_SZ / PTR_SZ)
#define MAX_FILE_SIZE (BLK_SZ * (DIRECT + PTRS_PB + PTRS_PB*PTRS_PB))

static char pathname[80];
static char sequential_data[MAX_FILE_SIZE * 2];
static char addr[PTRS_PB*PTRS_PB*BLK_SZ+1];
static char read_buf[MAX_FILE_SIZE];

int make_seqfile()
{
  int retval, fd;
  retval = rd_creat("/seqfile");
  if (retval < 0) {
    fprintf (stderr, "rd_create: Error creating seqfile! status: %d\n", 
	     retval);
    exit(1);
  }

  retval = rd_open("/seqfile");
  if (retval < 0) {
    fprintf (stderr, "rd_open: Error opening seqfile! status: %d\n", 
	     retval);
    exit(1);
  }
  fd = retval;

#ifdef EXCESSIVE_WRITE_REQUEST  
  retval = rd_write(fd, sequential_data, 2*MAX_FILE_SIZE);
  if (retval > MAX_FILE_SIZE) {
    fprintf (stderr, "rd_write: Reportedly wrote too much data! status: %d\n", 
	     retval);
    exit(1);
  }
#else
  retval = rd_write(fd, sequential_data, MAX_FILE_SIZE);
  if (retval > MAX_FILE_SIZE) {
    fprintf (stderr, "rd_write: Reportedly wrote too much data! status: %d\n", 
	     retval);
    exit(1);
  }
#endif  

  if (rd_close(fd) < 0) {
    fprintf (stderr, "rd_close: Reportedly wrote too much data! status: %d\n", 
	     retval);
    exit(1);
  }
  
  return 0;
  
}


int main()
{
  int retval, fd, i, offset, index_node_number;
  char comp;

  for (i = 0; i < MAX_FILE_SIZE; i++) {
   sequential_data[i] = (char) (((int) '0') + i % 10);
  }

#ifdef RAND_WRITE_AND_SEEK  
  make_seqfile();
  if (retval = rd_open("/seqfile") < 0) {
    fprintf (stderr, "rd_open: Error opening seqfile! status: %d\n", 
	     retval);
    exit(1);
  }
  fd = retval;    
  for (i = 0; i < 300; i++) {
    offset = rand() % (MAX_FILE_SIZE + 5);
    retval = rd_lseek(fd, offset);
    if (retval < 0 && offset < MAX_FILE_SIZE) {
      fprintf (stderr, "rd_lseek: Error seeking to valid offset %d! status: %d\n", 
	       offset, retval);
      exit(1);
    } else if (retval < 0 && offset > MAX_FILE_SIZE)
      continue;
    retval = rd_read(fd, read_buf, 1);
    if (retval < 1) {
      fprintf (stderr, "rd_read: Error reading  valid offset %d! status: %d\n", 
	       offset, retval);
      exit(1);
    }
    comp = (char) (((int) '0') + offset % 10);
     if (read_buf[0] != comp) {
       fprintf (stderr, "rd_read: Expected to read %c at offset %d, but read %c! status: %d\n", 
		comp, offset, read_buf[0], retval);
       exit(1);
     }
   }


 #endif  

  fprintf(stdout, "Passed all of my own tests\n");
  return 0;
}
