
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
#define DIR_ENTRY_SZ 16
#define PTRS_PB  (BLK_SZ / PTR_SZ)
#define MAX_FILE_SIZE (BLK_SZ * (DIRECT + PTRS_PB + PTRS_PB*PTRS_PB))
#define NUM_DATA_BLOCKS 7931

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

  if ((retval = rd_close(fd)) < 0) {
    fprintf (stderr, "rd_close: Error closing seqfile! status: %d\n", 
	     retval);
    exit(1);
  }
  
  return 0;
  
}


int main()
{
  int retval, fd, i, offset, index_node_number, num_written;
  char comp;

  /* Prepare data */
  memset (pathname, 0, 80);
  /* Fill data array where sequential_data[i] == "%d" i % 10 */
  for (i = 0; i < MAX_FILE_SIZE; i++) {
   sequential_data[i] = (char) (((int) '0') + i % 10);
  }

#ifdef RAND_WRITE_AND_SEEK  
  make_seqfile();
  if ((retval = rd_open("/seqfile")) < 0) {
    fprintf (stderr, "rd_open: Error opening seqfile! status: %d\n", 
	     retval);
    exit(1);
  }
  fd = retval;
  /* Seek to random offsets in file, make sure the byte read is
     equal to the offset */
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

  memset(read_buf, 0, MAX_FILE_SIZE);

  if ((retval = rd_close(fd)) < 0) {
    fprintf (stderr, "rd_close: Reportedly wrote too much data! status: %d\n", 
	     retval);
    exit(1);
  }

  retval = rd_unlink("/seqfile");
  if (retval < 0) {
    fprintf(stderr, "rd_unlink: Error unlinking seqfile: status %d\n", retval);
    exit(1);
  }

  /* Ensure that the root directory is now empty */
  retval = rd_open("/");
  if (retval < 0) {
    fprintf(stderr, "rd_open: Error opening root file: status %d\n", retval);
    exit(1);
  }

  fd = retval;
  retval = rd_readdir(fd, read_buf);
  if (retval != 0 || strlen(read_buf) > 0) {
    fprintf(stderr, "rd_readdir: Expected empty root file, but got dir entry %s: status %d\n", read_buf, retval);
    exit(1);
  }
  
  if ((retval = rd_close(fd)) < 0) {
    fprintf (stderr, "rd_close: Reportedly wrote too much data! status: %d\n", 
	     retval);
    exit(1);
  }
  
 #endif  

#ifdef UNLINK
  /* Tests that rd_unlink does not create fragmentation of directory entries.
     
     Assumes root directory is empty to begin with. Generates MAX_FILES (1023),
     which utilizes DIRECT + 1 (indirect block) + 56 data blocks
     a subset of them of size large enough to free a data_block,
     so that remaining datablocks should be
     NUM_DATA_BLOCKS - (DIRECT + 1 + 56 - 1)
     and then tries to generate a file large enough to fill the remaining data
     blocks 
  */

  memset (pathname, 0, 80);
  /* Generate MAXIMUM regular files */
  for (i = 0; i < MAX_FILES + 1; i++) { // go beyond the limit
    sprintf (pathname, "/file%d", i);
    
    retval = rd_creat (pathname);
    
    if (retval < 0) {
      fprintf (stderr, "rd_create: File creation error! status: %d\n", 
	       retval);
      
      if (i != MAX_FILES)
	exit (1);
    }
    
    memset (pathname, 0, 80);
  }   

  /* Unlink enough  files to free a datablock + 1*/
  for (i = 0; i < 15 + 2; i++) {
    //    offset = rand() % MAX_FILES;
    memset (pathname, 0, 80);
    sprintf (pathname, "/file%d", i);
    retval = rd_unlink(pathname);
    if (retval < 0) {
      fprintf(stderr, "rd_unlink: Error unlinking file%d: status %d\n", offset, retval);
      exit(1);
    }
  }

  retval = rd_creat("/bigfile1");
  if (retval < 0) {
    fprintf (stderr, "rd_create: Error creating /bigfile! status: %d\n",
  	     retval);
    exit(1);
  }
  
  fd = rd_open("/bigfile1");
  retval = rd_write(fd, sequential_data, MAX_FILE_SIZE);
  if (retval != MAX_FILE_SIZE) {
    fprintf (stderr, "rd_write: Reportedly wrote unexpected amount of data /bigfile1! status: %d\n",
  	     retval);
    exit(1);
  }
  num_written = retval;
  if ((retval = rd_close(fd)) < 0) {
    fprintf (stderr, "rd_close: Error closing /bigfile1! status: %d\n",
  	     retval);
    exit(1);
  }
  /* retval = rd_creat("/bigfile2"); */
  /* if (retval < 0) { */
  /*   fprintf (stderr, "rd_create: Error creating /bigfile2! status: %d\n", */
  /* 	     retval); */
  /*   exit(1); */
  /* } */
  
  /* fd = rd_open("/bigfile2"); */
  /* retval = rd_write(fd, sequential_data, MAX_FILE_SIZE); */
  /* if (retval < 0) { */
  /*   fprintf (stderr, "rd_write: Error writing to  /bigfile2! status: %d\n", */
  /* 	     retval); */
  /*   exit(1); */
  /* } */
  /* num_written += retval; */
  /* if ((retval = rd_close(fd)) < 0) { */
  /*   fprintf (stderr, "rd_close: Error closing /bigfile2! status: %d\n", */
  /* 	     retval); */
  /*   exit(1); */
  /* } */
  /* if (num_written != BLK_SZ * (NUM_DATA_BLOCKS - (DIRECT + 1 + 55) */
  /* 			       - (1 + 1 + PTRS_PB))) { */
  /*   fprintf (stderr, "rd_unlink: Error utilizing remaining data blocks! Amount of data written: %d\n", */
  /* 	     num_written); */
  /*   exit(1); */
  /* } */


  

#endif



  fprintf(stdout, "Passed all of my own tests\n");
  return 0;
}
