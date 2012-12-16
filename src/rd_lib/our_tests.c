/* 
   Our test cases
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "rd.h"

// #define's to control what tests are performed,
// comment out a test if you do not wish to perform it

#define RAND_WRITE_AND_SEEK
#define EXCESSIVE_WRITE_REQUEST
#define WRITE_TO_DIR
#define TEST6 //mkdir
#define TEST7 //open
#define TEST8 //close
#define TEST9 //readdir

// #define's to control whether single indirect or
// double indirect block pointers are tested

#define TEST_SINGLE_INDIRECT
#define TEST_DOUBLE_INDIRECT


#define MAX_FILES 1023
#define BLK_SZ 256		/* Block size */
#define DIRECT 8		/* Direct pointers in location attribute */
#define PTR_SZ 4		/* 32-bit [relative] addressing */
#define DIR_ENTRY_SZ 16
#define PTRS_PB  (BLK_SZ / PTR_SZ) /* Pointers per index block */
#define MAX_FILE_SIZE (BLK_SZ * (DIRECT + PTRS_PB + PTRS_PB*PTRS_PB))
#define NUM_DATA_BLOCKS 7931

static char pathname[80];

static char data1[DIRECT*BLK_SZ]; /* Largest data directly accessible */
static char data2[PTRS_PB*BLK_SZ];     /* Single indirect data size */
static char data3[PTRS_PB*PTRS_PB*BLK_SZ]; /* Double indirect data size */
static char addr[PTRS_PB*PTRS_PB*BLK_SZ+1]; /* Scratchpad memory */
static char pathname[80];
static char sequential_data[MAX_FILE_SIZE * 2];
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

int main () {
  int retval, fd, i, offset;
  char comp;
  
  
  /* Some arbitrary data for our files */
  memset (data1, '1', sizeof (data1));
  memset (data2, '2', sizeof (data2));
  memset (data3, '3', sizeof (data3));

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

#ifdef TEST6 //(mkdir)
  //if filename is longer than 14bytes
  retval = rd_mkdir("/123456789012345");
  
  if (retval >= 0)
  {
	  fprintf (stderr, "rd_mkdir: Filename longer than 14 bytes is created\n");
	  exit(1);
  }
  
//if creating DIR nder REG file
  rd_creat("/test.txt");
  retval = rd_mkdir("/test.txt/dir");
  
  if (retval >= 0)
  {
	  fprintf (stderr, "rd_mkdir: Directory created under regular file\n");
	  exit(1);
  }
    
//if parent DIR doesn't exist
  retval = rd_mkdir("/nonexistdir/dir");
  
  if (retval >= 0)
  {
	  fprintf (stderr, "rd_mkdir: Directory created under non-existing parent\n");
	  exit(1);
  }
  
//if creating maximum number of directories
  /* Generate MAXIMUM directory files */
  for (i = 0; i < MAX_FILES + 1; i++) { // go beyond the limit
    sprintf (pathname, "/dir%d", i);
    retval = rd_mkdir(pathname);
    if (retval < 0) {
      fprintf (stderr, "rd_mkdir: File creation error! status: %d\n", retval);
      if (i != MAX_FILES)
        break;
    }
    memset (pathname, 0, 80);
  }  
  
  /* Delete some of the directories created */
  for (i = 0; i < 100; i++) { 
    sprintf (pathname, "/dir%d", i);
    retval = rd_unlink (pathname);
    
    if (retval < 0) {
      fprintf (stderr, "rd_unlink: File deletion error! status: %d\n", 
	       retval);
      
      exit (1);
    }
    
    memset (pathname, 0, 80);
  }
#endif

#ifdef TEST7 //(open)
//if filename doesn't exist
  retval =  rd_open ("/nonexist"); /* Open directory file to read its entries */
  
  if (retval >= 0)
  {
	fprintf (stderr, "rd_open: non-existing directory opened\n");
	exit(1);
  }
  
  retval =  rd_open ("/nonexist.txt"); /* Open regular file */
  if (retval >= 0)
  {
	fprintf (stderr, "rd_open: non-existing file opened\n");
	exit(1);
  }
#endif 

#ifdef TEST8 //(close)
  retval = rd_close(1000);
  
  if (retval >= 0)
  {
	fprintf (stderr, "non-opened file closed\n");
	exit(1);
  }
#endif

#ifdef TEST9 //(readdir)
//if reading REG file
  rd_creat("/test.txt");
  fd = rd_open("/test.txt");
  memset (addr, 0, sizeof(addr)); /* Clear scratchpad memory */
  retval = rd_readdir (fd, addr); /* 0 indicates end-of-file */
  
  if (retval >= 0)
  {
	fprintf (stderr, "rd_readdir: Regular file read\n");
	exit(1);
  }

//if dir is empty
  rd_mkdir("/test9");
  fd = rd_open("/test9");
  //fprintf (stderr, "fd: %d\n", fd);
  memset (addr, 0, sizeof(addr)); /* Clear scratchpad memory */
  retval = rd_readdir (fd, addr); /* 0 indicates end-of-file */
  
  if (retval != 0)
  {
	fprintf (stderr, "rd_readdir: Didn't return 0 on empty directory\n");
	exit(1);
  }

#endif

  fprintf(stdout, "Passed all of our own tests\n");

  return 0;
}
