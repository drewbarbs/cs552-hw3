#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include "rd.h"
#include "../ramdisk_module/ramdisk_module.h"

int main() {


  char pathname[] = "/dir/doc/file";
  /* const char *pathname_copy = pathname; */
  /* char *tokenize = pathname_copy + 1; */
  /* char *pathname_copy = calloc(strlen(pathname) + 1, sizeof(char)); */
  /* strncpy(pathname_copy, pathname, strlen(pathname) - strlen(strrchr(pathname, '/'))); */
  /* while ((to_print = strsep(&tokenize, "/")) != NULL) { */
  /*     printf("%s\n", to_print); */
  /*   } */
  printf("%s\n", strrchr(pathname, '/'));
  printf("Finished\n");
  return 0;
}

