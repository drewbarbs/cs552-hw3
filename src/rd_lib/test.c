#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rd.h"

int main() {
  /* char tokenize_me[] = {"/drew/documents/file"}; */
  char *to_print = NULL;

  char pathname[] = "/dir/doc/file";
  const char *pathname_copy = pathname;
  char *tokenize = pathname_copy + 1;
  /* char *pathname_copy = calloc(strlen(pathname) + 1, sizeof(char)); */
  /* strncpy(pathname_copy, pathname, strlen(pathname) - strlen(strrchr(pathname, '/'))); */
  while ((to_print = strsep(&tokenize, "/")) != NULL) {
      printf("%s\n", to_print);
    }
  //  printf("%s\n", pathname_copy);
  printf("Finished\n");
  return 0;
}


for (i = 0; i < current->size / sizeof(directory_entry_t); i++) {
  if (i % DIR_ENTRIES_PB == 0) {
    if (i < DIRECT * DIR_ENTRIES_PB) {
      block_ptr = current->direct[i/DIR_ENTRIES_PB];
    }
  }
  /* if (block_ptr[i].filename is equal to token) {
       current_index_node_number = block_ptr[i].index_node_number;
       current
     }


  
 }
