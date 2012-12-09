#include <stdio.h>
#include <string.h>
#include "rd.h"

int main() {
  char tokenize_me[] = {"/drew/documents/file"};
  char *to_print = NULL;
  char *tokenize = tokenize_me;
  printf("About to tokenize \"/drew/documents/file\"\n");
  while ((to_print = strsep(&tokenize, "/")) != NULL) {
      printf("%s\n", to_print);
    }
  strcpy(tokenize_me, "new string");
  printf("%s\n", tokenize_me);
  printf("Finished\n");
  return 0;
}
