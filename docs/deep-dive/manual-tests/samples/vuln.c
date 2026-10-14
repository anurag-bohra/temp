#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void greet(const char *in){ char buf[32]; strcpy(buf, in); printf("hello %s\n", buf); }
int main(int argc,char**argv){ char line[256]; if(argc>1) greet(argv[1]); else { gets(line); greet(line);} return 0; }
