#define SIGABRT 1
#define SIGSEGV 2
#define SIGTERM 3
#define SIGINT  4

typedef void (*sigFunc)(int);
sigFunc signal(int,sigFunc);
#define SIG_DFL 0
#define SIG_IGN 0
