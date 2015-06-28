#include "ystring.h"
int getThreadIds(FileSize *mtid,FileSize *ctid){ return 0; }

const char *WithThread = 0;
int (*ThreadFork)() = 0;
int (*ThreadYield)() = 0;
int (*ThreadId)() = 0;
int (*ThreadWait)(int,int) = 0;
int (*ThreadExit)(void *code) = 0;
int SIZEOF_tid_t = 0;
