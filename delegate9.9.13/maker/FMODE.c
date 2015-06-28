#include <stdio.h>
#include <fcntl.h>

#if defined(O_BINARY) && !defined(__CYGWIN__)
#include <stdlib.h>
void setBinaryIO(){ _fmode = O_BINARY; }
#else
void setBinaryIO(){ }
#endif

