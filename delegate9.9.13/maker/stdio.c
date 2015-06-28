#include <stdio.h>

#ifdef _IOFBF
int STDIO_IOFBF = _IOFBF;
#else
int STDIO_IOFBF = 0;
#endif

