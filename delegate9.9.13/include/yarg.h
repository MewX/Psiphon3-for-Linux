#ifndef _YARG_H
#define _YARG_H

typedef int (*iFUNCP)(const void*,...);
typedef void (*vFUNCP)(void*,...);
typedef char *(*sFUNCP)(void*,...);

#include <stdarg.h>
#define VARGS(ac,a0) \
	char *va[ac]; va_list ap; va_start(ap,a0); \
	{ int ai; for(ai = 0; ai < ac; ai++) va[ai] = va_arg(ap,char*); }

#define VA4	va[0],va[1],va[2],va[3]

#define VA8	va[0],va[1],va[2],va[3],va[4],va[5],va[6],va[7]

#define VA14    va[0],va[1],va[2],va[3],\
                va[4],va[5],va[6],va[7],\
                va[8],va[9],va[10],va[11],va[12],va[13]

#define VA16    va[0],va[1],va[2],va[3],\
                va[4],va[5],va[6],va[7],\
                va[8],va[9],va[10],va[11],\
		va[12],va[13],va[14],va[15]

#endif /* _YARG_H */
