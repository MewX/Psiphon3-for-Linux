int SUBST_setlinebuf = 1;

#include <stdio.h>
#ifdef _IOFBF
/*
int setvbuf(FILE*,char*,int,unsigned int);
*/
void setlinebuf(FILE *fp)
{
	setvbuf(fp,NULL,_IOLBF,BUFSIZ);
}
#else
static int dummy;
#endif

