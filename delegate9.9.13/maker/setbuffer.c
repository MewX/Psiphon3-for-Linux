int SUBST_setbuffer = 1;

#include <stdio.h>
extern int STDIO_IOFBF;
void setbuffer(FILE *fp,char *buff,unsigned int size)
{
	setvbuf(fp,buff,STDIO_IOFBF,size);
}
