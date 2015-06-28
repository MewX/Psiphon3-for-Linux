const char *type_fcloseFILE = "A";
#include <stdio.h>
#include "ystring.h" /* for fclose() with mutex with free() */
/*
 * fclose(FILE *fp) without closing fileno(FILE *fp)
 */

#if isWindows()
#define setInvalidFd(fp) fp->_file = open("null",0)
#else
#define setInvalidFd(fp) fp->_file = -1
#endif

int FL_fcloseFILE(FL_PAR,FILE *fp){ 
	int fd = fileno(fp);
	fflush(fp);
#if 1
	setInvalidFd(fp);
#else
	if( isWindows() ){
		fp->_file = open("nul",0);
	}else
	fp->_file = -1;
#endif
	fclose(fp);
        return fd;
}
