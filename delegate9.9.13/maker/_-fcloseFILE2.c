const char *type_fcloseFILE = "B";
#include <stdio.h>
#include "ystring.h"
/*
 * fclose(FILE *fp) without closing fileno(FILE *fp)
 */
int FL_fcloseFILE(FL_PAR,FILE *fp){ 
	int fd = fileno(fp);
	fflush(fp);
	fp->_fileno = -1;
	fclose(fp);
        return fd;
}
