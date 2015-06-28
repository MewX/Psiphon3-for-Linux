#ifndef _MSC_VER
const char *type_fcloseFILE = "C";
#include <stdio.h>
#include "ystring.h"
/*
 * fclose(FILE *fp) without closing fileno(FILE *fp)
 */
int FL_fcloseFILE(FL_PAR,FILE *fp){
	int fd,fdsav;

	fd = fileno(fp);
	fdsav = dup(fd);
	fclose(fp);
	close(fd); /* do closesocket() on Win32 */
	dup2(fdsav,fd);
	close(fdsav);
	return fd;
}
#endif
