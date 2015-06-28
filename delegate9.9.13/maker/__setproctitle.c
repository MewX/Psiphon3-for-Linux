#include "ystring.h"
#include <sys/types.h>
#include <unistd.h>
int Setproctitle(const char *fmt,...){
	VARGS(8,fmt);
	setproctitle(fmt,VA8);
	return 0;
}
