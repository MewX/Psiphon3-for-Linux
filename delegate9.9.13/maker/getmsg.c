int SUBST_getmsg = 1;

#include <stdio.h>
int getmsg(int fd, struct strbuf *ctlptr, struct strbuf *dataptr, int *flags)
{
	fprintf(stderr,
		"delegated: getmsg() is not linked to this executable.\n");
	return -1;
}
