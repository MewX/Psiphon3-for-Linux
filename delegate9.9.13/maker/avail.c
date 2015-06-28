#include <stdio.h>

int main(int ac,char *av[])
{	const char *CC;
	const char *sym;
	int avail;
	FILE *tmp;

	if( ac < 3 ){
		fprintf(stderr,"Usage: %s CC function_name\n",av[0]);
		return -1;
	}

	tmp = tmpfile();
	CC = av[1];
	sym = av[2];
	avail = _available(tmp,sym,CC,"","");
	printf("%s is %s\n",sym,avail?"available":"not available");
	exit(avail);
}
