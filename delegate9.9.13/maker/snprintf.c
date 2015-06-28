#if defined(__osf__)
#include <stdio.h>
#include <varargs.h>
int snprintf(va_alist) va_dcl {
	va_list va;
	char *d;
	int n;
	const char *f;
	int z;

	va_start(va);
	d = va_arg(va,char*);
	n = va_arg(va,int);
	f = va_arg(va,const char*);
	z = vsprintf(d,f,va);
	va_end(va);
	if( n < z ){
		fprintf(stderr,"--FATAL-- snprintf %d/%d [%s]\n",z,n,f);
	}
	return z;
}
int vsnprintf(va_alist) va_dcl {
	va_list va;
	char *d;
	int n;
	const char *f;
	va_list v;
	int z;

	va_start(va);
	d = va_arg(va,char*);
	n = va_arg(va,int);
	f = va_arg(va,const char*);
	v = va_arg(va,va_list);
	z = vsprintf(d,f,v);
	va_end(va);
	if( n < z ){
		fprintf(stderr,"--FATAL-- vsnprintf %d/%d [%s]\n",z,n,f);
	}
	return z;
}
#endif
