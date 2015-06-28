#include <stdio.h>
int pendingcc(FILE *fp){
	if( fp == NULL )
		return -1;
	return fp->_bf._size - fp->_w;
}
