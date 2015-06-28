#include "ystring.h"
/* to screen the warning out to the standard output */
const char *p2llx = "A";
Int64 p2llX(FL_PAR,const void *p){
	return (Int64)p;
}
/* return 32bits value without sign extension */
Int64 p2lluX(FL_PAR,const void *p){
	if( sizeof(p) == 4 ){
		return 0xFFFFFFFF & (unsigned Int64)p;
	}
	return (Int64)p;
}
const void *ll2pX(FL_PAR,Int64 ll){
	return (const void *)ll;
}
const void *i2pX(FL_PAR,int i){
	return (const void *)i;
}
