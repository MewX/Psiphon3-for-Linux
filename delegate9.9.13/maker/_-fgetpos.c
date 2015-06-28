#include <stdio.h>
#include "file.h"

int Fgetpos(FILE *fp,Fpos_t *pos){
	return fgetpos(fp,(fpos_t*)pos);
}
int Fsetpos(FILE *fp,Fpos_t *pos){
	return fsetpos(fp,(fpos_t*)pos);
}
