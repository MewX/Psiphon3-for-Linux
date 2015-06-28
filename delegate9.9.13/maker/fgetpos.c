#include <stdio.h>
#include "file.h"

int Fgetpos(FILE *fp,Fpos_t *pos){
	pos[0] = ftell(fp);
	return pos[0];
}
