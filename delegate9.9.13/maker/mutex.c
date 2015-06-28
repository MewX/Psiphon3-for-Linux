#include "ystring.h"
const char *WithMutex = "none";
int setupCSC(const char *wh,void *acs,int asz){
        return 0;
}   
int debugCSC(void *acs,int on){
	return -1;
}
int enterCSC_FL(FL_PAR,void *xcs){
        return 0;
}
int enterCSCX_FL(FL_PAR,void *xcs,int timeout){
        return 0;
}
int leaveCSC_FL(FL_PAR,void *xcs){
	return 0;
}
int statsCSC(void *acs,int *count,int *retry,int *timeout){
	*count = *retry = *timeout = 0;
	return -1;
}
int sizeofCSC(){
        return 0;
}
