#include "ystring.h"

#ifdef __cplusplus
extern "C" {
#endif

int SUBST_pam_start = 1;

int pam_start(const char *s,const char *u,const struct pam_conv *c,void**h){
	porting_dbg("ERROR: PAM module is not built in.");
	return -1;
}
int pam_end(void *ph,int ps){
	return -1;
}
int pam_authenticate(void *ph,int flags){
	return -1;
}

#ifdef __cplusplus
}
#endif
