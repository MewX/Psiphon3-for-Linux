#include <sys/types.h>
#include <stdlib.h>
#include <regex.h>

const char *RegexVer(){
	return "regex";
}
void *Regcomp(const char *pat,int flag){
	regex_t re;
	regex_t *rre;
	int rcode;

	rcode = regcomp(&re,pat,flag);
	if( rcode == 0 ){
		rre = (regex_t*)malloc(sizeof(re));
		*rre = re;
		return (void*)rre;
	}
	return 0;
}
int Regexec(void *re,const char *str,int nm,int so,int eo,int flag){
	int rcode;
	regmatch_t rm;

	rm.rm_so = so;
	rm.rm_eo = eo;
	rcode = regexec((regex_t*)re,str,nm,&rm,flag);
	return rcode;
}
void Regfree(void *re){
	regfree((regex_t*)re);
}
