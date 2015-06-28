#include "dglib.h"
#include "file.h"

int statXX(const char *p,FileStat *b){
	return Istat(p,b);
}
void setup_hostid(FILE *out,int verb){
}
int capsreq_main(int ac,const char *av[]){
	NOSRC_warn("capsreq","");
	return -1;
}
int dump_hostid(PVStr(out),int verb){
	strcpy(out,"No-HostId-Available");
	return -1;
}
int capsgen_main(int ac,const char *av[]){
	NOSRC_warn("capsgen","");
	return -1;
}
int setup_caps(FILE *out,PCStr(slkey),PCStr(admin),int test){
	NOSRC_warn("setup_caps","");
	return -1;
}
void print_caps(FILE *out,int test){
}
int load_CAPSKEY(int init){
	return -1;
}
int issue_capskey(FILE *out,PVStr(capsresp),PVStr(retTo),PCStr(req),PCStr(from),PCStr(to)){
	NOSRC_warn("issue_capskey","");
	return -1;
}
int allowOutboundHTMUX(int clnt){
	return -1;
}
int scounter(int tid,const void *vkstr,int klen,int inc){
	return -1;
}
