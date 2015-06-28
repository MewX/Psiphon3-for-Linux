#include "dglib.h"
const char *OPT_S_sox;

typedef struct DGSox Sox;
typedef struct SoxAgent Agent;
typedef struct SoxPacket Packet;

void *optctx(DGC*ctx){
	return 0;
}
int sox_connects(void *sc,Sox *sox,DGC*ctx,PVStr(local),PVStr(remote),int itvl){
	NOSRC_warn("sox_connects","");
	return -1;
}
int sox_connect1(void *sc,DGC*ctx,Packet *pack,PCStr(serverURL),PVStr(remote),PVStr(local),int *pidp){
	NOSRC_warn("sox_connect1","");
	return -1;
}
int beSockMux(DGC*ctx,int sxsock,int insock,PCStr(sxhost),int sxport){
	NOSRC_warn("beSockMux","");
	return -1;
}

void send_BIND(Sox *sox,Agent *Apc,Packet *pack,PCStr(ports),Agent *Ap1){
}
void recv_BOUND(Sox *sox,Packet *pack){
}
void recv_BIND(Sox *sox,Agent *Apc,Packet *pack){
}
