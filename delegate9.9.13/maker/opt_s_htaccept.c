#include "dglib.h"
const char *OPT_S_htaccept;

int AcceptViaHTTP(DGCTX Conn,int ba,int rsock,int timeout,int priority,PCStr(rport),PVStr(sockname),PVStr(peername)){
	NOSRC_warn("AcceptViaHTTP","");
	setVStrEnd(sockname,0);
	setVStrEnd(peername,0);
	return -1;
}
int ConnectViaHTTP(DGCTX Conn,int sock,int timeout,PVStr(rhost),PVStr(rpeer)){
	NOSRC_warn("ConnectViaHTTP","");
	setVStrEnd(rhost,0);
	setVStrEnd(rpeer,0);
	return -1;
}
int startHTMUX_SV(DGCTX Conn,PCStr(sxver),FILE *tc,PCStr(req),PCStr(head)){
	NOSRC_warn("startHTMUX_SV","");
	return -1;
}
int startHTMUX_CL(DGCTX Conn,int sock,PCStr(rport)){
	NOSRC_warn("startHTMUX_CL","");
	return -1;
}
