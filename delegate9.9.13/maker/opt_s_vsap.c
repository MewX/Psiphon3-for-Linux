#include "dglib.h"
const char *OPT_S_vsap;
int CTX_VSAPbind(DGCTX Conn,PVStr(sockname),int nlisten){
	NOSRC_warn("VSAPbind","");
	setVStrEnd(sockname,0);
	return -1;
}
int VSAPaccept(DGCTX Conn,int timeout,int rsock,int priority,PVStr(sockname),PVStr(peername)){
	NOSRC_warn("VSAPaccept","");
	setVStrEnd(sockname,0);
	setVStrEnd(peername,0);
	return -1;
}
int CTX_VSAPbindaccept(DGCTX Conn,int timeout,int priority,PVStr(sockname),PVStr(peername)){
	NOSRC_warn("VSAPbindaccept","");
	setVStrEnd(sockname,0);
	setVStrEnd(peername,0);
	return -1;
}
