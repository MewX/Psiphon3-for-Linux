/*
 * libdelegate?
 */

#include <stdio.h>
#include "ystring.h"
#include "dgctx.h"

int VSocket(DGC*C,PCStr(b),int c,PVStr(d),PVStr(e),PCStr(f)){
        return -1;
}
int CTX_ToS(DGC*ctx){
	return -1;
}
int CTX_FromS(DGC*ctx){
	return -1;
}
int fullpathSUCOM(PCStr(path),PCStr(mode),PVStr(xpath)){
        return 0;
}
int fullpathDYLIB(PCStr(path),PCStr(mode),PVStr(xpath)){
	return 0;
}
void BeforeExec(){
}

int MAIN_argc;
const char **MAIN_argv;
const char *getMainArg(PCStr(where),PCStr(name)){
	const char *val;
	if( MAIN_argv ){
		if( val = getv(MAIN_argv,name) )
			return val;
	}
	return getenv(name);
}

int pamViaSudo(PCStr(service),PCStr(user),PCStr(pass),int *ok){
	return -1;
}

void tcp_relay2(int timeout,int s1,int d1,int s2,int d2);
void tcp_relay2X(DGC*ctx,int timeout,int s1,int d1,int s2,int d2){
	tcp_relay2(timeout,s1,d1,s2,d2);
}

int SERNO(){ return 0; }
int BREAK_STICKY;
void clearThreadEnv(){ }
int gotsigTERM(PCStr(fmt),...){ return 0; }

int dump_ENTR(PCStr(fmt),PVStr(entrance)){ return 0; }

const char *DELEGATE_exesign(){ return ""; }

void NOSRC_warn(PCStr(func),PCStr(fmt),...){
	fprintf(stderr,"## %s: Not available",func);
}

/*
typedef struct {
  const char *name;
        void *addr;
  const char *opts;
} DLMap;
int dl_library(const char *libname,DLMap *dlmap,const char *mode){
	return -1;
}
*/
#ifdef _MSC_VER
int pubDecyptRSA(PCStr(pubkey),int len,PCStr(enc),PVStr(dec)){ return -1; }
#endif

/*
int inGzip;
const char *FL_F_Gzip;
int FL_L_Gzip;
*/

#if isWindows() && !isWindowsCE()
int FMT_putInitlog(const char *fmt,...){
	return 0;
}

/* socks5.o */
void finishClntYY(FL_PAR,DGCTX){}
void finishServYY(FL_PAR,DGCTX){}
const char *gethostaddrX(PCStr(host)){ return "255.255.255.255"; }
int SRCIFfor(DGCTX,PCStr(proto),PCStr(rhost),int rport,PVStr(lhost),int *lport){ return 0; }
DGC*MainConn(){ return 0; }
#endif
