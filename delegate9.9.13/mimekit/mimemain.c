#define main mainX /*{*/
#ifdef ENMIME
int ENMIME_main(int ac,const char *av[]);
int main(int ac,char *av[]){ return ENMIME_main(ac,(const char**)av); }
#endif
#ifdef DEMIME
int DEMIME_main(int ac,const char *av[]);
int main(int ac,char *av[]){ return DEMIME_main(ac,(const char**)av); }
#endif

#ifdef LOCAL2MIME
int LOCAL2MIME_main(int ac,const char *av[]);
int main(int ac,char *av[]){ return LOCAL2MIME_main(ac,(const char**)av); }
#endif
#ifdef MIME2LOCAL
int MIME2LOCAL_main(int ac,const char *av[]);
int main(int ac,char *av[]){ return MIME2LOCAL_main(ac,(const char**)av); }
#endif
#undef main /*}*/

#include "ystring.h"
int randstack_call(int strg,iFUNCP func, ...);
int main(int ac,char *av[]){
	/*
	randstack_call(SB_STAT,(iFUNCP)mainX,ac,av);
	*/
	return mainX(ac,av);
}

#if defined(ENMIME)||defined(DEMIME)||defined(LOCAL2MIME)||defined(MIME2LOCAL)
int (*MIME_setPosterMasks)(PCStr(from));
int (*MIME_makeEmailFP)(PVStr(ocrc),PCStr(addr));
int (*MIME_makeEmailCX)(PVStr(ocrc),PCStr(wf),PCStr(addr));
int (*MIME_mapPosterAddr)(PCStr(maddr),PVStr(xmaddr));
int (*MIME_mapMessageId)(PCStr(xref),PCStr(msgid),PVStr(xmsgid));
int (*MIME_makeAdminKey)(PCStr(from),PVStr(key),int siz);
#endif
