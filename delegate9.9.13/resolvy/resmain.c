/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1995 Electrotechnical Laboratry (ETL), AIST, MITI

Permission to use, copy, modify, and distribute this material for any
purpose and without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies, and
that the name of ETL not be used in advertising or publicity pertaining
to this material without the specific, prior written permission of an
authorized representative of ETL.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	resmain.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950817	created
//////////////////////////////////////////////////////////////////////#*/
#include "ystring.h"
#include "vaddr.h"
#include "dgctx.h"

void FinishX(PCStr(F),int L,int code)
{
	exit(code);
}

int resolvy_main(int ac,const char *av[]);
int main(int ac,char *av[]){ return resolvy_main(ac,(const char**)av); }

void setBinaryIO(){ }
void WINthread(){}
int acceptViaSocks(int sock,PVStr(rhost),int *rport){ return -1; }
int bindViaSocks(DGC*Conn,PCStr(dsthost),int dstport,PVStr(rhost),int *rport){ return -1; }
int GetViaSocks(DGC*Conn,PCStr(host),int port){ return 0; }
int CTX_auth(DGC*ctx,PCStr(user),PCStr(pass)){ return 0; }
int VSA_getViaSocksX(DGC*ctx,PCStr(h),int p,VSAddr *sv,AuthInfo *au,VSAddr *lo){
	return 0;
}
int serverPid(){ return getpid(); }
void finishClntYY(FL_PAR,DGCTX){}
void finishServYY(FL_PAR,DGCTX){}
const char *gethostaddrX(PCStr(host)){ return "255.255.255.255"; }
int SRCIFfor(DGCTX,PCStr(proto),PCStr(rhost),int rport,PVStr(lhost),int *lport){ return 0; }
DGC*MainConn(){ return 0; }
