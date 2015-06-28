/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1996 Electrotechnical Laboratry (ETL), AIST, MITI

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
Program:	service.h
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	961029	extracted from service.c
//////////////////////////////////////////////////////////////////////#*/

#include "dgctx.h"
typedef struct DGCtx *DGCP;
typedef int servFunc(DGCP Conn);
typedef int (*servFuncP)(DGCP Conn);
typedef int servFunc2(DGCP Conn,int,int);
typedef int servFuncX(DGCP Conn,int,int,int fromC,int toC,PCStr(dST_PROTO),PCStr(dST_HOST),int dST_PORT,PCStr(d_SELECTOR));

#define PI_CLNT	1
#define PI_SERV	2
#define PI_BOTH	3

typedef struct {
	int	 s_withcache;
	int	 s_initfrom;	/* initiated from client/server side */
	int	 s_selfack;	/* return ack in the protocol handler */
  const	char	*s_name;
	int	 s_iport;	/* default port */
       servFuncP s_client;
	int	 s_stls;	/* STARTLS */
  const	char	*s_Host;	/* default server host */

	int	 s_nocallback;	/* should be obsoleted by
				 MOUNT="/-_-* * proto=!{protoList}" */
	int	 s_stats;
} Service;
#define services services_tab

#define VPORT	0x10000
#define NSERVICES	100
#define SV_DISABLE	0x00000001
