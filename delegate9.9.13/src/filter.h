/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1999 Electrotechnical Laboratry (ETL), AIST, MITI
Copyright (c) 1999 Yutaka Sato

Permission to use, copy, and distribute this material for any purpose
and without fee is hereby granted, provided that the above copyright
notice and this permission notice appear in all copies.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
//////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	filter.h
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	990823	extracted from delegate.h,filter.c
//////////////////////////////////////////////////////////////////////#*/

#define F_CL		 1
#define F_TOCL		 2
#define F_FROMCL	 3
#define F_SV		 4
#define F_TOSV		 5
#define F_FROMSV	 6
#define F_MD		 7
#define F_TOMD		 8
#define F_FROMMD	 9
#define F_RPORT		10
#define F_CACHE		11
#define F_TOCACHE	12
#define F_FROMCACHE	13
#define F_PROXY		14
#define F_PRE_TOCL	15
#define F_PRE_FROMCL	16
#define F_PRE_TOSV	17
#define F_PRE_FROMSV	18
#define F_PRE_TOMD	19
#define F_PRE_FROMMD	20
#define F_DISABLE	21

#define XF_mask(i)	(1<<(i-1))

#define XF_ALL		-1
#define XF_FCL		XF_mask(F_CL)
#define XF_FTOCL	XF_mask(F_TOCL)
#define XF_FFROMCL	XF_mask(F_FROMCL)
#define XF_FSV		XF_mask(F_SV)
#define XF_FTOSV	XF_mask(F_TOSV)
#define XF_FFROMSV	XF_mask(F_FROMSV)
#define XF_FMD		XF_mask(F_MD)
#define XF_FTOMD	XF_mask(F_TOMD)
#define XF_FFROMMD	XF_mask(F_FROMMD)
#define XF_RPORT	XF_mask(F_RPORT)
#define XF_PRE_TOCL	XF_mask(F_PRE_TOCL)
#define XF_PRE_FROMCL	XF_mask(F_PRE_FROMCL)
#define XF_PRE_TOSV	XF_mask(F_PRE_TOSV)
#define XF_PRE_FROMSV	XF_mask(F_PRE_FROMSV)
#define XF_PRE_TOMD	XF_mask(F_PRE_TOMD)
#define XF_PRE_FROMMD	XF_mask(F_PRE_FROMMD)
#define XF_DISABLE	XF_mask(F_DISABLE)

#define XF_CLIENT	(XF_FFROMCL|XF_FTOCL|XF_FCL)
#define XF_SERVER	(XF_FFROMSV|XF_FTOSV|XF_FSV)
#define XF_MASTER	(XF_FFROMMD|XF_FTOMD|XF_FMD)

int waitFilterThread(Connection *Conn,int timeout,int which);
int waitPreFilter(Connection *Conn,int msec);

int pushSTLS_FSV(Connection *Conn,PCStr(proto));
int clearSTLS(Connection *Conn);
int clearSTLSX(Connection *Conn,int fmask);
int uncheckSTLS_SV(Connection *Conn);

