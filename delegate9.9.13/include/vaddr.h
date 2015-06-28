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
Program:	vaddr.h
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

	Virtual and Universal Address for Applications.

History:
	991116	created
//////////////////////////////////////////////////////////////////////#*/
#ifndef _VADDR_H
#define _VADDR_H

#ifndef _VSOCKET_H
/* virtual socket address intended to be 128 bytes (enough for AF_UNIX) */
typedef struct {
	int	s_int[32];
} VSAddr;
#endif

/* virtual application address intended to be 128 bytes */
typedef struct {
 VSAddr		a_vsa;		/* union of socket addresses types */
 unsigned char	a_type;
 unsigned char	a_flags;
 unsigned short	a_port;		/* (socket) port number */
 struct {
 unsigned int	a_int[4];	/* IP address in host byte order */
 } a_ints;
 unsigned int   a_sid;		/* scope id for IPv6 */
 MStr(		a_name,102);	/* symbolic (host) name */
 MStr(		a_proto,32);
 unsigned short a_protoport;	/* the standard port# of the a_proto */
} VAddr;

#define VA_REMOTE	0x00001
#define VA_SOCKPAIR	0x00002
#define VA_RSLVOK	0x00010
#define VA_RSLVINVOK	0x00020
#define VA_RSLVERR	0x00040
#define VA_RSLVINVERR	0x00080
#define VA_RSLVED	0x000F0

extern VAddr AddrZero;
extern VAddr AddrNull;
extern VAddr MaskZero;

#define CLASS_MASK	0 /* mask determind by the default class of address */
#define HEURISTIC_MASK	1 /* mask determined by heuristics */

#define I0	a_ints.a_int[0]
#define I1	a_ints.a_int[1]
#define I2	a_ints.a_int[2]
#define I3	a_ints.a_int[3]

#define AddrEQ(a,b) ( \
	   a.I0 == b.I0 \
	&& a.I1 == b.I1 \
	&& a.I2 == b.I2 \
	&& a.I3 == b.I3 )

#define AddrAND(r,a,b) { \
	r.I0 = a.I0 & b.I0; \
	r.I1 = a.I1 & b.I1; \
	r.I2 = a.I2 & b.I2; \
	r.I3 = a.I3 & b.I3; }

#define	AddrInvalid(a)	(AddrEQ((a),AddrZero) || AddrEQ((a),AddrNull))

typedef struct {
	MStr(	i_user,64);
	MStr(	i_pass,64);
	/*
	MStr(	i_syst,60);
	*/
	MStr(	i_syst,32);
	MStr(	i_atyp,16); /* Ident, Basic, Digest */
	MStr(	i_meth,12); /* method */
	int	i_stat;
	VAddr	i_addr;
	int	i_error;
	short	i_acond;

	char	i_stype; /* origin, proxy, gateway */
	char	i_xstat;
    const char *i_xrealm; /* acceptable realm */
	MStr(	i_realm,128); /* realm */
#if 0
	MStr(	i_path,512); /* uri */
#endif
	defQStr(i_path);
	MStr(	i_nonce,64);
	MStr(	i_opaque,64);
	MStr(	i_qop,32);
	MStr(	i_nc,32);
	MStr(	i_cnonce,64);
	int	i_expire;
	MStr(	i_upfx,16); /* a sring to be prefixed to user name */
} AuthInfo03;
#define AuthInfo AuthInfo03

/*
#define IDENT_NOTYET	 0
#define IDENT_GOT	 1
*/
#define AUTH_SET	 2
#define AUTH_FORW	 4
#define AUTH_GEN	 8
#define AUTH_MAPPED	0x10
#define AUTH_GOT	0x20
#define AUTH_TESTONLY	0x40
#define AUTH_BREAK	0x80

#define AUTH_ORIGIN	0x01
#define AUTH_PROXY	0x02

#define AUTH_ENOAUTH	0x01
#define AUTH_ENOSERV	0x02
#define AUTH_ENOUSER	0x04
#define AUTH_EBADPASS	0x08
#define AUTH_ESTALE	0x10
#define AUTH_EBADDOMAIN	0x20
#define AUTH_EBADCRYPT	0x40
#define AUTH_EDONTHT	0x80

#define AUTH_AORIGIN	1
#define AUTH_APROXY	2
#define AUTH_AGATEWAY	4

#define AUTH_XOK	0x01
#define AUTH_XCONN	0x02
#define AUTH_XMITM	0x04

#define i_Port	i_addr.a_port
#define i_Host	i_addr.a_name
/**/

typedef struct {
	double	ri_timeout;
	short	ri_server;
	short	ri_client;
	int	ri_rcvd;
	int	ri_sent;
} RidentEnv;
extern RidentEnv ridentEnv;
#define RIDENT_TIMEOUT	ridentEnv.ri_timeout
#define RIDENT_SERVER	ridentEnv.ri_server
#define RIDENT_CLIENT	ridentEnv.ri_client
#define RIDENT_RCVD	ridentEnv.ri_rcvd
#define RIDENT_SENT	ridentEnv.ri_sent

#endif
