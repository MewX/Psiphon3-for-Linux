/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1998-1999 Yutaka Sato
Copyright (c) 1998-1999 Electrotechnical Laboratry (ETL), AIST, MITI

Permission to use, copy, and distribute this material for any purpose
and without fee is hereby granted, provided that the above copyright
notice and this permission notice appear in all copies.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	ldap.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	981201	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <ctype.h>
#include "delegate.h"
#include "fpoll.h"
static int int1st;
#define LDAP_SNOOP	0

extern int IO_TIMEOUT;
static int timeoutms(){
	return IO_TIMEOUT * 1000;
}

#define CLASS_OF(type)	((type >> 6) & 3)
#define CLASS_UNV	0
#define CLASS_APP	1
#define CLASS_CTX	2
#define CLASS_PRI	3
static const char *classname[4] = {"UNV","APP","CTX","PRI"};
#define classof(type)	classname[CLASS_OF(type)]

#define TYPE_STRUCT	0x20
#define TYPE_INT	2
#define TYPE_CSTRING	4
#define TYPE_ENUM	10
#define TYPE_OF(type)	(type & 0x1F)

#define LDAP_BIND		0
#define LDAP_BIND_RESULT	1
#define LDAP_UNBIND		2
#define LDAP_SEARCH		3
#define LDAP_SEARCH_RESULT	4
#define LDAP_SEARCH_DONE	5

#define RESULT_OK	0
#define RESULT_UNAVAIL	52

#define ident(class,sort,type)	((class<<6)|(sort<<5)|type)

typedef unsigned char *Message;

#define FGETTYPE(in)	getc(in)
#define MGETTYPE(mp)	(*mp++)

static int scan_type(Message octets,int *typep)
{
	if( typep ) *typep = octets[0];
	return 1;
}
static int scan_leng(FILE *in,Message octets,int *lengp)
{	int bytes,bi,noct,leng,ch;

	bytes = 0;
	if( in != NULL ){
		ch = getc(in);
		octets[bytes++] = ch;
	}else	ch = octets[bytes++];

	if( ch & 0x80 ){
		noct = ch & 0x7F;
		leng = 0;
		for( bi = 0; bi < noct; bi++ ){
			if( in != NULL ){
				ch = getc(in);
				octets[bytes++] = ch;
			}else	ch = octets[bytes++];
			leng = (leng << 8) | ch;
		}
	}else{
		leng = ch & 0x7F;
	}
	if( lengp ) *lengp = leng;
	return bytes;
}
static int add_leng(Message octets,int disp,int inc)
{	int leng,bytes,bi;

	bytes = scan_leng(NULL,octets+disp,&leng);
	if( bytes <= 0 ){
		return -1;
	}
	leng += inc;
	if( bytes == 1 ){
		octets[disp] = leng;
		return 0;
	}else{
		bytes--;
		for( bi = 1; bi <= bytes; bi++ )
			octets[disp+bi] = leng >> 8*(bytes-bi);
		return 0;
	}
}
static int put_leng(Message octets,int leng)
{	int bytes,bi;

	if( leng < 128 ){
		*octets = leng;
		return 1;
	}
	bytes = 0;
	for( bi = 0; bi < 4; bi++ )
		if( leng & (0xFF << 8*bi) )
			bytes = bi + 1;

	for( bi = 0; bi < bytes; bi++ )
		octets[1+bi] = leng >> 8*(bytes-bi-1);

	octets[0] = 0x80 | bytes;
	return 1 + bytes;
}
static int scan_int(Message octets,int leng)
{	int lx,ival;

	ival = 0;
	for( lx = 0; lx < leng; lx++ )
		ival = (ival << 8) | octets[lx];
	return ival;
}

static int mssglen(Message mssg)
{	int off,type,leng;

	off = 0;
	off += scan_type(&mssg[off],&type);
	off += scan_leng(NULL,&mssg[off],&leng);
	return off + leng;
}

#define MAXMSGSZ 5*1024*1024
static Message read_mssg(FILE *in)
{	int type,leng;
	Message mssg;
	unsigned char tbuf[128];
	int len1,tlen,rcc;

	tlen = 0;

	if( fPollIn(in,timeoutms()) <= 0 ){
		sv1log("#### LDAP read_mssg timeout\n");
		return NULL;
	}

	type = getc(in);
	if( type == EOF ) return NULL;
	tbuf[tlen++] = type;

	tlen += len1 = scan_leng(in,&tbuf[tlen],&leng);
	if( len1 < 0 )
		return NULL;
	if( MAXMSGSZ < leng ){
		syslog_ERROR("ERROR: too large message (%d)\n",leng);
		return NULL;
	}

	mssg = (Message)malloc(tlen+leng);
	bcopy(tbuf,mssg,tlen);

	rcc = fread(mssg+tlen,1,leng,in); /**/
	if( rcc != leng ){
		free(mssg);
		syslog_ERROR("ERROR: premature EOF %x/%x\n",rcc,leng);
		return NULL;
	}
	return mssg;
}


#define EDIT_NOOP	0
#define EDIT_ERASE	1
#define EDIT_APPEND	2
#define EDIT_GETSEQ	0x10
#define EDIT_GETAPP	0x20

typedef struct {
	int	e_edit;
	int	e_type;
	short	e_eno[16];
} MssgEdit;
static MssgEdit mssgEdit[] = {
	{ EDIT_GETSEQ, ident(CLASS_UNV,0,TYPE_INT),     {1,1,0,0} },
	{ EDIT_GETAPP, ident(CLASS_APP,0,TYPE_INT),     {1,2,0,0} },
	{ EDIT_ERASE,  ident(CLASS_UNV,0,TYPE_CSTRING), {1,2,1,0} },
	{ EDIT_ERASE,  ident(CLASS_UNV,0,TYPE_CSTRING), {1,2,7,2} },
	{ EDIT_APPEND, ident(CLASS_UNV,0,TYPE_CSTRING), {1,2,1,0} },
	{ 0 },
};
typedef struct {
	short	m_eno[16];
	int	m_dump;
	int	m_edit;
	int	m_off;
	Message m_btm;
	Message	m_work;
	Message	m_push;
	int	m_modified;
	defQStr(m_arg);
	char	m_apptype;
	int	m_seq;
	MStr(	m_base,1024);
unsigned char	m_xmssg[0x10000];
} MssgNest;

static void dump_octets(Message data,int leng)
{	int ci,ch;
	CStr(line,1024);
	refQStr(lp,line); /**/

	line[0] = 0;
	for( ci = 0; ci < leng; ci++ ){
		if( ci % 8 == 0 ){
			if( ci != 0 )
				syslog_DEBUG("%s\n",line);
			lp = line;
			sprintf(lp,"%03x: ",ci);
			lp += strlen(lp);
		}
		ch = 0xfF & data[ci];
		sprintf(lp,"%02x %c|",ch,0x20<=ch&&ch<0x7F?ch:' ');
		lp += strlen(lp);
	}
	syslog_DEBUG("%s\n",line);
}
static void scan_cstring(Message data,int leng,Message buff,int max)
{	int off,ch;
	char *bp = (char*)buff; /**/

	*bp++ = '"';
	for( off = 0; off < leng && off < max; off++ ){
		ch = data[off];
		if( 0x20 <= ch && ch <= 0x7F )
			*bp++ = ch;
		else	*bp++ = '?';
	}
	*bp++ = '"';
	*bp = 0;
}
static void sprint_unit(int ptype,int type,int leng,Message data,PVStr(buff))
{	const char *xtypename = NULL;

	if( type & TYPE_STRUCT ){
	  switch( CLASS_OF(type) ){
	  case CLASS_APP:
	    switch( TYPE_OF(type) ){
		case LDAP_BIND: xtypename = "BIND"; break;
		case LDAP_BIND_RESULT: xtypename = "BIND-RESULT"; break;
		case LDAP_SEARCH: xtypename = "SEARCH"; break;
		case LDAP_SEARCH_RESULT: xtypename="SEARCH-RESULT"; break;
		case LDAP_SEARCH_DONE: xtypename = "SEARCH-DONE"; break;
	    }
	  break;

	  case CLASS_CTX:
	    if( ptype == ident(CLASS_APP,1,LDAP_SEARCH) )
	    switch( TYPE_OF(type) ){
		case 0: xtypename = "AND"; break;
		case 1: xtypename = "OR"; break;
		case 2: xtypename = "NOT"; break;
		case 3: xtypename = "EQ"; break;
	    }
	  break;
	  }
	  if( xtypename != NULL )
		sprintf(buff,"<%s>",xtypename);
	}else{
		if( CLASS_OF(type) == CLASS_CTX ){
			switch( TYPE_OF(type) ){
				case 7: xtypename = "PRESENT"; break;
			}
			if( xtypename != NULL ){
				sprintf(buff,"<%s>",xtypename);
				scan_cstring(data,leng,(unsigned char*)buff+strlen(buff),80);
			}
		}else
		if( CLASS_OF(type) == CLASS_APP
		 && TYPE_OF(type) == LDAP_UNBIND
		){
			sprintf(buff,"<UNBIND>");
		}else
		if( leng == 0 ){
			sprintf(buff,"(empty)");
		}else
		switch( type ){
		default:
			sprintf(buff,"0x%x",data[0]);
			break;
		case TYPE_INT:
			sprintf(buff,"%d",scan_int(data,leng));
			break;
		case TYPE_CSTRING:
			scan_cstring(data,leng,(unsigned char*)buff,160);
			break;
		}
	}
}
static int push1(MssgNest *Mp,int xtype,int xclen,Message xdata,int toff)
{	Message work;
	int nput;

	nput = 0;
	if( xtype & TYPE_STRUCT){
	}else{
		nput += xclen;
		Mp->m_push -= xclen;
		bcopy(xdata,Mp->m_push,xclen);
	}

	work = Mp->m_work;
	*work++ = xtype;
	work += put_leng(work,xclen);
	toff = work - Mp->m_work;

	nput += toff;
	Mp->m_push -= toff;
	bcopy(Mp->m_work,Mp->m_push,toff);
/*
sv1log("PUSH %03x [%d][%x,%x,%x] %s %x 0x%02x %3d [%d]\n",
Mp->m_btm - Mp->m_push,
toff,
Mp->m_work[0],
Mp->m_work[1],
Mp->m_work[2],
((xtype&TYPE_STRUCT)?"*":"-"),xdata,xtype,xclen,nput);
*/

	return nput;
}

static int scan_mssg1(MssgNest *Mp,int ptype,int lev,int nel,int off0,Message data);
static int scan_next(MssgNest *Mp,int lev,int *celp,int ptype,int pleng,Message data,int toff)
{	int len;
	int type,tlen,clen,ileng1,xleng1;
	Message mp;
	int ei,li,edit;
	MssgEdit *Ep;
	Message spush;
	Message wptr;
	Message xdata;
	int wleng;

	if( pleng == 0 )
		return 0;

	mp = data;
	mp += scan_type(mp,&type);
	mp += scan_leng(NULL,mp,&clen);
	tlen = mp - data;
	xdata = data + tlen;
	ileng1 = tlen + clen;

	edit = EDIT_NOOP;
	Mp->m_eno[lev] = *celp;
	Mp->m_eno[lev+1] = 0;

	if( Mp->m_edit != EDIT_NOOP ){
		for( ei = 0; edit = mssgEdit[ei].e_edit; ei++ ){ 
			if( edit != Mp->m_edit )
			if( edit != EDIT_GETSEQ )
			if( edit != EDIT_GETAPP )
				continue;
			Ep = &mssgEdit[ei];
			for( li = 0; li <= lev; li++ ){
				if( Mp->m_eno[li] != Ep->e_eno[li] )
					break;
			}
			if( Mp->m_eno[li] == 0 )
			if( Ep->e_eno[li] == 0 ){
				/* apply "edit" command to the current element */
				/* should check e_type */
				break;
			}
		}
	}

	spush = Mp->m_push;
	scan_mssg1(Mp,ptype,lev,*celp,toff,data);
	xleng1 = spush - Mp->m_push;

	wptr = 0;
	if( toff + ileng1 < pleng ){
		if( Mp->m_edit != EDIT_NOOP ){
			if( wleng = Mp->m_btm - Mp->m_push ){
				wptr = Mp->m_work;
				Mp->m_work += wleng;
				bcopy(Mp->m_push,wptr,wleng);
				Mp->m_push = Mp->m_btm;
			}
		}
		*celp += 1;
		scan_next(Mp,lev,celp,ptype,pleng,data+ileng1,toff+ileng1);
	}

	if( Mp->m_edit != EDIT_NOOP ){
		Message dp;
		int ylen;
		int tlen;

		tlen = 1024 < clen ? 1024:clen;
		bcopy(xdata,Mp->m_work,tlen);
		Mp->m_work[tlen] = 0;

		switch( edit ){
		  case EDIT_GETSEQ:
			if( TYPE_OF(type) == TYPE_INT ){
				Mp->m_seq = scan_int(mp,clen);
			}
			break;
		  case EDIT_GETAPP:
			Mp->m_apptype = type;
			syslog_DEBUG("#### apptype=%X [%s %d]\n",type,
				classof(type),TYPE_OF(type));
			break;
		  case EDIT_ERASE:
			if( TYPE_OF(type) != TYPE_CSTRING )
				break;
			wordscanX((char*)Mp->m_work,AVStr(Mp->m_base),sizeof(Mp->m_base));
			if( dp = (Message)strrchr((char*)Mp->m_work,'@') ){
				ylen = strlen((char*)dp);
				strcpy(Mp->m_arg,(char*)dp);
				setVStrEnd(Mp->m_arg,ylen);
/*
sv1log("******* ERASE: %d -> %d [%s]\n",clen,clen-ylen,Mp->m_arg);
*/
				clen -= ylen;
				Mp->m_modified++;
			}
			break;
		  case EDIT_APPEND:
			ylen = strlen(Mp->m_arg);
			bcopy(xdata,Mp->m_work,clen);
			bcopy(Mp->m_arg,&Mp->m_work[clen],ylen);
			xdata = Mp->m_work;
			Mp->m_work += clen + ylen;
/*
sv1log("******* APPEND: %d -> %d [%s]\n",clen,clen+ylen,Mp->m_arg);
*/
			clen += ylen;
			Mp->m_modified++;
			break;
		}
		if( type & TYPE_STRUCT )
			clen = xleng1;

		if( wptr ){
			Mp->m_push -= wleng;
			bcopy(wptr,Mp->m_push,wleng);
		}
		push1(Mp,type,clen,xdata,toff);

		if( lev == 1 && toff == 0 && (ptype & TYPE_STRUCT) ){
			int total;
			total = Mp->m_btm - Mp->m_push;
			push1(Mp,ptype,total,data,0);
		}
	}
	return 0;
}


static int scan_mssg1(MssgNest *Mp,int ptype,int lev,int nel,int off0,Message data)
{	int li;
	int tlen,len1,type,leng,stype,sleng;
	int off,cel;
	int ch;
	Message push,work,temp;

	tlen = 0;
	tlen += len1 = scan_type(data,&type); data += len1;
	tlen += len1 = scan_leng(NULL,data,&leng); data += len1;
	Mp->m_eno[lev] = nel;

	if( type == TYPE_INT && int1st < 0 ){
		int1st = scan_int(data,leng);
	}

	if( Mp->m_dump ){
		CStr(line,1024);
		refQStr(lp,line); /**/
		if( lev == 0 ){
			syslog_ERROR("-- leng=%x(%d) type=%x --\n",
				tlen+leng,tlen+leng,type);
			dump_octets(data-tlen,tlen+leng);
		}
		sprintf(lp,"%03x %2d %2d %03x ", Mp->m_off,lev,nel,off0);
		lp += strlen(lp);

		for( li = 0; li <= lev; li++ ){
			sprintf(lp,"%d.",Mp->m_eno[li]);
			lp += strlen(lp);
		}
		setVStrPtrInc(lp,' ');

		sprintf(lp,"[%s %2d](%2d) ",classof(type),type&0x1F,leng);
		lp += strlen(lp);
		setVStrEnd(lp,0);

		sprint_unit(ptype,type,leng,data,QVStr(lp,line));
		syslog_ERROR("%s\n",line);
	}

	Mp->m_off += tlen;
	if( type & TYPE_STRUCT ){
		cel = 1;
		scan_next(Mp,lev+1,&cel,type,leng,data,0);
	}

	Mp->m_off += leng;
	return tlen + leng;
}
static int scan_mssgX(Message mssg,int dump,int edit,PVStr(arg),MssgNest *Mp)
{
	int leng;
	int bsiz;
	const unsigned char *buff;

	Mp->m_off = 0;
	Mp->m_dump = dump;
	Mp->m_edit = edit;

	/*
	 * one for working input, one for temporary for editing,
	 * and one for output
	 */
	bsiz = mssglen(mssg)*3 + 1024;
	buff = 0;
	if( edit != EDIT_NOOP && sizeof(Mp->m_xmssg) < bsiz ){
		syslog_ERROR("scan_mssg: editing large data: %d / %d\n",
			mssglen(mssg),bsiz);
		Mp->m_work = (unsigned char*)(buff = (const unsigned char*)malloc(bsiz));
		Mp->m_btm  = Mp->m_work + bsiz;
	}else{
	Mp->m_work = Mp->m_xmssg;
	Mp->m_btm  = Mp->m_xmssg + sizeof(Mp->m_xmssg);
	}

	Mp->m_push = Mp->m_btm;
	Mp->m_seq = 0;
	Mp->m_apptype = 0;
	setQStr(Mp->m_arg,arg,(UTail(arg)-arg)+1);
	Mp->m_modified = 0;
	Mp->m_base[0] = 0;
	leng = scan_mssg1(Mp,0,0,1,0,mssg);

	if( Mp->m_modified )
		bcopy(Mp->m_push,mssg,mssglen(Mp->m_push));


	if( buff ){
		free((char*)buff);
	}
	return leng;
}
static int scan_mssg(Message mssg,int dump,int edit,PVStr(arg))
{	MssgNest Ma,*Mp = &Ma;

	return scan_mssgX(mssg,dump,edit,AVStr(arg),Mp);
}

static Message make_LDAPResult2(int msgid,int type)
{	unsigned char resp[1024]; /**/
	Message mresp;
	int ri;

	ri = 0;
	resp[ri++] = ident(CLASS_UNV,1,16);
	resp[ri++] = 9;
	resp[ri++] = ident(CLASS_UNV,0,TYPE_INT);
	resp[ri++] = 1;
	resp[ri++] = msgid;
	resp[ri++] = ident(CLASS_APP,1,type);
	resp[ri++] = 4;
	resp[ri++] = ident(CLASS_UNV,0,TYPE_CSTRING);
	resp[ri++] = 0;
	resp[ri++] = ident(CLASS_UNV,1,16);
	resp[ri++] = 0;

	mresp = (Message)malloc(ri);
	bcopy(resp,mresp,ri);
	return mresp;
}

static Message make_LDAPResult(int msgid,int type,int code,PCStr(comment))
{	unsigned char resp[1024]; /**/
	Message mresp,tail;
	int ri,comlen,comlenlen;
	unsigned char comlenbuf[8];

	comlen = strlen(comment);
/*
	comlenlen = put_leng(&comlenbuf[sizeof(comlenbuf)],comlen);
*/

	ri = 0;
	resp[ri++] = ident(CLASS_UNV,1,16);
	resp[ri++] = 14+comlen; 
	resp[ri++] = ident(CLASS_UNV,0,TYPE_INT);
	resp[ri++] = 3;
	resp[ri++] = msgid >> 16;
	resp[ri++] = msgid >> 8;
	resp[ri++] = msgid;
	resp[ri++] = ident(CLASS_APP,1,type);
	resp[ri++] = 7+comlen;
	resp[ri++] = ident(CLASS_UNV,0,TYPE_ENUM);
	resp[ri++] = 1;
	resp[ri++] = code;
	resp[ri++] = ident(CLASS_UNV,0,TYPE_CSTRING);
	resp[ri++] = 0;
	resp[ri++] = ident(CLASS_UNV,0,TYPE_CSTRING);
	resp[ri++] = comlen;
	bcopy(comment,&resp[ri],comlen);
	ri += comlen;

/*
ri = 0;
tail = &resp[sizeof(reesp)-1];
ri += comlen;
bcopy(comment,tail[-ri],comlen);
ri++; tail[-ri] = comlen;
...
*/

	mresp = (Message)malloc(ri);
	bcopy(resp,mresp,ri);
	return mresp;
}
static void putEmptyResult(Connection *Conn,int msgid)
{	Message resp;
	int mlen;

	resp = make_LDAPResult2(msgid,LDAP_SEARCH_RESULT);
	mlen = mssglen(resp);
	scan_mssg(resp,1,EDIT_NOOP,VStrNULL);
	IGNRETP write(ToC,resp,mlen);

	resp = make_LDAPResult(msgid, LDAP_SEARCH_DONE,RESULT_OK,"");
	mlen = mssglen(resp);
	scan_mssg(resp,1,EDIT_NOOP,VStrNULL);
	IGNRETP write(ToC,resp,mlen);
}

/*
 * MOUNT should be achieved in scan_mssg() to generate baseObject
 */
/*
static void mount(Connection *Conn,MssgNest *Mp,PVStr(srchroot))
*/
static void mount(Connection *Conn,MssgNest *Mp,PVStr(srchroot),PVStr(proto))
{	const char *opts;
	CStr(server,1024);
	const char *dp;

	if( strchr(srchroot,'@') )
		return;

	wordscanX(Mp->m_base,AVStr(server),sizeof(server));
	if( opts = CTX_mount_url_to(Conn,NULL,"GET",AVStr(server)) ){
		sv1log("MOUNTed to %s <= %s\n",server,Mp->m_base);
		if( strneq(server,"ldaps://",8) ){
			strcpy(proto,"ldaps");
			strsubst(AVStr(server),"ldaps","ldap");
		}
		if( strneq(server,"ldap://",7) ){
			setVStrElem(srchroot,0,'@');
			dp = wordscanY(server+7,QVStr(srchroot+1,srchroot),256,"^/");
			if( *dp == '/' ){
				linescanX(dp+1,AVStr(Mp->m_base),sizeof(Mp->m_base));
				/* baseObject in the message should be
				 * replaced with this
				 */
			}
		}
	}
}

/* REMOVE "@real-server-name" in baseObject's LDAPDN in SEARCH requests
 * APPEND "@real-server-name" to baseObject's LDAPDN in SEARCH responses
 * This rewriting should be controled with MOUNT parameter.
 */
static void proxy_ldap(Connection *Conn)
{	FILE *fc,*tc,*fs,*ts;
	int nmsg[2];
	Message bindmssg,srchmssg,mssg,nmssg,resp;
	CStr(srchroot,512);
	CStr(ldapserv,512);
	CStr(proto,128);
	CStr(host,512);
	int mlen;
	int port;
	MssgEdit Me,*Ep = &Me;
	MssgNest Ma,*Mp = &Ma;
	int type;

	fc = fdopen(FromC,"r");
	nmsg[0] = nmsg[1] = 0;

	if( !isMYSELF(DFLT_HOST) ){
		fs = fdopen(FromS,"r");
		srchroot[0] = 0;
		goto RELAY;
	}

	nmsg[0]++;
	bindmssg = read_mssg(fc);
	if( bindmssg == NULL )
		return;
	int1st = -1;

	srchroot[0] = 0;
	scan_mssgX(bindmssg,1,EDIT_ERASE,AVStr(srchroot),Mp);

	if( TYPE_OF(Mp->m_apptype) == LDAP_SEARCH )
	if( srchroot[0] == 0 )
	{
		syslog_ERROR("#### SearchReuest for RootDSE\n");
		putEmptyResult(Conn,Mp->m_seq);

		nmsg[0]++;
		bindmssg = read_mssg(fc);
		if( bindmssg == NULL ){
			return;
		}
		srchroot[0] = 0;
		scan_mssgX(bindmssg,1,EDIT_ERASE,AVStr(srchroot),Mp);
	}

	resp = make_LDAPResult(int1st,
		LDAP_BIND_RESULT,RESULT_OK,
		"Bound by proxy (DeleGate)");

	mlen = mssglen(resp);
	syslog_ERROR("#### proxy BIND response (%d)\n",mlen);
	scan_mssg(resp,1,EDIT_NOOP,VStrNULL);
	IGNRETP write(ToC,resp,mlen);

	nmsg[0]++;
	srchmssg = read_mssg(fc);
	if( srchmssg == NULL ){
		syslog_ERROR("#### disconnected by client\n");
		return;
	}
	srchroot[0] = 0;
	scan_mssgX(srchmssg,1,EDIT_ERASE,AVStr(srchroot),Mp);

	if( TYPE_OF(Mp->m_apptype) == LDAP_SEARCH )
	if( srchroot[0] == 0 )
	if( Mp->m_base[0] == 0 )
	{
		syslog_ERROR("#### SearchReuest for RootDSE\n");
		putEmptyResult(Conn,Mp->m_seq);

		nmsg[0]++;
		srchmssg = read_mssg(fc);
		if( srchmssg == NULL ){
			return;
		}
		srchroot[0] = 0;
		scan_mssgX(srchmssg,1,EDIT_ERASE,AVStr(srchroot),Mp);
	}

	type = Mp->m_apptype;
	if( TYPE_OF(type) == LDAP_UNBIND ){
		syslog_ERROR("#### not a SEARCH message: %X = %s %d\n",
			type,classof(type),TYPE_OF(type));
		return;
	}

	strcpy(proto,"ldap");
	mount(Conn,Mp,AVStr(srchroot),AVStr(proto));
	/*
	mount(Conn,Mp,AVStr(srchroot));
	*/

	if( srchroot[0] == '@' )
		strcpy(ldapserv,srchroot+1);
	else	ldapserv[0] = 0;

	/*
	port = scan_hostport("ldap",ldapserv,AVStr(host));
	*/
	port = scan_hostport(proto,ldapserv,AVStr(host));
	syslog_ERROR("LDAP-SERVER=[%s]=[%s:%d]\n",srchroot,host,port);
	set_realserver(Conn,proto,host,port);
	/*
	set_realserver(Conn,"ldap",host,port);
	*/
	if( connect_to_serv(Conn,FromC,ToC,0) < 0 ){
		syslog_ERROR("#### proxy connection error response\n");
		resp = make_LDAPResult(Mp->m_seq,
			LDAP_SEARCH_DONE,RESULT_UNAVAIL,
			"Can't connect to LDAP server by proxy (DeleGate)");
		goto xERROR;
	}

	fs = fdopen(FromS,"r");

	mlen = mssglen(bindmssg);
	syslog_ERROR("#### relay client's BIND (%d)\n",mlen);
	scan_mssg(bindmssg,1,EDIT_NOOP,VStrNULL);
	IGNRETP write(ToS,bindmssg,mlen);

	syslog_ERROR("#### wait BIND response from the server\n");
	nmsg[1]++;
	resp = read_mssg(fs);
	if( resp == NULL ){
		syslog_ERROR("#### EOF from server\n");
		resp = make_LDAPResult(Mp->m_seq,
			LDAP_SEARCH_DONE,RESULT_UNAVAIL,
			"EOF from LDAP server to proxy (DeleGate)");
		goto xERROR;
	}
	scan_mssg(resp,1,EDIT_NOOP,VStrNULL);

	mlen = mssglen(srchmssg);
	syslog_ERROR("#### forward search request (%d)\n",mlen);
	scan_mssg(srchmssg,1,EDIT_NOOP,VStrNULL);
	IGNRETP write(ToS,srchmssg,mlen);

 RELAY:{
	FILE *fpv[2],*ifp;
	int rds[2],tov[2],fi;

	syslog_ERROR("#### start bidirectional relay\n");
	fpv[0] = fc; tov[0] = ToS;
	fpv[1] = fs; tov[1] = ToC;
	/*
	while( !feof(fc) && !feof(fs) && 0 < fPollIns(0,2,fpv,rds) )
	*/
	while( !feof(fc) && !feof(fs) && 0 < fPollIns(timeoutms(),2,fpv,rds) )
	for( fi = 0; fi < 2; fi++ )
	if( rds[fi] ){
		int type,bytes;

		nmsg[fi]++;
		ifp = fpv[fi];
		mssg = read_mssg(ifp);
		if( mssg == NULL ){
			syslog_ERROR("#### %s EOF\n",fi==0?"C-S":"S-C");
			break;
		}

		mlen = mssglen(mssg);
		bytes = scan_leng(NULL,mssg+1,NULL);
		type = mssg[1+bytes+3];
		syslog_ERROR("#### %s[%d] (%d) %x\n",fi==0?"C-S":"S-C",nmsg[fi],mlen,type);

		if( LDAP_SNOOP )
			scan_mssg(mssg,1,EDIT_NOOP,VStrNULL);

		if( fi == 0 ){
			if( type == ident(CLASS_APP,1,LDAP_SEARCH ) ){
				scan_mssg(mssg,0,EDIT_ERASE,AVStr(srchroot));
				mlen = mssglen(mssg);
			}
		}else{
			if( type == ident(CLASS_APP,1,LDAP_SEARCH_RESULT) ){
				/* srchroot is inserted into msssg and ASN1 tag
				 * may be expanded to represend longer length
				 * (+2 seems enough)
				 */
				nmssg = (Message)malloc(mssglen(mssg)+strlen(srchroot)+32);
				bcopy(mssg,nmssg,mssglen(mssg));
				free(mssg);
				mssg = nmssg;
				scan_mssg(mssg,0,EDIT_APPEND,AVStr(srchroot));
				mlen = mssglen(mssg);
			}
		}
		IGNRETP write(tov[fi],mssg,mlen);
	}
 }
	return;

xERROR:
	mlen = mssglen(resp);
	scan_mssg(resp,1,EDIT_NOOP,VStrNULL);
	IGNRETP write(ToC,resp,mlen);
}

int service_tcprelay(Connection *Conn);
int service_ldap(Connection *Conn)
{
	if( isMYSELF(DFLT_HOST) )
                proxy_ldap(Conn);
	else
	if( LDAP_SNOOP ){
                proxy_ldap(Conn);
	}
	else	service_tcprelay(Conn);
	return 0;
}
