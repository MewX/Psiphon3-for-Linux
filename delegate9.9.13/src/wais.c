/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1995-1999 Yutaka Sato
Copyright (c) 1995-1999 Electrotechnical Laboratry (ETL), AIST, MITI

Permission to use, copy, and distribute this material for any purpose
and without fee is hereby granted, provided that the above copyright
notice and this permission notice appear in all copies.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	wais.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950310	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "delegate.h"
#include <fcntl.h>
int codeconv_bufsize(int ccode,int size);

#define STRLEN(a)	strlen((char*)a)
#define STRCHR(a,b)	strchr((char*)a,b)
#define STRCAT(a,b)	Xstrcat(QVStr((char*)a,a),(char*)b)
#define STRCPY(a,b)	Xstrcpy(QVStr((char*)a,a),(char*)b)
#define STRNCPY(a,b,n)	Xstrncpy(QVStr((char*)a,a),(char*)b,n)

#define MAX_REC_DOC	100

/*
 *	PDU types
 */
#define P_InitAPDU		20
#define P_InitRespAPDU		21
#define P_SearchAPDU		22
#define P_SearchRespAPDU	23

typedef struct {
	int	t_tag;
	int	t_type;
  const	char   *t_name;
} Tags;

/*
 *	data types
 */
#define _BM	1
#define _IN	2
#define _TX	3
#define _Tx	4
#define _ST	5
#define _DI	6
#define _CC	7
#define _UN	8

#define PD_DatabaseNames	18
#define PD_AttributeList	44
#define PD_Term			45
#define PD_Operator		46
#define PD_DocumentHeaderGroup	150
#define PD_DocumentTextGroup	153
#define PD_DocumentText		127
#define PD_Date			122
#define PD_Headline		123

static Tags TagTab[] = {
	{   1,	_IN,	"PDU-Type"},
	{   2,	_IN,	"Reference-ID"},
	{   3,	_IN,	"Protocol-Version"},
	{   4,	_BM,	"Options"},
	{   5,	_IN,	"Prefered-Message-Size"},
	{   6,	_IN,	"Maximum-Record-Size"},
	{   7,	_TX,	"ID-Authentication"},
	{   8,	_TX,	"Implementation-ID"},
	{   9,	_TX,	"Implementation-Name"},
	{  10,	_TX,	"Implementation-Version"},
	{  17,	_TX,	"Result-Set-Name"},
	{  18,	_TX,	"Database-Names"},
	{  19,	_TX,	"Element-Set-Names"},
	{  20,	_TX,	"Query-Type"},
	{  27,	_IN,	"Present-Status"},
	{  28,	_TX,	"Database-Diagnostic-Records"},
	{  36,	_TX,	"Delete-MSG"},

	{  44,  _TX,	"Attribute-List"},
	{  45,  _DI,	"Term"},
	{  46,  _TX,	"Operator"},

	{  99,	_ST,	"User-Information-Length"},
	{ 100,	_CC,	"Chunk-Code"},
	{ 101,	_IN,	"Chunk-ID-Length"},
	{ 102,	_TX,	"Chunk-Marker"},
	{ 106,	_TX,	"Seed-Words"},
	{ 107,	_TX,	"Document-ID-Chunk"},
	{ 111,	_IN,	"Data-Factor"},
	{ 114,	_IN,	"Max-Documents-Retrieved"},
	{ 116,	_DI,	"Document-ID"},
	{ 117,	_IN,	"Version-Number"},
	{ 118,	_IN,	"Score"},
	{ 119,	_IN,	"Best-Match"},
	{ 120,	_IN,	"Document-Length"},
	{ 121,	_TX,	"Source"},
	{ 122,	_TX,	"Date"},
	{ 123,	_TX,	"Headline"},
	{ 127,	_Tx,	"Document-Text"},

	{ 131,	_IN,	"Lines"},
	{ 132,	_ST,	"Type-Block"},
	{ 133,	_TX,	"Type"},

	{ 150,	_ST,	"Document-Header-Group"},
	{ 151,	_ST,	"Document-Short-Header-Group"},
	{ 152,	_ST,	"Document-Long-Header-Group"},
	{ 153,	_ST,	"Document-Text-Group"},
	{ 154,	_ST,	"Document-Headline-Group"},
	{ 155,	_ST,	"Document-Code-Group"},
	0
};

#define scan_int(buf,idx,val) {\
	val = 0; \
	while( buf[idx] & 0x80 ) \
		val = (val << 7) | (buf[idx++] & 0x7F); \
	val = (val << 7) | buf[idx++]; \
}
static int relay_taglen(FILE *src,FILE *dst,int *rem)
{	int val,ch;

	val = 0;
	while( (ch = getc(src)) != EOF ){
		putc(ch,dst);
		*rem -= 1;
		val = (val << 7) | (ch & 0x7F);
		if( (ch & 0x80) == 0 )
			break;
	}
	return val;
}

static int scan_decF(unsigned char *buf,int len)
{	int iv,ix;
	iv = 0;
	for( ix = 0; ix < len; ix++ )
		iv = (iv << 8) | buf[ix];
	return iv;
}
static char *dstrncpy(xPVStr(dst),PCStr(src),int len)
{	int l1;
	unsigned char ch;

	for( l1 = 0; l1 < len; l1++ ){
		assertVStr(dst,dst+1);
		ch = *src++;
		if( ch<=0x20||0x7F<=ch || ch=='%'||ch==';'||ch=='"' ){
			sprintf(dst,"%%%02x",ch & 0xFF);
			dst += 3;
		}else	setVStrPtrInc(dst,ch);
	}
	setVStrEnd(dst,0);
	return (char*)dst;
}
static void encode_did(PVStr(pbuf),unsigned char *buf,int len)
{	int idx;
	refQStr(pp,pbuf); /**/
	int l1,tag;

	for( idx = 0; idx < len; ){
		assertVStr(pbuf,pp+1);
		if( buf[idx] < 0x20 ){
			tag = buf[idx++];
			sprintf(pp,"%d=",tag);
			pp += STRLEN(pp);
			scan_int(buf,idx,l1);
			pp = dstrncpy(AVStr(pp),(char*)&buf[idx],l1);
			idx += l1;
			setVStrPtrInc(pp,';');
		}else	setVStrPtrInc(pp,buf[idx++]);
	}
	setVStrEnd(pp,0);
}

static int decode_did(unsigned char *edid,unsigned char *ddid)
{	int tag,l1;
	unsigned char ch;
	const unsigned char *ep;
	const unsigned char *fp;
	unsigned char *dp;
	unsigned char *tp;
	const unsigned char *np;
	unsigned CStr(ebuf,0x4000);
	CStr(elem,0x1000);

	STRCPY(ebuf,edid);
	dp = ddid;
	for( ep = ebuf; *ep; ep = np ){
		if( np = (unsigned char*)STRCHR(ep,';') ){
			truncVStr(np); np++;
		}
		if( Xsscanf((char*)ep,"%d=%s",&tag,AVStr(elem)) != 2 )
			break;

		dp[0] = tag;
		dp[1] = 0;
		tp = &dp[2]; 
		for( fp = (unsigned char*)elem; ch = *fp++; ){
			if( ch == '%' ){
				CStr(xb,3);
				int xv;;
				xb[0] = *fp++;
				xb[1] = *fp++;
				xb[2] = 0;
				sscanf(xb,"%x",&xv);
				*tp++ = xv;
			}else	*tp++ = ch;
		}
		l1 = tp - &dp[2];
		dp[1] = l1;
		dp = tp;
		if( np == 0 )
			break;
	}
	return dp - ddid;
}
	
static int print_data(xPVStr(pbuf),int tag,int len,unsigned char *buf)
{	int ti,iv,ttype;
	const char *tname;
	Tags *ttab;

	ttype = 0;
	ttab = TagTab;
	for( ti = 0; tname = ttab[ti].t_name; ti++ )
		if( ttab[ti].t_tag == tag ){
			ttype = ttab[ti].t_type;
			break;
		}

	if( tname == 0 ){
		sprintf(pbuf,"????: [%d %d]",buf[0],buf[1]);
	}else{
		sprintf(pbuf,"%s: ",tname);
		pbuf += STRLEN(pbuf);
		switch( ttype ){
		    case _DI:
			encode_did(AVStr(pbuf),buf,len);
			break;
		    case _ST:
			break;
		    case _TX:

if( tag == PD_DatabaseNames ){
	CStr(tb,1024);
	STRNCPY(tb,buf,len);
	setVStrEnd(tb,len);
	sv1log("Database-Names: %s\n",tb);
}else
if( tag == PD_Headline ){
	STRNCPY(pbuf,buf,len);
	setVStrEnd(pbuf,len);
}else
			dstrncpy(AVStr(pbuf),(char*)buf,len);
			break;
		    case _BM:
			iv = scan_decF(buf,len);
			sprintf(pbuf,"0x%x",iv);
			break;
		    case _IN:
			iv = scan_decF(buf,len);
			sprintf(pbuf,"%d",iv);
			break;
		    case _UN:
			sprintf(pbuf,"[%x %x]",buf[0],buf[1]);
			break;
		    case _CC:
			switch( buf[0] ){
				case 0: STRCPY(pbuf,"Document"); break;
				case 1: STRCPY(pbuf,"Byte"); break;
				case 2: STRCPY(pbuf,"Line"); break;
				case 3: STRCPY(pbuf,"Paragraph"); break;
			}
			break;
		}
	}
	return ttype;
}

static void dump_record(unsigned char *buf,int buflen,PVStr(out))
{	int tag,len,idx,idx0;
	CStr(pbuf,1024);
	int ttype;

	idx = 0;
	while( idx < buflen ){
		idx0 = idx;
		scan_int(buf,idx,tag);
		scan_int(buf,idx,len);
		ttype = print_data(AVStr(pbuf),tag,len,&buf[idx]);
		Verbose("%5d [tag=%3d;len=%3d]%d %s\n",
			idx0,tag,len,ttype,pbuf);

		if( ttype == _ST )
			dump_record(&buf[idx],len,AVStr(out));
		else
		if( out != NULL ){
			STRCAT(out,pbuf);
			STRCAT(out,"\n");
		}
		idx += len;
	}
}

static const char *curDB = 0;
static int byDID = 0;

static void dhg2html(PVStr(dst),PCStr(dhg))
{	int score = 0;
	int lines = 0;
	int bytes = 0;
	const char *date = "";
	CStr(dateb,256);
	const char *type = "TEXT";
	CStr(typeb,256);
	const char *did = "-";
	CStr(didb,0x10000);
	const char *subj = "";
	CStr(subjb,0x1000);
	CStr(subjbe,0x1000);
	const char *hfp;

	if( hfp = findFieldValue(dhg,"Score") ) score = atoi(hfp);
	if( hfp = findFieldValue(dhg,"Lines") ) lines = atoi(hfp);
	if( hfp = findFieldValue(dhg,"Document-Length") ) bytes = atoi(hfp);
	if( hfp = findFieldValue(dhg,"Date")  )
		{ wordScan(hfp,dateb); date = dateb; }
	if( hfp = findFieldValue(dhg,"Type")  )
		{ wordScan(hfp,typeb); type = typeb; }
	if( hfp = findFieldValue(dhg,"Document-ID") )
		{ wordScan(hfp,didb); did = didb; }
	if( hfp = findFieldValue(dhg,"Headline") ){
		lineScan(hfp,subjb);
		if( subjb[0] ){
			encodeEntitiesX(subjb,AVStr(subjbe),sizeof(subjbe));
			subj = subjbe;
		}
	}
	sprintf(dst,
		"%5d %8s %5d <A HREF=\"/%s/%s/%d/%s\"><B>%s</B></A>\n",
		score,date,lines,
		curDB?curDB:"DB-DB-DB-DB",
		type,bytes,did,subj);
}

static void relay_userinfo(Connection *Conn,int up,FILE *src,FILE *dst,PVStr(out),int recleng,int trace)
{
	defQStr(buf); /*alloc*/
	int rem0,rem,tag,len,rcc;
	int cconv;
	const char *what;

	what = up ? "C>S" : "S>C";
	rem = recleng;

	cconv = CTX_check_codeconv(Conn,0);
	if( codeconv_bufsize(cconv,10) > 10 )
		cconv = 0;

	while( 0 < rem ){
		rem0 = rem;
		tag = relay_taglen(src,dst,&rem);
		len = relay_taglen(src,dst,&rem);

		if( len == 0 ){
			Verbose(">>> [%d,%d] rem=%d\n",tag,len,rem);
			if(  tag == 28 )
				len = rem;
			else	continue;
		}
 if( tag == PD_DocumentTextGroup ){
	Verbose("Document-Text-Group: %d\n",len);
	continue;
 }

		if( rem < len ){
			ERRMSG("**** ERROR **** tag:%d len:%d > rem:%d\n",
				tag,len,rem);
			len = rem;
		}
		setQStr(buf,(char*)malloc(len+1),len+1);

		rcc = fread((char*)buf,1,len,src);
		setVStrEnd(buf,rcc);

 {
 int ttype;
 CStr(pbuf,2048);
 ttype = print_data(AVStr(pbuf),tag,len,(unsigned char*)buf);
 Verbose("%5d[TAG=%3d;LEN=%3d]%d %s\n",recleng-rem0,tag,len,ttype,pbuf);
 }
		if( tag == 106 ){
			CStr(ebuf,1024);

TO_EUC((const char*)buf,AVStr(ebuf),"text/plain");

			sv1log("%s: SeedWords=[%s]%d [%s]%d\n",what,
				buf,istrlen(buf),ebuf,istrlen(ebuf));
			strncpy(buf,ebuf,len);
		}else
		if( tag == PD_DocumentHeaderGroup ){
			if( out ){
				CStr(tmp,4096);
				tmp[0] = 0;
				dump_record((unsigned char*)buf,len,AVStr(tmp));
				dhg2html(TVStr(out),tmp);
			}else	dump_record((unsigned char*)buf,len,VStrNULL);
		}else
		if( tag == PD_DocumentText ){
			if( cconv ){
				CTX_check_codeconv(Conn,1);
				sv1log("%s: %d bytes\n",what,len);
				CTX_line_codeconv(Conn,buf,AVStr(buf),"text/plain");
			}
			if( byDID )
			strcat(out,buf);
		}
else
if( tag == PD_Date )
	Verbose("Date: [%d] %s\n",len,buf);

		fwrite(buf,rcc,1,dst);
		free((char*)buf);
		rem -= rcc;
	}
	Verbose("DONE\n");
}

#define int3(b,i)	( ((b[i])<<16) | ((b[i+1])<<8) | (b[i+2]) )
void dump_searchPDU(int ptype,unsigned char *buf)
{
Verbose("Type: %d (Search); Upper=%d; Lower=%d; Present=%d Replace=%d\n",
	ptype, int3(buf,1), int3(buf,4), int3(buf,7), buf[10]);
}

static int relay_record(Connection *Conn,int up,FILE *fs,FILE *tc,xPVStr(head),PVStr(body))
{	int ptype,tag,len;
	int rcc,wcc,rem;
	int bsize,hsize;
	unsigned CStr(buf,0x10000);
	const char *what;

	what = up ? "C>S" : "S>C";
	Verbose("%s:\n",what);

	rcc = fread(buf,1,25,fs);
	Verbose("%d read\n",rcc);
	if( rcc <= 0 )
		return 0;

	buf[25] = 0;
	bsize = atoi((char*)buf);
	fwrite(buf,25,1,tc);
	Verbose("%s: %d [%s]\n",what,bsize,buf);

	if( bsize == 0 ){
		fflush(tc);
		return 0;
	}

	rem = bsize;
	IGNRETP fread(buf,1,2,fs);
	fwrite(buf,2,1,tc);
	rem -= 2;
	hsize = (buf[0] << 8) | buf[1];

	IGNRETP fread(buf,1,hsize,fs);
	fwrite(buf,hsize,1,tc);
	rem -= hsize;
	ptype = buf[0];
	Verbose("HeaderLength: %d / %d, rem=%d\n",hsize,bsize-2,rem);

	if( ptype == P_InitAPDU ){
		Verbose("Type: %d (Init);\n",ptype);
		dump_record(&buf[1],hsize-1,VStrNULL);
	}
	if( ptype == P_InitRespAPDU ){
		Verbose("Type: %d (InitResp); Result=%d;\n",buf[1],ptype);
		dump_record(&buf[2],hsize-2,VStrNULL);
	}
	if( ptype == P_SearchAPDU ){
		dump_searchPDU(ptype,buf);
		dump_record(&buf[11],hsize-11,VStrNULL);
	}
	if( ptype == P_SearchRespAPDU ){
Verbose("Type: %d (SearchResp); Status=%d; Result=%d; Returned=%d; Next=%d\n",
			ptype, buf[1], int3(buf,2), int3(buf,5), int3(buf,8));
		if( head ){
			sprintf(head,"Search-Returned: %d\n",int3(buf,5));
			head += strlen(head);
		}
		dump_record(&buf[11],hsize-11,VStrNULL);
	}

	if( 0 < rem ){
		tag = relay_taglen(fs,tc,&rem);
		len = relay_taglen(fs,tc,&rem);
		Verbose("User-Information: [%d/%x %d] rem=%d\n",tag,tag,len,rem);
		relay_userinfo(Conn,up,fs,tc,AVStr(body),rem,ptype!=P_SearchRespAPDU);
	}
	fflush(tc);
	return bsize;
}

static void proxyWAIS(Connection *Conn)
{
	Verbose("proxy-WAIS\n");
}

int service_wais(Connection *Conn)
{	int cc,sctotal,cstotal;
	FILE *ts,*fs,*tc,*fc;

	if( isMYSELF(DFLT_HOST) ){
		proxyWAIS(Conn);
		return -1;
	}

	ts = fdopen(ToS,"w");
	fs = fdopen(FromS,"r");
	tc = fdopen(ToC,"w");
	fc = fdopen(FromC,"r");

	if( ts == NULL || tc == NULL ){
		Verbose("Open failed: %x %x\n",p2i(ts),p2i(tc));
		return 0;
	}

	sctotal = 0;
	Verbose("WAIS START\n");
	while( cc = relay_record(Conn,1,fc,ts,VStrNULL,VStrNULL) ){
		if( (cc = relay_record(Conn,0,fs,tc,VStrNULL,VStrNULL)) == 0 )
			break;
		sctotal += cc;
	}
	Verbose("WAIS DONE: %d\n",sctotal);

	fclose(ts);
	fclose(fs);
	fclose(tc);
	fclose(fc);
	return sctotal;
}

void WAIS_serverOpen(Connection *Conn,PCStr(name),int port)
{	int svsock;

	svsock = connect_to_serv(Conn,FromC,ToC,0);
}

#define addQbuf(v) setVStrElemInc(qpdu,len,v)
static void wais_search(Connection *Conn,int sv,PVStr(head),PVStr(out),PCStr(dbname),PCStr(words),PCStr(did),PCStr(type),int leng)
{
FILE *ts,*fs,*null;
	JStr(qpdu,2048);
	int len,ulen,blen;
int tfd;
int vtop;
static int serno = 50;

ts = fdopen(sv,"w");
fs = fdopen(sv,"r");
/*
null = fopen("/dev/null","w");
*/
tfd = open("/dev/null",1); null = fdopen(tfd,"w");

	len = 0;
	addQbuf( 0); len++;
	addQbuf(22);

 if( words ){
	addQbuf( 0); addQbuf( 0); addQbuf(50);
	addQbuf( 0); addQbuf(10); addQbuf( 0);
	addQbuf( 0); addQbuf( 0); addQbuf(50);
 }else{
	addQbuf( 0); addQbuf( 0); addQbuf(10);
	addQbuf( 0); addQbuf( 0); addQbuf(16);
	addQbuf( 0); addQbuf( 0); addQbuf(15);
 }
	addQbuf( 1);
	vtop = len;

	if( words ){
		addQbuf(17); addQbuf( 0);
	}else{
		addQbuf(17); addQbuf( 3);
		Xstrcpy(DVStr(qpdu,len),"FOO");
		len += 3;
	}
	addQbuf(18); addQbuf(strlen(dbname));
		Xstrcpy(DVStr(qpdu,len),dbname);
		len += strlen(dbname);

	if( words ){
		addQbuf(20); addQbuf( 1); addQbuf('3');
	}else{
		addQbuf(20); addQbuf( 1); addQbuf('1');
		addQbuf(19); addQbuf(15);
		Xstrcpy(DVStr(qpdu,len)," \037Document Text");
		len += 15;
	}
	addQbuf( 2); addQbuf( 1); addQbuf(++serno);
	setVStrElem(qpdu,1,len - 2);

 if( words ){
	addQbuf(99); ulen = len; addQbuf(0x80); addQbuf( 0);
 }else{
	addQbuf(21); ulen = len; addQbuf(0x80); addQbuf( 0);
 }

	if( words != NULL ){
		CStr(ewords,1024);

TO_EUC(words,AVStr(ewords),"text/plain");

		addQbuf(111);addQbuf( 1); addQbuf( 1);
		addQbuf(114);addQbuf( 1); addQbuf(MAX_REC_DOC);
		addQbuf(106);addQbuf(strlen(ewords));
		Xstrcpy(DVStr(qpdu,len),ewords);
		len += strlen(ewords);
	}
	if( did != NULL ){
		int dl;
		CStr(tmp,128);

		addQbuf(PD_AttributeList);
		addQbuf(17);
		Xstrcpy(DVStr(qpdu,len),"un re ig ig ig ig");
		len += 17;
		dl = decode_did((unsigned char*)did,(unsigned char*)&qpdu[len+3]);
		addQbuf(PD_Term);
		addQbuf(0x80 | 0x7F & (dl>>7));
		addQbuf(0x7F & dl);
		len += dl;

		addQbuf(PD_AttributeList);
		addQbuf(17);
		Xstrcpy(DVStr(qpdu,len),"wt re ig ig ig ig");
		len += 17;
		addQbuf(PD_Term);
		addQbuf(strlen(type));
		Xstrcpy(DVStr(qpdu,len),type);
		len += strlen(type);

		addQbuf(PD_Operator);
		addQbuf( 1);
		addQbuf('a');

		addQbuf(PD_AttributeList);
		addQbuf(17);
		Xstrcpy(DVStr(qpdu,len),"wb ro ig ig ig ig");
		len += 17;
		addQbuf(PD_Term);
		addQbuf( 1);
		addQbuf('0');

		addQbuf(PD_Operator);
		addQbuf( 1);
		addQbuf('a');

		addQbuf(PD_AttributeList);
		addQbuf(17);
		Xstrcpy(DVStr(qpdu,len),"wb rl ig ig ig ig");
		len += 17;
		sprintf(tmp,"%d",leng);
		addQbuf(PD_Term);
		addQbuf(strlen(tmp));
		Xstrcpy(DVStr(qpdu,len),tmp);
		len += strlen(tmp);

		addQbuf(PD_Operator);
		addQbuf( 1);
		addQbuf('a');
	}

	blen = len - (ulen+2);
	setVStrElem(qpdu,ulen+0,0x80 | 0x7F & (blen>>7));
	setVStrElem(qpdu,ulen+1,0x7F & blen);

/*
Verbose(">>>>>>>> %010dz2wais        0\n",len);
Verbose("HederLength: %d / %d\n",((qpdu[0]<<8)|qpdu[1]),len);
dump_searchPDU(22,qpdu+2);
dump_record(&qpdu[vtop],len-vtop,VStrNULL);
*/

	fprintf(ts,"%010dz2wais        0",len);
	fwrite(qpdu,1,len,ts);
	fflush(ts);
	relay_record(Conn,0,fs,null,AVStr(head),AVStr(out));
}

/*
 *    WWW Address mapping convention:
 *
 *    /servername/database/type/length/document-id
 *    /servername/database?word+word+word
 */

static int putIndex(Connection *Conn,FILE *tc,int vno,PCStr(dbname),PCStr(words),PCStr(head),PCStr(body))
{	int totalc,returned;
	const char *hfp;

	totalc = putHttpHeaderV(Conn,tc,vno,NULL,"text/html",NULL,0,0,0);
	fprintf(tc,"<TITLE> WAIS Search in %s database</TITLE>",dbname);
	fprintf(tc,"<H2> WAIS Search in `%s' database </H2>",dbname);
	fprintf(tc,"at the server <I>%s:%d</I><BR>",DST_HOST,DST_PORT);
	fprintf(tc,"<ISINDEX>");

	if( *words ){
		if( hfp = findFieldValue(head,"Search-Returned") )
			returned = atoi(hfp);
		else	returned = 0;

		fprintf(tc,"<B>`%s'</B> found in ",words);
		if( returned == MAX_REC_DOC )
			fprintf(tc,"more than ");
		fprintf(tc,"<B>%d</B> documents ",returned);
		fprintf(tc,"in <B>%s</B> database.\n",dbname);
		fprintf(tc,"<PRE>\n");
		fprintf(tc,"score   date   lines\n");
		fprintf(tc,"----- -------- -----\n");
		fprintf(tc,"%s",body);
		fprintf(tc,"</PRE><HR>");
		totalc += strlen(body);
	}
	totalc += putFrogForDeleGate(Conn,tc,"");
	return totalc;
}

int HttpWais(Connection *Conn,int vno,int sv,PCStr(server),int iport,PCStr(path))
{	CStr(xpath,0x10000);
	const char *dbname;
	const char *docid;
	refQStr(words,xpath); /**/
	FILE *tc,*tcx;
	int totalc;
	const char *dp;
	const char *type;
	int leng;
	int svsock;
	CStr(head,0x2000);
	CStr(body,0x40000); /* large enough to receive catalog... X-< */

	head[0] = body[0] = 0;
	strcpy(xpath,path);
	dbname = xpath;
	if( *dbname == '/' )
		dbname++;

	if( words = strchr(dbname,'?') ){
		truncVStr(words); words++;
		nonxalpha_unescape(words,AVStr(words),1);
		docid = NULL;
		type = NULL;
		leng = 0;
		goto search;
	}else
	if( type = strchr(dbname,'/') ){
		truncVStr(type); type++;
		if( dp = strchr(type,'/') ){
			truncVStr(dp); dp++;
			leng = atoi(dp);
			if( docid = strchr(dp,'/') ){
				truncVStr(docid); docid++;
				words = NULL;
				goto search;
			}
		}
	}else
	if( *dbname ){
		docid = NULL;
		words = "";
		goto search;
	}
	return 0;

search:
	if( (svsock = sv) == -1 )
	if( (svsock = connect_to_serv(Conn,FromC,ToC,0)) < 0 )
		return 0;

	if( words && *words || docid ){
		curDB = dbname;
		byDID = docid != NULL;
		wais_search(Conn,svsock,AVStr(head),AVStr(body),dbname,words,docid,type,leng);
		byDID = 0;
		curDB = NULL;
	}

	tc = fdopen(ToC,"w");
	tcx = (FILE*)openHttpResponseFilter(Conn,tc);
	if( words ){
		totalc = putIndex(Conn,tcx,vno,dbname,words,head,body);
	}else
	if( docid ){
		/* code-conv. will not be done in MASTER, so sending to
		 * ResponseFilter is necessary also for code-conv.
		 */
		totalc = putHttpHeaderV(Conn,tcx,vno,NULL,"text/plain",NULL,0,0,0);
		fputs(body,tcx);
		totalc += strlen(body);
	}
	fclose(tcx);
	fflush(tc);
	return totalc;
}
