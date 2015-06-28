/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1997-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2006 National Institute of Advanced Industrial Science and Technology (AIST)
AIST-Product-ID: 2000-ETL-198715-01, H14PRO-049, H15PRO-165, H18PRO-443

Permission to use this material for noncommercial and/or evaluation
purpose, copy this material for your own use, and distribute the copies
via publicly accessible on-line media, without fee, is hereby granted
provided that the above copyright notice and this permission notice
appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	pgp.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970208	created
//////////////////////////////////////////////////////////////////////#*/
#include "ystring.h"
#include "mime.h"
static void putENCRIPTED(FILE *src,FILE *dst,PCStr(boundary),PCStr(EOL));
static void putSIGNED(FILE *src,FILE *sign,FILE *dst,PCStr(boundary),PCStr(EOL));

int PGP_MODE;
#define _PGP_SIGN	1
#define _PGP_ENCR	2
#define _PGP_VRFY	4
#define _PGP_DECR	8
#define _PGP_MIME	0x10	/* encode in PGP/MIME format */

int PGP_SIGN(){ return PGP_MODE & _PGP_SIGN; }
int PGP_ENCR(){ return PGP_MODE & _PGP_ENCR; }
int PGP_VRFY(){ return PGP_MODE & _PGP_VRFY; }
int PGP_DECR(){ return PGP_MODE & _PGP_DECR; }
int PGP_MIME(){ return PGP_MODE & _PGP_MIME; }

#define CRLF	"\r\n"

#include <fcntl.h>
#ifdef O_BINARY
#define LEOLINE	"\r\n"  /* may be on Windows */
#else
#define LEOLINE	"\n"
#endif

static scanListFunc pgp1(PCStr(arg))
{
	if( strcasecmp(arg,"sign") == 0 ) PGP_MODE |= _PGP_SIGN; else
	if( strcasecmp(arg,"encr") == 0 ) PGP_MODE |= _PGP_ENCR; else
	if( strcasecmp(arg,"decr") == 0 ) PGP_MODE |= _PGP_DECR; else
	if( strcasecmp(arg,"vrfy") == 0 ) PGP_MODE |= _PGP_VRFY; else
	if( strcasecmp(arg,"mime") == 0 ) PGP_MODE |= _PGP_MIME; else
	syslog_ERROR(
		"Unknown parameter \"PGP=%s\". Use {sign,mime,encr,decr,vrfy}*\r\n",
		arg);
	return 0;
}
void scan_PGP(void*_,PCStr(args))
{
	scan_commaList(args,0,scanListCall pgp1);
}

static FILE *xpopen(PCStr(shcom),PCStr(mode),int dstfd)
{	int stdout_fd;
	FILE *pfp;

	stdout_fd = dup(1);
	dup2(dstfd,1);
	pfp = popen(shcom,mode);
	dup2(stdout_fd,1);
	close(stdout_fd);
	return pfp;
}

void PGPverify(FILE *src,FILE *sign,FILE *vrfy)
{	CStr(datafile,1024);
	CStr(signfile,1024);
	FILE *pfp,*ofp,*fp;
	CStr(shcom,1024);
	int io[2],ch,nc,unlink_err;

	fp = TMPFILEX(AVStr(datafile));
	copyLEOLINE(src,fp);
	fclose(fp);

	fp = TMPFILEX(AVStr(signfile));
	copyfile1(sign,fp);
	fclose(fp);

	sprintf(shcom,"pgp %s %s",signfile,datafile);
	fprintf(stderr,"\r\n==> %s [%s]\r\n","VRFY",shcom);
	IGNRETZ pipe(io);

	pfp = xpopen(shcom,"w",io[1]);
	close(io[1]);
	ofp = fdopen(io[0],"r");

	unlink_err = 0;
	for( nc = 0; ; nc++ ){
		ch = getc(ofp);
		if( nc == 0 ){
			/* visible data files should be removed as fast as
			 * possible (but it's impossible under Windows X-)
			 */
			unlink_err |= unlink(datafile);
			unlink_err |= unlink(signfile);
		}
		if( ch == EOF )
			break;

		putc(ch,stderr);
		putc(ch,vrfy);
	}
	fclose(ofp);
	pclose(pfp);

	if( unlink_err ){
		unlink(datafile);
		unlink(signfile);
	}
}
void PGPcodec(PCStr(com),PCStr(pass),FILE*src,FILE*sign,FILE*dst)
{	CStr(shcom,1024);
	CStr(line,1024);
	FILE *pfp,*tmp;
	CStr(pgppassfd,128);
	int passfd[2];

	sprintf(shcom,"pgp -f");
	if( strcaseeq(com,"ENCR") )
		strcat(shcom," -ca");
	else
	if( strcaseeq(com,"SIGN") ){
		strcat(shcom," -sta");
		if( sign ){
			strcat(shcom," -b");
			dst = sign;
		}
	}

	fprintf(stderr,"\r\n==> %s [%s]\r\n",com,shcom);
	if( pass[0] ){
		IGNRETZ pipe(passfd);
		IGNRETP write(passfd[1],pass,strlen(pass));
		IGNRETP write(passfd[1],LEOLINE,strlen(LEOLINE));
		sprintf(pgppassfd,"PGPPASSFD=%d",passfd[0]);
		putenv(pgppassfd);
	}

	if( file_isreg(fileno(dst)) ){
		tmp = NULL;
		pfp = xpopen(shcom,"w",fileno(dst));
	}else{
		tmp = TMPFILE("PGPcodec");
		pfp = xpopen(shcom,"w",fileno(tmp));
	}

	if( pass[0] ){
		close(passfd[0]);
		close(passfd[1]);
	}

	while( fgets(line,sizeof(line),src) )
		fputs(line,pfp);

	pclose(pfp);

	if( tmp != NULL ){
		fseek(tmp,0,0);
		copyfile1(tmp,dst);
		fclose(tmp);
	}
	fseek(dst,0,2);
}

/*
 * RFC 2015
 */
int isPGPMIME(FILE *art)
{	CStr(ctype,512);

	fgetsHeaderField(art,"Content-Type",AVStr(ctype),sizeof(ctype));
	if( strncasecmp(ctype,"multipart/encrypted",19) == 0 )
		return 1;
	if( strncasecmp(ctype,"multipart/signed",16) == 0 )
		return 1;
	return 0;
}
static void replaceCtype(FILE *src, FILE *dst,PCStr(ctype),PCStr(EOL),int noEOH)
{	CStr(line,1024);
	int putit,putctype,putmmver,EOH;
	CStr(mmver,128);

	putit = 0;
	putmmver = 0;
	putctype = 0;
	myMIMEversion(AVStr(mmver));

	while( fgets(line,sizeof(line),src) ){
		if( line[0] != ' ' && line[0] != '\t' ){
			if( strncasecmp(line,"MIME-Version",12) == 0 ){
				fprintf(dst,"MIME-Version: %s%s",mmver,EOL);
				putmmver = 1;
				putit = 0;
			}else
			if( strncasecmp(line,"Content-Type",12) == 0 ){
				if( ctype[0] )
				fprintf(dst,"Content-Type: %s%s",ctype,EOL);
				putctype = 1;
				putit = 0;
			}else	putit = 1;
		}
		if( EOH = line[0] == '\r' || line[0] == '\n' ){
			if( !putmmver )
				fprintf(dst,"MIME-Version: %s%s",mmver,EOL);
			if( !putctype && ctype[0] )
				fprintf(dst,"Content-Type: %s%s",ctype,EOL);
			if( noEOH )
				break;
		}
		if( putit )
			fputs(line,dst);
		if( EOH )
			break;
	}
}

static void putPGPMIME(FILE *src,FILE *dst,PCStr(pcom),PCStr(EOL))
{	CStr(ctype,512);
	CStr(nctype,1024);
	int off;
	const char *crtyp;
	const char *proto;
	CStr(boundary,128);
	FILE *body1,*body2;

	off = ftell(src);
	fseek(src,0,2);
	sprintf(boundary,"PGP-MIME-MimeKit%s-%x-%x-%x",
		MimeKit_Version,itime(NULL),iftell(src),getpid());
	fseek(src,off,0);

	if( PGP_ENCR() ){
		crtyp = "multipart/encrypted";
		proto = "application/pgp-encrypted";
	}else{
		crtyp = "multipart/signed";
		proto = "application/pgp-signature";
	}

	fgetsHeaderField(src,"Content-Type",AVStr(ctype),sizeof(ctype));

	sprintf(nctype,"%s; boundary=\"%s\";%s  micalg=%s; protocol=\"%s\"",
			crtyp, boundary, EOL, "pgp-md5", proto);

	replaceCtype(src,dst,nctype,EOL,0);

	body1 = TMPFILE("PGPMIME");

	/* it is safer to send Local End Of Line code to pgp ... */
	if( ctype[0] )
		fprintf(body1,"Content-Type: %s%s",ctype,LEOLINE);
	fprintf(body1,"%s",LEOLINE);
	copyLEOLINE(src,body1);
	fflush(body1);
	fseek(body1,0,0);
	body2 = TMPFILE("PGPMIME");

	if( PGP_ENCR() ){
		PGPcodec(pcom,"",body1,NULL,body2);
		fseek(body2,0,0);
		putENCRIPTED(body2,dst,boundary,EOL);
	}else{
		PGPcodec(pcom,"",body1,body2,NULL);
		fseek(body1,0,0);
		fseek(body2,0,0);
		putSIGNED(body1,body2,dst,boundary,EOL);
	}

	fclose(body2);
	fclose(body1);
}

#define BGN_PGP		"-----BEGIN PGP "
#define BGN_MSG		"-----BEGIN PGP MESSAGE-----"
#define END_MSG		"-----END PGP MESSAGE-----"
#define BGN_SIGNED	"-----BEGIN PGP SIGNED MESSAGE-----"
#define BGN_SIGN	"-----BEGIN PGP SIGNATURE-----"
#define END_SIGN	"-----END PGP SIGNATURE-----"

static void putENCRIPTED(FILE *src,FILE *dst,PCStr(boundary),PCStr(EOL))
{
	fprintf(dst,"--%s%s",boundary,EOL);
	fprintf(dst,"Content-Type: application/pgp-encrypted%s",EOL);
	fprintf(dst,"%s",EOL);
	fprintf(dst,"Version: 1%s",EOL);
	fprintf(dst,"%s",EOL);
	fprintf(dst,"--%s%s",boundary,EOL);
	fprintf(dst,"Content-Type: application/octet-stream%s",EOL);
	fprintf(dst,"%s",EOL);
	copyfile1(src,dst);
	fprintf(dst,"%s",EOL);
	fprintf(dst,"--%s--%s",boundary,EOL);
}

static void putSIGNED(FILE *src,FILE *sign,FILE *dst,PCStr(boundary),PCStr(EOL))
{
	fprintf(dst,"--%s%s",boundary,EOL);
	copyfile1(src,dst);
	fprintf(dst,"%s",EOL);

	fprintf(dst,"--%s%s",boundary,EOL);
	fprintf(dst,"Content-Type: application/pgp-signature%s",EOL);
	fprintf(dst,"%s",EOL);
	copyfile1(sign,dst);
	fprintf(dst,"%s",EOL);

	fprintf(dst,"--%s--%s",boundary,EOL);
}

static FILE *getEOR(FILE *msg,PVStr(eor),int size)
{	FILE *nmsg;

	nmsg = TMPFILE("PGPMIME");
	setVStrEnd(eor,0);
	RFC821_skipbody(msg,nmsg,AVStr(eor),size);
	fclose(msg);
	fflush(nmsg);
	fseek(nmsg,0,0);
	return nmsg;
}
void getEOLINE(FILE *msg,PVStr(eol))
{	int off,ch;

	off = ftell(msg);
	strcpy(eol,CRLF);
	while( (ch = getc(msg)) != EOF ){
		if( ch == '\r' ){
			ch = getc(msg);
			if( ch == '\n' || ch == EOF )
				break;
			ungetc(ch,msg);
		}else
		if( ch == '\n' ){
			strcpy(eol,"\n");
			break;
		}
	}
	fseek(msg,off,0);
}
void copyLEOLINE(FILE *src,FILE *dst)
{	CStr(line,1024);
	refQStr(np,line); /**/

	while( fgets(line,sizeof(line),src) ){
		if( np = strpbrk(line,CRLF) )
			strcpy(np,LEOLINE);
		fputs(line,dst);
	}
}
void toJISjaca(FILE *src,FILE *dst,PCStr(EOL))
{	CStr(line,1024);
	CStr(xline,2048);

	RFC821_skipheader(src,dst,NULL);
	fprintf(dst,"%s",EOL);

	while( fgets(line,sizeof(line),src) ){
		TO_JIS(line,AVStr(xline),"text/plain");
		fputs(xline,dst);
	}
}

/*
 *  RFC 1991
 */
int isPGPFORMAT(FILE *art)
{	CStr(line,1024);
	int ispgp;
	int aoff;
	const char *pstr;
	int plen;

	ispgp = 0;
	aoff = ftell(art);
	pstr = BGN_PGP;
	plen = strlen(pstr);

	while( fgets(line,sizeof(line),art) ){
		if( strncmp(line,pstr,plen) == 0 ){
			ispgp = 1;
			break;
		}
	}
	fseek(art,aoff,0);
	return ispgp;
}

static int isTEXT(FILE *art)
{	CStr(ctype,1024);

	fgetsHeaderField(art,"Content-Type",AVStr(ctype),sizeof(ctype));
	if( ctype[0] == 0 || strncasecmp(ctype,"text/",5) == 0 )
		return 1;
	else	return 0;
}

void PGPencodeMIME(FILE *src,FILE *dst)
{
	PGPencodeMIMEX(src,dst,O_ALL);
}
void PGPencodeMIMEX(FILE *src,FILE *dst,int filter)
{	MimeEnv me;

	me.me_filter = filter;
	me.me_ccx = NULL;
	PGPencodeMIMEXX(&me,src,dst);
}
int PGPencodeMIMEXX(MimeEnv *me,FILE *src,FILE *dst)
{	FILE *tmp1,*tmp2;
	const char *pcom;
	CStr(EOL,4);
	CStr(EOR,128);
	int filter = me->me_filter;

	if( PGP_ENCR() == 0 && PGP_SIGN() == 0 ){
		/*
		encodeMIMEX(src,dst,filter);
		return;
		*/
		encodeMIMEXX(me,src,dst);
		return 0;
	}

	tmp1 = TMPFILE("PGPMIME");
	/*
	encodeMIMEX(src,tmp1,filter);
	*/
	encodeMIMEXX(me,src,tmp1);
	fflush(tmp1);
	fseek(tmp1,0,0);

	if( !isTEXT(tmp1) ){
		copyfile1(tmp1,dst);
		fclose(tmp1);
		/*
		return ;
		*/
		return 0;
	}

	tmp1 = getEOR(tmp1,AVStr(EOR),sizeof(EOR));
	getEOLINE(tmp1,FVStr(EOL));

	if( PGP_SIGN() )
		pcom = "SIGN";
	else	pcom = "ENCR";

	if( PGP_MIME() ){
		putPGPMIME(tmp1,dst,pcom,EOL);
	}else{
		RFC821_skipheader(tmp1,dst,NULL);
		fprintf(dst,"%s",EOL);
		fflush(dst);

		tmp2 = TMPFILE("PGPMIME");
		copyLEOLINE(tmp1,tmp2);
		fflush(tmp2);
		fseek(tmp2,0,0);
		PGPcodec(pcom,"",tmp2,NULL,dst);
		fclose(tmp2);
	}

	fputs(EOR,dst);
	fflush(dst);
	fclose(tmp1);
	return 1;
}

int relay_pgpSIGNED(FILE *fs,FILE *tc,const char *boundaries[],PVStr(endline))
{	int rcode;

	rcode = relayBODYpart(fs,tc,boundaries,1,AVStr(endline));
	return rcode;
}
static FILE *SIGN;
int relay_pgpSIGN(FILE *fs,FILE *tc,const char *boundaries[],PVStr(endline))
{	int rcode;
	FILE *sign;

	if( SIGN )
		sign = SIGN;
	else	sign = tc;
	rcode = relayBODYpart(fs,sign,boundaries,1,AVStr(endline));
	fseek(sign,0,0);
	return rcode;
}

static int copyVerify(FILE *vrfy, FILE *out,PVStr(outs))
{	CStr(line,1024);
	int verified;

	setVStrEnd(outs,0);
	verified = -1;
	while( fgets(line,sizeof(line),vrfy) ){
		if( strncmp(line,"Good signature",14) == 0 ){
			strcat(outs," ");
			strcat(outs,line);
			verified = 1;
		}else
		if( strncmp(line,"Bad signature",13) == 0 ){
			strcat(outs," ");
			strcat(outs,line);
		}else
		if( strncmp(line,"Signature made",14) == 0 ){
			strcat(outs," ");
			strcat(outs,line);
		}
		fputs(line,out);
	}
	return verified;
}
static void putVerify(FILE *out,PCStr(vrfys),PCStr(EOL))
{
	fprintf(out,"X-PGP-Verified: by MimeKit/%s;%s%s",
		MimeKit_Version,EOL,vrfys);
}

FILE *PGPMIMEverify(FILE *art,int *verified,PCStr(EOL))
{	CStr(ctype,512);
	FILE *jaca,*tmp,*out;
	int oconv;
	FILE *vrfy;
	CStr(vrfys,1024);

	*verified = 0;

	fgetsHeaderField(art,"Content-Type",AVStr(ctype),sizeof(ctype));
	if( strncasecmp(ctype,"multipart/encrypted",19) == 0 )
		return art;

	jaca = TMPFILE("PGPMIME");
	toJISjaca(art,jaca,EOL);
	fflush(jaca);
	fseek(jaca,0,0);
	fclose(art);
	art = jaca;

	SIGN = TMPFILE("PGPMIMESIGN");

	tmp = TMPFILE("MIMEtoPGP");
	oconv = MIME_CONV;
	MIME_CONV = 0;
	decodeMIME(art,tmp,NULL,0xFF,1,0); /* data to tmp, signature to SIGN */
	MIME_CONV = oconv;
	fflush(tmp);
	fseek(tmp,0,0);

	vrfy = TMPFILE("MIMEtoPGP");
	RFC821_skipheader(tmp,NULL,NULL);
	PGPverify(tmp,SIGN,vrfy);
	fseek(vrfy,0,0);
	fseek(tmp,0,0);
	fclose(SIGN);

	fprintf(stderr,"\r\n==> VERIFICATION\n");
	*verified = copyVerify(vrfy,stderr,AVStr(vrfys));
	fseek(vrfy,0,0);

	out = TMPFILE("MIMEtoPGP");

	if( PGP_DECR() ){
		RFC821_skipheader(tmp,NULL,NULL);
		fgetsHeaderField(tmp,"Content-Type",AVStr(ctype),sizeof(ctype));
		fseek(tmp,0,0);

		replaceCtype(tmp,out,ctype,EOL,1);
		if( PGP_VRFY() )
			putVerify(out,vrfys,EOL);
		fprintf(out,"%s",EOL);

		RFC821_skipheader(tmp,NULL,NULL); /* skip inserted header */
		copyfile1(tmp,out);
	}else{
		fseek(art,0,0);
		RFC821_skipheader(art,out,NULL);
		putVerify(out,vrfys,EOL);
		fprintf(out,"%s",EOL);
		copyfile1(art,out);
	}
	fflush(out);
	fseek(out,0,0);

	fclose(art);
	fclose(vrfy);
	fclose(tmp);
	return out;
}

FILE *PGPdecode(FILE *art,int was_mime,PCStr(EOL))
{	FILE *jaca,*tmp1,*tmp2;
	CStr(ctype,512);
	int is_mime;

	tmp1 = TMPFILE("PGPMIME");
	tmp2 = TMPFILE("PGPMIME");

	is_mime = isPGPMIME(art);

	PGPcodec("DECR","",art,NULL,tmp2);
	fflush(tmp2);
	fseek(tmp2,0,0);
	fseek(art,0,0);

	if( is_mime )
		fgetsHeaderField(tmp2,"Content-Type",AVStr(ctype),sizeof(ctype));

	if( is_mime || was_mime ){
		/* Skip Content-Type of Body Part */
		RFC821_skipheader(tmp2,NULL,NULL);
	}
	if( is_mime )
		replaceCtype(art,tmp1,ctype,EOL,0);
	else{
		RFC821_skipheader(art,tmp1,NULL);
		fprintf(tmp1,"%s",EOL);
	}
	copyfile1(tmp2,tmp1);

	fflush(tmp1);
	fseek(tmp1,0,0);

	fclose(tmp2);
	return tmp1;
}

void PGPdecodeMIME(FILE*src,FILE*dst,FILE*cache, int filter,int codeconv,int enHTML)
{	FILE *tmp;
	int is_mime;
	int omode;
	int verified;
	CStr(EOL,4);
	CStr(EOR,1024);

	if( !PGP_DECR() && !PGP_VRFY() ){
		decodeMIME(src,dst,cache,filter,codeconv,enHTML);
		return;
	}

	tmp = TMPFILE("PGPMIME");
	RFC821_skipbody(src,tmp,AVStr(EOR),sizeof(EOR));
	fseek(tmp,0,0);
	if( cache != NULL ){
		copyfile1(tmp,cache);
		fseek(tmp,0,0);
	}

	is_mime = isPGPMIME(tmp);
	getEOLINE(tmp,FVStr(EOL));

	if( !is_mime && !isPGPFORMAT(tmp) ){
		copyfile1(tmp,dst);
		fclose(tmp);
		return;
	}

	/* verify SIGNATURE in PGP/MIME */
	verified = 0;
	if( is_mime )
		tmp = PGPMIMEverify(tmp,&verified,EOL);

	/* decrypt PGP */
	if( verified == 0 && PGP_DECR() )
		tmp = PGPdecode(tmp,is_mime,EOL);

	/* convert CHARCODE */

	omode = PGP_MODE;
	PGP_MODE = 0;
	decodeMIME(tmp,dst,NULL,filter,codeconv,enHTML);
	PGP_MODE = omode;

	fputs(EOR,dst);
	fflush(dst);
	fclose(tmp);
}
