/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	msg.c (message I/O)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
	Multiplex control and data messages on a communication channel.
History:
	941225	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include "ystring.h"
#include "dglib.h"
#include "fpoll.h"

#define MSG_SIZE	0x8000
#define MSG_TIMEOUT	((double)0.5)

static void sv1Vlog(PCStr(fmt), ...){}

#define BASE64	"/BASE64"

void putPreStatus(FILE *dstf,PCStr(status))
{
	fprintf(dstf,"^%s",status);
	fflush(dstf);
}
void putPostStatus(FILE *dstf,PCStr(status))
{	const char *sp;
	char ch;

	fputs("$",dstf);
	for( sp = status; ch = *sp; sp++ ){
		if( ch == '\n' && sp[1] != 0 )
			fputs("\\n",dstf);
		else
		if( ch == '\\' )
			fputs("\\\\",dstf);
		else	putc(ch,dstf);
	}
	fflush(dstf);
}
static void unescape_nl(PVStr(str))
{	refQStr(dp,str); /**/
	const char *sp;
	char ch;

	sp = str;
	dp = (char*)sp;
	while( ch = *sp++ ){
		if( ch == '\\' ){
			if( *sp == 'n' )
				setVStrPtrInc(dp,'\n');
			else	setVStrPtrInc(dp,*sp);
			sp++;
		}else	setVStrPtrInc(dp,ch);
	}
	setVStrEnd(dp,0);
}
static int putmsghead(PCStr(what),int ser,PCStr(buff),int leng,FILE *dst,PCStr(encode),PVStr(xbuff))
{	int xleng = 0;

	if( buff == NULL )
		return 0;

	sv1Vlog("%s: @%d %d %s\r\n",what,ser,leng,"");
	if( encode && strcaseeq(encode,BASE64) )
		xleng = leng = str_to64(buff,leng,AVStr(xbuff),MSG_SIZE*2,1);
	else	xleng = 0;
	fprintf(dst,"@%d %d [%s]\r\n",ser,leng,encode);
	return xleng;
}

int putMessage1X(FILE *dstf,int ser,PCStr(buff),int size,PCStr(encode))
{	int wc,wcc,nw;
	CStr(xbuff,MSG_SIZE*2);
	int xsize;

	sv1Vlog("putMessage: got %d\n",size);

	if( xsize = putmsghead("putMessage",ser,buff,size,dstf,encode,AVStr(xbuff)) ){
		buff = xbuff;
		size = xsize;
	}

	if( buff != NULL ){
		nw = 0;
		for( wcc = 0; wcc < size; wcc += wc ){
			wc = fwrite(buff+wcc,1,size-wcc,dstf);
			if( wc == 0 )
				return -1;
			nw++;
		}
	}
	fflush(dstf);
	sv1Vlog("putMessage: put %d/%d\n",size,nw);
	return 0;
}

static int freadIntime(PVStr(buff),int s,int n,FILE *fp,double Timeout)
{	int rc,rc0,rc1;
	double start,end;
	int nread;

	if( s != 1 )
		return freadTIMEOUT(BVStr(buff),s,n,fp);

	start = Time();
	end = 0;
	rc = 0;
	nread = 0;
	while( rc < n ){
		if( feof(fp) ){
			break;
		}
		rc0 = n - rc;
		if( 512 < rc0 )
			rc0 = 512;

		rc1 = freadTIMEOUT(QVStr(buff+rc,buff),s,rc0,fp);
		end = Time();

		if( rc1 == 0 )
			break;

		nread++;
		rc += rc1;
		if( Timeout <= (end-start) )
			break;
	}
	daemonlog("D","freadIntime: %dbytes / %dread / %4.2fseconds\n",
		rc,nread,end-start);
	return rc;
}

FileSize putMessageFX(FILE *srcf,FILE *dstf,FILE *cachefp,PCStr(encode))
{
	return putMessageFX_CB(srcf,dstf,cachefp,encode,NULL,NULL);
}
FileSize putMessageFX_CB(FILE *srcf,FILE *dstf,FILE *cachefp,PCStr(encode),msgCBFunc cb,void *cbarg)
{	int ser,rcc;
	FileSize rcc_total;
	CStr(buff,MSG_SIZE);

	rcc_total = 0;
	for( ser = 1; rcc = freadIntime(AVStr(buff),1,sizeof(buff),srcf,MSG_TIMEOUT); ser++ ){
		if( cb != NULL ){
			rcc = (*cb)(cbarg,AVStr(buff),rcc);
			if( rcc < 0 ){
				break;
			}
		}
		rcc_total += rcc;
		if( cachefp )
			fwrite(buff,1,rcc,cachefp);
		if( putMessage1X(dstf,ser,buff,rcc,encode) < 0 )
			goto EXIT;
	}
	putMessage1X(dstf,ser,NULL,0,encode);
	fflush(dstf);
EXIT:
	return rcc_total;
}


#define MSG_BUFSIZE (MSG_SIZE *2) /* extra space for pending strings without NL */
static struct { defQStr(PendingBuff); } PendingBuff;
#define PendingBuff PendingBuff.PendingBuff
static const char *PendingP;
static int Pending;
static int DoFill;

static void pclear()
{
	PendingP = PendingBuff;
	Pending = 0;
	DoFill = 0;
}
static int pfill(int len,FILE *srcf)
{	int brc;

	if( PendingBuff == 0 )
		setQStr(PendingBuff,(char*)calloc(MSG_BUFSIZE,1),MSG_BUFSIZE);
	if( Pending )
		Bcopy(PendingP,PendingBuff,Pending);
	PendingP = PendingBuff;
	brc = freadTIMEOUT(QVStr(PendingBuff+Pending,PendingBuff),1,len,srcf);
	Pending += brc;
	sv1vlog("fillPending: +%d = %d bytes\n",brc,Pending);
	return brc;
}
static void ppush(PCStr(buff),int len)
{
	if( PendingBuff == 0 )
		setQStr(PendingBuff,(char*)calloc(MSG_BUFSIZE,1),MSG_BUFSIZE);

	PendingP = PendingBuff;
	bcopy(buff,(char*)PendingBuff+Pending,len);
	Pending += len;
	sv1log("pushPending: +%d = %d bytes\n",len,Pending);
}
static int pgets(PVStr(buff),int len,FILE *srcf)
{	int pi;
	const char *sp;
	refQStr(dp,buff); /**/
	char ch;
	int rc,rrc,EOB = 0;

	if( Pending == 0 || DoFill )
	if( !feof(srcf) ){
		DoFill = 0;
		rrc = pfill(len,srcf);
		if( len == rrc )
			EOB = 1;
	}

	sp = PendingP;
	cpyQStr(dp,buff);
	rc = 0;
	for( pi = 0; pi < Pending; pi++ ){
		assertVStr(buff,dp+1);
		rc++;
		ch = *sp++;
		setVStrPtrInc(dp,ch);
		if( ch == '\n' )
			goto GOTNL;
		if( ch == '\r' && rc < Pending && *sp != '\n' )
			goto GOTNL;
	}

	if( MSG_SIZE <= pi || EOB ){
		sv1log("Without CR/LF: %d/%d, %d\n",pi,MSG_SIZE,EOB);
		goto GOTNL;
	}

	if( !feof(srcf) ){
		DoFill = 1;
		return 0;
	}
GOTNL:
	setVStrEnd(buff,rc);
	Pending -= rc;
	PendingP = sp;
	return rc;
}

static int flushPending(int outEOF,int ser,siFUNCP func,FILE *dstf,PCStr(arg))
{	int pending;

	if( pending = Pending ){
		sv1log("flushPending: eof=%d %d\n",outEOF,Pending);
		if( !outEOF ){
			/* should be done line by line in "linemode" ... */
			(*func)(ser,PendingP,Pending,dstf,arg);
		}
		pclear();
	}
	return pending;
}

FileSize getMessageFX(FILE *srcf,FILE *cachefp,int timeout,siFUNCP func,FILE *dstf,PCStr(arg),PCStr(encode))
{	CStr(head,MSG_SIZE+1);
	FileSize total;
	int ser,rc,rcc1,rcc,pending,pen;
	CStr(buff,MSG_SIZE+1);
	const char *op;
	int linemode;
	int outEOF;
	int decode64,cleng;

	total = 0;
	head[0] = 0;
	linemode = 0;
	pending = 0;
	outEOF = 0;

	op = "";
	for(;;){
		if( dstf != NULL && ready_cc(srcf) == 0 )
			if( fflushTIMEOUT(dstf) == EOF ){
				outEOF++;
				break;
			}

		head[0] = 0;
		if( fgetsTimeout(AVStr(head),sizeof(head),srcf,timeout) == NULL ){
			sv1log("getMessageF: fgets timeout(%d)\n",timeout);
			break;
		}

		if( head[0] == '^' ){
			op = (*func)(-1,head+1,strlen(head)-1,dstf,arg);
			if( op && streq(op,"linemode") ){
				sv1log("getMessageF: linemode\n");
				linemode = 1;
			}
			continue;
		}
		if( head[0] == '$' ){
			total += flushPending(outEOF,ser,func,dstf,arg);
			unescape_nl(AVStr(head));
			(*func)(0,head+1,strlen(head)-1,dstf,arg);
			sv1Vlog("getMessageF: End of Block\n");
			break;
		}

		buff[0] = 0;
		if( Xsscanf(head,"@%d %d %[^\r\n]\r\n",&ser,&rcc,AVStr(buff)) < 2 )
		if( sscanf(head,"@%d - %d\r\n",&ser,&rcc) != 2 ){
			sv1log("getMessageF: Bad block header(%d) %s\n",
				istrlen(head),head);
			break;
		}

		sv1Vlog("getMessageF: @%d %d %s\n",ser,rcc,buff);
		decode64 = strcasestr(buff,BASE64) != 0;

		if( 0 < rcc ){
		    pen = pending;
		    pending = 0;
		    for( ; 0 < pen+rcc; rcc -= rc ){

			if( dstf != NULL && ready_cc(srcf) == 0 )
				if( fflushTIMEOUT(dstf) == EOF ){
					outEOF++;
					break;
				}

			if( linemode ){
				rc = pgets(AVStr(buff),rcc,srcf);
				if( rc == 0 ){
					pending = pen+rcc;
					break;
				}
				op = (*func)(ser,buff,rc,dstf,arg);
				if( cachefp )
					fwrite(buff,1,rc,cachefp);
			}else{
				if( rcc < MSG_SIZE )
					rcc1 = rcc;
				else	rcc1 = MSG_SIZE;

/*
951026
rc = freadIntime(AVStr(buff),1,rcc1,srcf,(double)1);
timeouting often make the received packet collupted (in back-linemode only ?
*/
				rc = freadTIMEOUT(AVStr(buff),1,rcc1,srcf);
				if( rc == 0 ){
					sv1log("getMessageF: premature EOF\n");
					break;
				}
				if( decode64 ){
					cleng =
					str_from64(buff,rc,AVStr(head),sizeof(head));
					Bcopy(head,buff,cleng);
				}else	cleng = rc;
				op = (*func)(ser,buff,cleng,dstf,arg);
				if( cachefp )
					fwrite(buff,1,cleng,cachefp);

				if( op && streq(op,"back-linemode") ){
					sv1log("getMessageF: back-linemode\n");
					ppush(buff,rcc1);
					linemode = 1;
					rc = 0;
				}
			}
			if( op && streq(op,"ABORT") ){
				goto EXIT;
			}
			if( op && streq(op,"EOF") ){
				if( outEOF <= 1 )
					sv1log("getMessageF: EOF/output\n");
				outEOF++;
				break;
			}
			total += cleng;
		    }
		}
	}
	if( dstf != NULL ) fflushTIMEOUT(dstf);
EXIT:
	if( op && streq(op,"ABORT") ){
		int len = 0;
		sv1log("-- ABORT ...\n");
		for(;;){
			if(fgetsTimeout(AVStr(head),sizeof(head),srcf,5)==NULL)
				break;
			/*
			sv1log("-- %s",head);
			*/
			if( head[0] == '$' ){
				break;
			}
			len += strlen(head);
		}
		sv1log("-- ABORT DONE skipped %d\n",len);
		total += len;
	}
	sv1vlog("getMessageF: done(%lld) + %d\n",total,Pending);
	total += flushPending(outEOF,ser,func,dstf,arg);
	return total;
}
static const char *cpy1(int ser,PCStr(buff),int leng,FILE *dst,PCStr(encode))
{	int wcc;
	CStr(xbuff,MSG_SIZE*2);
	int xsize;

	if( ser <= 0 )
		return "";

	if( xsize = putmsghead("cpy1",ser,buff,leng,dst,encode,AVStr(xbuff)) ){
		buff = xbuff;
		leng = xsize;
	}

	wcc = fwrite(buff,1,leng,dst);
	return "";
}
FileSize cpyMessageFX(FILE *src,FILE *dst,FILE *cachefp,PCStr(encode))
{
	/*
	return getMessageFX(src,cachefp,0,cpy1,dst,"",encode);
	*/
	return getMessageFX(src,cachefp,0,cpy1,dst,encode,"");
}
