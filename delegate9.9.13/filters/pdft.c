/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2005-2006 National Institute of Advanced Industrial Science and Technology (AIST)

Permission to use this material for noncommercial and/or evaluation
purpose, copy this material for your own use, and distribute the copies
via publicly accessible on-line media, without fee, is hereby granted
provided that the above copyright notice and this permission notice
appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:   program/C; charset=US-ASCII
Program:        pdft.c
Author:         Yutaka Sato <ysato@delegate.org>
Description:
History:
        051114  created
//////////////////////////////////////////////////////////////////////#*/
/*
9.0.6 introduction and extension the MOUNT for PDF and SWF
http://en.wikipedia.org/wiki/Portable_Document_Format
http://partners.adobe.com/public/developer/pdf/index_reference.html
PDFReference16.pdf

PDF translator
Yutaka Sato
051114 created

http://www.cs.cmu.edu/~dst/Adobe/Gallery/anon21jul01-pdf-encryption.txt
*/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "ystring.h"
#include "credhy.h"
#include "dglib.h"
#include "auth.h"

int zlibUncompress(void *in,int isiz,void *out,int osiz);
int gunzipFilter(FILE *in,FILE *out);

int sslway_dl();
#define RC4_INT unsigned int
typedef struct {
	RC4_INT x,y;
	RC4_INT data[256];
} RC4_KEY;
void myRC4_set_key(RC4_KEY *key,int len,const unsigned char *data);
void myRC4(RC4_KEY *key,unsigned long len,const unsigned char *in,unsigned char *out);
#define RC4_set_key	myRC4_set_key
#define RC4		myRC4

#define P_SCANONLY	1
#define P_SHOWSTAT	2
#define P_VERBOSE	4
#define P_IGNERROR	8

typedef struct {
	int	 p_ver;
	int	 p_rev;
	int	 p_permit;
 unsigned char	 p_key[16];
	int	 p_length;
} Stdf;

#define MAX_TOKENSIZE	(2*1024*1024)	/* maybe with \ddd encoding */
typedef struct {
	int	 p_flags;
  const char	*p_inf;
	FILE	*p_in;
	FILE	*p_out;
	FILE	*p_dec; /* decrypted & decoded format */
	int	 p_col;
	char	*p_header;
	MStr(	 p_id0,32);
	int	 p_id0len;
	MStr(	 p_id1,32);
	int	 p_nobjs;
	MStr(	 p_token,MAX_TOKENSIZE);
	MStr(	 p_objsrc,1024); /* in normalized representation */

	int	 p_pch; /* previous char. in output text */
	int	 p_outch;
	int	 p_ignch;

	int	 p_objn;
	int	 p_genn;
	int	 p_stdfilter;
	Stdf	 p_stdf;
} Pdf;


static int header(Pdf *pdf);
static int iobj(Pdf *pdf);

static void scan_pdf(Pdf *pdf){
	header(pdf);
	/* body is a list of indirect objects */
	for(;;){
		if( iobj(pdf) < 0 ){
			break;
		}
		pdf->p_nobjs++;
	}

	if( pdf->p_flags & P_SHOWSTAT ){
	fprintf(stderr,"%s, %5d obj, text %6d / %6d (ign %d, out %d), %s\n",
			pdf->p_header,
			pdf->p_nobjs,
			iftell(pdf->p_out),iftell(pdf->p_in),
			pdf->p_ignch,
			pdf->p_outch,
			pdf->p_inf?pdf->p_inf:"");
	}
}
int PdfToText(FILE *pdff,FILE *txtf){
	Pdf *pdf;

	pdf = (Pdf*)calloc(1,sizeof(Pdf));
	pdf->p_in = pdff;
	pdf->p_out = txtf;
	pdf->p_flags = P_SHOWSTAT;
	scan_pdf(pdf);
	free(pdf);
	return 0;
}
int pdft_main(int ac,const char *av[]){
	Pdf *pdf;
	int ai;
	const char *a1;
	const char *inf = 0;

	pdf = (Pdf*)calloc(1,sizeof(Pdf));
	pdf->p_in = stdin;
	pdf->p_out = stdout;
	pdf->p_dec = fopen("/tmp/pdf.dec","w");
	pdf->p_flags = P_SHOWSTAT;

	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( *a1 == '-' ){
			switch( a1[1] ){
				case 's': pdf->p_flags |= P_SCANONLY; break;
				case 'V': pdf->p_flags |= P_VERBOSE; break;
				case 'I': pdf->p_flags |= P_IGNERROR; break;
			}
		}else{
			if( inf == 0 ){
				inf = a1;
			}
		}
	}
	if( inf ){
		pdf->p_in = fopen(inf,"r");
		if( pdf->p_in == NULL ){
			fprintf(stderr,"%s: cannot open %s\n",av[0],inf);
			return -1;
		}
		pdf->p_inf = inf;
	}

	scan_pdf(pdf);
	return 0;
}
#ifdef MAIN
int main(int ac,char *av[]){
	pdft_main(ac,(const char**)av);
	return 0;
}
#endif

static char passpadd[] = {
	0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
	0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
	0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
	0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A
};
static void setupCrypt(Pdf *pdf,int ver,int rev,int per,int len,PCStr(owner),PCStr(pass)){
	Stdf *stdf;
	MD5 *md5;
	char perm[4];
	const unsigned char *k;

	stdf = &pdf->p_stdf;
	if( len == 0 ){
		len = 40;
	}
	stdf->p_ver = ver;
	stdf->p_rev = rev;
	stdf->p_permit = per;
	stdf->p_length = len;

	md5 = newMD5();
	addMD5(md5,passpadd,32);
	addMD5(md5,owner,32);
	perm[0] = per;
	perm[1] = per >> 8;
	perm[2] = per >> 16;
	perm[3] = per >> 24;
	addMD5(md5,perm,4);
	addMD5(md5,pdf->p_id0,pdf->p_id0len);
	if( 3 <= stdf->p_rev ){
		/* if( !metadata_encrypted ) ... */
		addMD5(md5,"\377\377\377\377",4);
fprintf(stderr,"\t####A# REV %d\n",stdf->p_rev);
	}
	endMD5(md5,(char*)stdf->p_key);

	if( 3 <= stdf->p_rev ){
		int i;
fprintf(stderr,"\t####B# REV %d %dbytes\n",stdf->p_rev,stdf->p_length/8);
		for( i = 0; i < 50; i++ ){
			md5 = newMD5();
			addMD5(md5,(char*)stdf->p_key,stdf->p_length/8);
			endMD5(md5,(char*)stdf->p_key);
		}
	}

	k = stdf->p_key;
	fprintf(stderr,"\t-- SEUTP KEY[%X %X %X %X %X] (ID/ len=%d)\n",
		k[0],k[1],k[2],k[3],k[4],pdf->p_id0len);
	{	int i;
		k = (unsigned char*)pdf->p_id0;
		fprintf(stderr,"\t-- /ID<");
		for( i = 0; i < pdf->p_id0len; i++ )
			fprintf(stderr,"%02x",k[i]);
		fprintf(stderr,">\n");
		fprintf(stderr,"\t-- /P %d %x<",per,per);
		for( i = 0; i < 4; i++ ){
			fprintf(stderr,"%02x",0xFF&perm[i]);
		}
		fprintf(stderr,">\n");
	}

}
static int decryptObj(Pdf *pdf,const unsigned char *in,int ilen,unsigned char *out){
	RC4_KEY key;
	MD5 *md5;
	char digest[16];
	char objnb[3];
	char gennb[2];

	if( sslway_dl() < 0 ){
		return -1;
	}
	md5 = newMD5();
/*
	addMD5(md5,(char*)pdf->p_stdf.p_key,5);
*/
	addMD5(md5,(char*)pdf->p_stdf.p_key,pdf->p_stdf.p_length/8);
	objnb[0] = pdf->p_objn;
	objnb[1] = pdf->p_objn >> 8;
	objnb[2] = pdf->p_objn >> 16;
	addMD5(md5,objnb,3);
	gennb[0] = pdf->p_genn;
	gennb[1] = pdf->p_genn >> 8;
	addMD5(md5,gennb,2);
	endMD5(md5,digest);

/*
fprintf(stderr,"---- %d.%d Klen=%d ilen=%d\n",
pdf->p_objn,pdf->p_genn,pdf->p_stdf.p_length,ilen);
*/
	bzero(&key,sizeof(key));
	RC4_set_key(&key,pdf->p_stdf.p_length/8+5,(unsigned char*)digest);
	RC4(&key,ilen,in,out);
	return 0;
}

static char *pfgets(char *str,int siz,FILE *in,int skipcom){
	char *sp;
	const char *sx;
	int ch;
	int inComment = 0;
	sp = str;
	sx = &str[siz-1];

	while( 1 ){
		if( sx <= sp )
			break;
		if( (ch = getc(in)) == EOF )
			break;
		if( ch == '\r' || ch == '\n' ){
			if( sp == str ){
				continue;
			}
			break;
		}
		*sp++ = ch; 
	}
	if( sp == str && ch == EOF )
		return 0;
	if( ch == '\r' ){
		ch = getc(in);
		if( ch != '\n' )
			ungetc(ch,in);
	}
	*sp = 0;
	return str;
}
static char *gettokens(Pdf *pdf){
	FILE *in = pdf->p_in;
	refQStr(sp,pdf->p_token);
	const char *sx;
	int ch;
	int inText = 0;
	int inEsc = 0;
	int inComment = 0;
	int inString = 0;

	sp = pdf->p_token;
	sx = &pdf->p_token[sizeof(pdf->p_token)-1];

	while( 1 ){
		if( sx <= sp )
			break;
		if( (ch = getc(in)) == EOF )
			break;

		if( inEsc == 0 ){
			if( inText ){
				if( ch == '(' ){
					inText++;
				}else
				if( ch == ')' ){
					inText--;
				}
			}else{
				if( ch == '(' ){
					inText++;
				}
			}
		}
		if( inEsc ){
			inEsc = 0;
		}else{
			if( ch == '\\' )
				inEsc = 1;
		}

		if( inText == 0 ){
			if( isspace(ch) ){
				if( pdf->p_token < sp )
					break;
				inComment = 0;
				continue;
			}
			if( ch == '%' ){
				inComment = 1;
				continue;
			}
		}
		if( !inComment ){
			/*
			if( inText && (ch <= 0x20 || 0x7F <= ch) ){
			if( VERBOSE
			*/
			if( inText && (ch < 0x20&&!isspace(ch) || 0x7F <= ch) ){
				setVStrPtrInc(sp,'\\');
				sprintf(sp,"%03o",ch);
				sp += 3;
			}else
/*
			if( inText && ch == 0 ){
				setVStrPtrInc(sp,'\\');
				sprintf(sp,"%03o",ch);
				sp += 3;
			}else
*/
			{
				setVStrPtrInc(sp,ch); 
			}
		}
	}

	truncVStr(sp);
	if( sp == pdf->p_token && ch == EOF )
		return 0;
	if( ch == '\r' ){
		ch = getc(in);
		if( ch != '\n' )
			ungetc(ch,in);
	}
	return pdf->p_token;
}

#define isOct(ch) \
	('0' <= ch && ch <= '8')
#define isHex(ch) \
	('0' <= ch && ch <= '9' || 'A' <= ch && ch <= 'F' || 'a'<=ch&&ch<='f')
#define toHex(ch) \
	(('0' <= ch && ch <= '9') ? ch-'0' : toupper(ch)-'A'+10)

static int scanesc(const char **spp){
	const char *sp;
	int ch;
	int xch;

	sp = *spp;
	if( sp[1] == 0 )
		return -1;
	sp++;
	ch = *sp;
	switch( ch ){
	    case 'n': xch = '\n'; break;
	    case 'r': xch = '\r'; break;
	    case 't': xch = '\t'; break;
	    case 'b': xch = '\b'; break;
	    case 'f': xch = '\f'; break;
	    case '(': xch = '('; break;
	    case ')': xch = ')'; break;
	    case '\\': xch = '\\'; break;
	    default:
		if( isOct(ch) && isOct(sp[1]) && isOct(sp[2]) ){
			xch = ((ch-'0')<<6) | ((sp[1]-'0')<<3) | (sp[2]-'0');
			sp += 2;
		}else{
			xch = ch;
		}
		break;
	}
	*spp = sp;
	return xch;
}

static int scanxstr(const char *str,PVStr(buf),int siz){
	const char *sp = str;
	int xch;
	refQStr(bp,buf);

	for(; isHex(*sp) && isHex(sp[1]); sp += 2 ){
		xch = (toHex(sp[0]) << 4) | toHex(sp[1]);
		setVStrPtrInc(bp,xch);
	}
	truncVStr(bp);
	return bp-buf;
}
static int scanstr(const char *str,PVStr(buf),int siz){
	const char *sp = str;
	const char *xp = &buf[siz-1];
	refQStr(bp,buf);
	int ch;

	for( sp = str;; sp++ ){
		if( xp <= bp )
			break;
		ch = *sp;
		if( ch == '\\' ){
			ch = scanesc(&sp);
			if( ch < 0 )
				break;
			setVStrPtrInc(bp,ch);
//fprintf(stderr,"A[%2d] %2o\n",bp-buf,0xFF&ch);
			continue;
		}
		if( ch == ')' )
			break;
		setVStrPtrInc(bp,ch);
//fprintf(stderr,"B[%2d] %2o\n",bp-buf,0xFF&ch);
	}
	truncVStr(bp);
	return bp - buf;
}
static void Putc(Pdf *pdf,int ch,FILE *fp){
//fprintf(stderr,"--Putc(%X)\n",ch);
	if( ch == 0 ){
		pdf->p_ignch++;
/*
fprintf(stderr,"------------------- \\0 ------------------\n");
exit(0);
*/
	}else
/*
	if( ch < 0x20 && !isspace(ch) && (pdf->p_pch & 0x80)==0 ){
		putc(' ',fp);
		pdf->p_ignch++;
	}else
*/
	{
		putc(ch,fp);
	}
	pdf->p_outch++;
	pdf->p_pch = ch;
}
static int dumpstr(Pdf *pdf,const char *str){
	const char *sp;
	const char *ep;
	int ch;
	int nc;
	int inString;
	FILE *out = pdf->p_out;
	int inText = 0;
	int first = 1;

	nc = 0;
	inString = 0;
/*
	const char *withTj = strstr(str,">Tj");
*/
	if( strstr(pdf->p_objsrc,"BT") ){
		fprintf(stderr,"%% %s\n",pdf->p_objsrc);
	}

	for( sp = str; ch = *sp; sp++ ){
		if( !inText ){
			/* "BT" */
			if( first && ch=='B' && sp[1]=='T' && isspace(sp[2]) ){
				inText = 1;
				sp += 2;
			}else{
				if( isspace(ch) )
					first = 1;
				else	first = 0;
			}
			continue;
		}else{
			/* "ET" */
			if( first && ch=='E' && sp[1]=='T' && isspace(sp[2]) ){
				inText = 0;
				sp += 2;
				first = 1;
				continue;
			}else{
				if( isspace(ch) ){
					if( first ){
						/* ignore contiguous space */
						continue;
					}
					first = 1;
				}else	first = 0;
			}
		}
		if( 0 < inString && ch == '\\' ){
			int xch;
			xch = scanesc(&sp);
			if( xch < 0 )
				goto pEOT;
//fprintf(stderr,"---A PUTC \\%X\n",ch);
			Putc(pdf,xch,out);
			continue;
		}
		if( ch == '(' ){
			/*
			if( inString == 0 ){
				Putc(pdf,' ',out);
			}
			*/
			inString++;
		}else
		if( ch == ')' ){
			inString--;
		}else
		if( 0 < inString ){
//fprintf(stderr,"---B PUTC \\%X\n",ch);
			Putc(pdf,ch,out);
			if( ch == '\r' || ch == '\n' )
				pdf->p_col = 0;
			else	pdf->p_col++;
			if( 70 < pdf->p_col && (ch == ' ' || ch == '\t') ){
				Putc(pdf,'\n',out);
				pdf->p_col = 0;
			}
		}else
		if( ch == '<' ){
			/*
			if( withTj ){
				if( withTj < sp ){
					withTj = strstr(sp,">Tj");
				}
			}
			if( withTj )
			*/
			{
				int nch = 0;
				int xch;
				for( sp++; isHex(*sp) && isHex(sp[1]); sp+=2 ){
				xch = (toHex(sp[0]) << 4) | toHex(sp[1]);
//fprintf(stderr,"---C PUTC \\%X\n",ch);
					Putc(pdf,xch,out);
					pdf->p_col++;
					nch++;
				}
			}
			/*
			if( 70 < pdf->p_col ){
				Putc(pdf,'\n',out);
				pdf->p_col = 0;
			}
			*/
		}
	}
pEOT:
	Putc(pdf,' ',out);
	return 0;
}
static int isDigits(const char *str){
	const char *sp;
	int ch;

	for( sp = str; ch = *sp; sp++ )
		if( !isdigit(ch) )
			return 0;
	return str < sp;
}

typedef int (*Pdffunc)(Pdf*);
static int findscanobj(Pdf *pdf,const char *pat,int gett,Pdffunc scan);
static int scantrailer(Pdf *pdf);
static int scanstdfilter(Pdf *pdf);
static int dumpStream(Pdf *pdf,int leng,const char *deflate){
	char inb[0x80000];
	int bi = 0;
	int ci;
	int co = 0;
	int ch;
	int olen;
	FILE *ifp = pdf->p_in;
	const char *token = pdf->p_token;
	const char *eos = "endstream";

	/*
	for( ci = 0; ci < leng; ci++ )
	*/
	for( ci = 0; ;ci++ ){
		ch = getc(ifp);
	getNEXT:
		if( ch == EOF ){
		fprintf(stderr,"--%d 0%o premature EOF in stream %d/%d\n",
			(int)ftell(ifp),(int)ftell(ifp),ci,leng);
			break;
		}
		if( ch == 'e' ){
			for( bi = 1; eos[bi]; bi++ ){
				ch = getc(ifp);
				if( ch == EOF )
					goto gotEOF;
				if( ch != eos[bi] ){
					if( bi+1 < sizeof(inb)-co ){
						bcopy(eos,inb+co,bi);
						co += bi;
					}
					goto getNEXT;
				}
			}
			if( 0 < co && leng < co && inb[co-1] == '\n' ){
				co--;
			}
			if( 0 < co && leng < co && inb[co-1] == '\r' ){
				co--;
			}
/*
fprintf(stderr,"--#%d endstream 0%o\n",pdf->p_objn,ftell(ifp));
*/
			strcpy(pdf->p_token,"endstream");
			break;
		}
		if( co < sizeof(inb) ){
			inb[co++] = ch;
		}
	} gotEOF:

	if( pdf->p_flags & P_SCANONLY ){
	}else
	if( strstr(pdf->p_objsrc,"/Predictor") ){
		/* not a text */
	}else
	if( deflate[0] == 0 ){
		inb[co] = 0;
if( strstr(inb,"BT ")||strstr(inb,"BT\r")||strstr(inb,"BT\n") )
		dumpstr(pdf,inb);
	}else{
		int osiz;
		char *outb;

		osiz = 128*1024+co*128;
		if( 64*1024*104 < osiz )
			osiz = 64*1024*1024;
		outb = (char*)malloc(osiz);

	RETRY:
		if( pdf->p_stdfilter ){
			unsigned char *xinb;
			xinb = (unsigned char*)malloc(co);
bzero(xinb,co);
			if( decryptObj(pdf,(unsigned char*)inb,co,xinb) == 0 ){
				olen = zlibUncompress(xinb,co,outb,osiz-1);
/*
unsigned char *i = (unsigned char *)inb;
unsigned char *o = (unsigned char *)xinb;
fprintf(stderr,
"---- DECRYPT and uncompress: %d.%d = %d [%X %X %X %X][%X %X %X %X]\n",
pdf->p_objn,pdf->p_genn,olen,
i[0],i[1],i[2],i[3],
o[0],o[1],o[2],o[3]
);
*/
			}else	olen = -1;
			free(xinb);
		}else{
			olen = zlibUncompress(inb,co,outb,osiz-1);
			if( olen < 0 ){
				if( pdf->p_id0len == 0 ){
/*
fprintf(stderr,"------------ FIND TRAILER ON DEMAND\n");
*/
				findscanobj(pdf,"trailer",0,scantrailer);
				}
				if( pdf->p_stdfilter == 0 ){
/*
fprintf(stderr,"------------ FIND FILTER ON DEMAND\n");
*/
				findscanobj(pdf,"/Standard",1,scanstdfilter);
				}
				if( pdf->p_stdfilter ){
/*
fprintf(stderr,"------------ RETRY DEFLATE off=%o\n",ftell(pdf->p_in));
*/
					goto RETRY;
				}
			}
		}

//fprintf(stderr,"--#%d deFlate %d -> %d\n",pdf->p_objn,co,olen);

/*
if( olen < 0 )
fprintf(stderr,"--%d F%d SDICT %s\n",(int)ftell(ifp),pdf->p_stdfilter,pdf->p_objsrc);
*/
if( olen < 0 ){
	fprintf(stderr,"\t--#%d %d %o deFlate %3d/%3d -> %d/%d deflate=[%s]\n",
	pdf->p_nobjs,(int)ftell(ifp),(int)ftell(ifp),
	co,leng,olen,osiz,deflate);
}

if( olen < 0 )
{
FILE *fp,*tmp;
fp = fopen("/tmp/px","w");
fwrite(inb,1,co,fp);
fclose(fp);
/*
fp = fopen("/tmp/px","r");
tmp = tmpfile();
olen = gunzipFilter(fp,tmp);
fprintf(stderr,"by gunzipFilter() -> %d\n",olen);
fclose(fp);
fclose(tmp);
*/
//if( pdf->p_stdfilter == 0 )
//sleep(2);
}

		if( 0 < olen ){
			outb[olen] = 0;
			if( pdf->p_dec ){
				fprintf(pdf->p_dec,
					"\n%%%% ## decoded %d -> %d\n",co,olen);
				fwrite(outb,1,olen,pdf->p_dec);
			}
			dumpstr(pdf,outb);
		}
		free(outb);
		if( olen < 0 ){
			if( (pdf->p_flags & P_IGNERROR) == 0 ){
fprintf(stderr,"\t---- ---- ---- DECODE ERROR ---- V%d R%d P%d L%d\n",
pdf->p_stdf.p_ver,
pdf->p_stdf.p_rev,
pdf->p_stdf.p_permit,
pdf->p_stdf.p_length
);
				return -1;
			}
		}
	}
	return 0;
}

static int scantrailer(Pdf *pdf){
	char line[1024];
	const char *sp;

	for(;;){
		if(pfgets(line,sizeof(line),pdf->p_in,0)==NULL)
			return -1;
if( pdf->p_flags & P_VERBOSE )
fprintf(stderr,"\t#trailer[%s]\n",line);
		if( strcmp(line,"%%EOF") == 0 )
			break;
		if( sp = strstr(line,"/P ") ){
		}
		if( sp = strstr(line,"/ID[<") ){
			pdf->p_id0len = scanxstr(sp+5,AVStr(pdf->p_id0),sizeof(pdf->p_id0));
fprintf(stderr,"\t##/ID len=%d %s\n",pdf->p_id0len,line);
		}
	}
	return 0;
}

static int scanstdfilter(Pdf *pdf){
	const char *sp;
	int olen,ulen;
	CStr(owner,64);
	CStr(user,64);
	int ver = 0;
	int rev = 0;
	int per = 0;
	int len = 0;

	pdf->p_stdfilter = 1;
	olen = 0;
	if( sp = strstr(pdf->p_objsrc,"/O") ){
		sp += 2;
		if( *sp == ' ' ) sp++;
		if( *sp == '(' )
		olen = scanstr(sp+1,AVStr(owner),sizeof(owner));
	}
	ulen = 0;
	if( sp = strstr(pdf->p_objsrc,"/U") ){
		sp += 2;
		if( *sp == ' ' ) sp++;
		if( *sp == '(' )
		ulen = scanstr(sp+1,AVStr(user),sizeof(user));
	}
	if( sp = strstr(pdf->p_objsrc,"/V") ){
		ver = atoi(sp+2);
	}
	if( sp = strstr(pdf->p_objsrc,"/R") ){
		rev = atoi(sp+2);
	}
	if( sp = strstr(pdf->p_objsrc,"/P") ){
		per = atoi(sp+2);
	}
	if( sp = strstr(pdf->p_objsrc,"/Length") ){
		len = atoi(sp+7);
	}

fprintf(stderr,
//"##STANDARD FILTER [%d.%d]# V%d R%d P%X L%d OWNER(%d) USER(%d) %s\n",
"\t##STANDARD FILTER [%d.%d]# V%d R%d P%X L%d OWNER(%d) USER(%d)\n",
pdf->p_objn,pdf->p_genn,ver,rev,per,len,olen,ulen,pdf->p_objsrc);

	if( pdf->p_id0len == 0 ){
		findscanobj(pdf,"trailer",0,scantrailer);
	}
	setupCrypt(pdf,ver,rev,per,len,owner,user);
	return 0;
}
static int getobj(Pdf *pdf){
	FILE *ifp = pdf->p_in;
	CStr(buff,1024);
	int off;
	int len;
	int rcc;
	int ci;

	off = ftell(ifp);

	truncVStr(pdf->p_objsrc);
	if( off < sizeof(buff) )
		len = off;
	else	len = sizeof(buff)-1;
	fseek(ifp,-len,1);
	rcc = fread(buff,1,QVSSize(buff,len),ifp);
	if( 0 < rcc ){
		buff[rcc] = 0;
		for( ci = rcc-1; 0 <= ci; ci-- ){
			if( buff[ci] == '<' ){
				strcpy(pdf->p_objsrc,buff+ci+1);
				break;
			}
		}
	}
	for(;;){
		if( gettokens(pdf) == NULL )
			break;
		strcat(pdf->p_objsrc," ");
		strcat(pdf->p_objsrc,pdf->p_token);
		if( strstr(pdf->p_token,"endobj") )
			break;
	}
	clearerr(ifp);
	fseek(ifp,off,0);
	return 0;
}
static int findscanobj(Pdf *pdf,const char *pat,int gett,Pdffunc scan){
	int off;
	int found = 0;
	int ch;
	int ti = 0;
	FILE *ifp = pdf->p_in;

	off = ftell(ifp);
	for(;;){
		ch = getc(ifp);
		if( ch == EOF )
			break;
		if( ch == pat[ti] ){
			ti++;
			if( pat[ti] == 0 ){
/*
fprintf(stderr,"\t-- %d found pat[%s]\n",ftell(ifp),pat);
*/
				if( scan != NULL ){
					if( gett ){
						CStr(p_sav,16*1024);
						CStr(p_savo,16*1024);
						strcpy(p_sav,pdf->p_token);
						strcpy(p_savo,pdf->p_objsrc);

						getobj(pdf);

/*
fprintf(stderr,"-------- %d found pat[%s][%s]\n",ftell(ifp),pat,pdf->p_objsrc);
*/

						(*scan)(pdf);

						strcpy(pdf->p_token,p_sav);
						strcpy(pdf->p_objsrc,p_savo);
					}else{
						(*scan)(pdf);
					}
				}
				found = 1;
				break;
			}
		}else{
			ti = 0;
		}
	}
	clearerr(ifp);
	fseek(ifp,off,0);
	return found;
}

static int iobj(Pdf *pdf){
	const char *token = pdf->p_token;
	const char *sp;
	CStr(deflate,1024);
	int leng;
	int Objn;

	if( gettokens(pdf) ==  0 ) /* object number */
		return -1;
	Objn = atoi(token);
	pdf->p_objn = atoi(token);

	if( pdf->p_dec ){
		fprintf(pdf->p_dec,"\n%%%% ## OBJ[%d] ## %d\n",
			pdf->p_nobjs,pdf->p_objn);
	}
gotTOKEN:
	if( pdf->p_flags & P_VERBOSE ){
		//fprintf(stderr,"--%d iobj#%d [%s]\n",
		fprintf(stderr,"\t--%d 0%o iobj[%d] #%d\n",
			(int)ftell(pdf->p_in),
			(int)ftell(pdf->p_in),
			pdf->p_nobjs,pdf->p_objn,token);
	}

	if( !isDigits(token) ){
		char line[1024];
		if( strcmp(token,"xref") == 0 ){
			int objn,lines,oi;

			if( pfgets(line,sizeof(line),pdf->p_in,1) == NULL ){
				return -1;
			}
//fprintf(stderr,"xref [%s]\n",line);
			if( sscanf(line,"%d %d",&objn,&lines) != 2 )
				return -1;
		gotXREF:
			for( oi = 0; oi < lines; oi++ ){
				if(pfgets(line,sizeof(line),pdf->p_in,1)==NULL)
					return -1;
if( pdf->p_flags & P_VERBOSE )
fprintf(stderr,"\txref #%d [%s]\n",oi,line);

			}
			if( gettokens(pdf) == NULL )
				return -1;
			if( isDigits(token) ){
				if( gettokens(pdf) == NULL )
					return -1;
				if( isDigits(token) ){
					lines = atoi(token);
//fprintf(stderr,"xref NEXT %d\n",lines);
					goto gotXREF;
				}else{
//fprintf(stderr,"xref ERROR[%s]\n",token);
					return -1;
				}
			}else{
//fprintf(stderr,"xref END %o [%s]\n",(int)ftell(pdf->p_in),token);
				goto gotTOKEN;
			}
		}
		if( strcmp(token,"trailer") == 0 ){
			scantrailer(pdf);
			return 0;
		}
		return -1;
	}

	gettokens(pdf); /* generation number */
	pdf->p_genn = atoi(token);

	gettokens(pdf); /* obj */
	truncVStr(deflate);
	leng = 0;
	pdf->p_objsrc[0] = 0;
	for(;;){
/*
		if( pdf->p_flags & P_VERBOSE )
			fprintf(stderr,"--- A %s\n",token);
*/

		if( strlen(pdf->p_objsrc)+strlen(token)+2<sizeof(pdf->p_objsrc) ){
			if( pdf->p_objsrc[0] )
			if( *token != '/' )
			if( *token != '(' )
			if( *token != '<' )
			if( *token != '>' )
				strcat(pdf->p_objsrc," ");
			strcat(pdf->p_objsrc,token);
			if( pdf->p_dec ){
				putc(' ',pdf->p_dec);
				fwrite(token,1,strlen(token),pdf->p_dec);
			}
		}
		if( strcmp(token,"endobj") == 0 ){
			break;
		}
		if( (sp = strstr(token,"endobj")) && sp[6]==0 ){
//fprintf(stderr,"--- ENDOBJ [%s]\n",token);
fprintf(stderr,"--- ENDOBJ\n",token);
			break;
		}
		if( sp = strstr(token,"/FlateDecode") ){
			strncpy(deflate,token,sizeof(deflate));
			if( strchr(deflate,'(') ){
				truncVStr(deflate);
			}
			if( strstr(deflate,"/FlateDecode") == NULL ){
/*
may be in (string /FlateDecode)
fprintf(stderr,"-- not /FlateDecode [%s]\n",token);
*/
				truncVStr(deflate);
			}
/*
fprintf(stderr,"-------- %s\n",deflate);
fprintf(stderr,"--#%d.%d deflate len=%d / %d\n",
pdf->p_objn,pdf->p_genn,strlen(deflate),strlen(token),deflate);
*/
		}
		if( (sp = strstr(token,"/Length")) && sp[7] == 0 ){
//fprintf(stderr,"--- B %s\n",token);
			gettokens(pdf);
			if( isDigits(token) ){
				leng = atoi(token);
//fprintf(stderr,"--- C leng=%d\n",leng,token);
/*
				gettokens(pdf);
				if( isDigits(token) ){
					int objn;
					objn = atoi(token);
					gettokens(pdf);
					if( strcmp(token,"R") == 0 ){
fprintf(stderr,"-----------> %d %d REFER\n",leng,objn);
					}
				}
*/
			}
			continue;
		}

		if( strcasecmp(token,"BT") == 0 ){
 fprintf(stderr,"%d BT\n",iftell(pdf->p_in));
		}
		if( strcasecmp(token,"ET") == 0 ){
 fprintf(stderr,"%d ET\n",iftell(pdf->p_in));
		}

		if( sp = strstr(token,"stream") ){
//fprintf(stderr,"----> %s\n",token);
			if( sp[6] == 0 ){
//fprintf(stderr,"====> %s\n",token);
/*
				fprintf(stderr,"stream BEGIN %d %s\n",
					leng,*deflate?"deflate":"");
*/
				if( dumpStream(pdf,leng,deflate) < 0 ){
					return -1;
				}
/*
				gettokens(pdf);
*/
				if( strcmp(token,"endstream") != 0 ){

//fprintf(stderr,"-- %d %o SCAN ERROR: %d %s\n",
fprintf(stderr,"-- %d %o SCAN ERROR: %d\n",
(int)ftell(pdf->p_in),
(int)ftell(pdf->p_in),
leng,token);
					break;
				}
			}
		}
/*
		if( pdf->p_token[0] == '(' ){
			fprintf(stderr,"%s ",pdf->p_token);
		}
*/
	getNEXT:
		if( gettokens(pdf) == NULL )
			break;
/*
fprintf(stderr,"--%d #%d GOT TOKEN [%s]\n",
	(int)ftell(pdf->p_in),pdf->p_nobjs,token);
*/
	}
	if( pdf->p_stdfilter == 0 ){
		if( strstr(pdf->p_objsrc,"/Filter") )
		if( strstr(pdf->p_objsrc,"/Standard") ){
			scanstdfilter(pdf);
		}
	}
	return 0;
}

static int header(Pdf *pdf){
	char line[1024];
	if( pfgets(line,sizeof(line),pdf->p_in,0) == NULL )
		return -1;
	pdf->p_header = strdup(line);
	if( pdf->p_dec ){
		fprintf(pdf->p_dec,"%s (%s)\n",line,
			pdf->p_inf?pdf->p_inf:"stdin");
	}
/*
if( pdf->p_flags & P_VERBOSE )
	fprintf(stderr,"HEAD: %s\n",line);
*/
	return 0;
}
