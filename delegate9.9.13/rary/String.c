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
Program:	strings.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	940821	extracted from DeleGate/src/misc.c
//////////////////////////////////////////////////////////////////////#*/
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include "ystring.h"
#include "log.h"

extern SStr(VStrUNKNOWN,1);
void Strins(PVStr(str),PCStr(ins));
void uvinit(UTag**,UTag*,int);

int isdigits(PCStr(str))
{	const char *sp;
	char ch;

	if( *str == 0 )
		return 0;

	for( sp = str; ch = *sp; sp++ )
		if( !isdigit(ch) )
			return 0;
	return 1;
}
int isdigit2(PCStr(str))
{
	return isdigit(str[0]) && isdigit(str[1]);
}
int Isalnum(int ch)
{
	return isalnum(ch);
}
const char *Isnumber(PCStr(str))
{
	if( (*str == '-' || *str == '+') && isdigit(str[1]) )
		str++;

	if( isdigit(*str) ){
		while( isdigit(*str) )
			str++;
		return str;
	}
	return 0;
}
FileSize kmxatoi(PCStr(ai))
{	const char *dp;
	FileSize n;

	if( dp = Isnumber(ai) ){
		n = atoi(ai);
		switch( *dp ){
			case 'k': case 'K': n *= 1024; break;
			case 'm': case 'M': n *= 1024 * 1024; break;
			case 'g': case 'G': n *= 1024 * 1024 * 1024; break;
		}
		return n;
	}
	return 0;
}


int strcaseeq(PCStr(a),PCStr(b))
{
	if( a == b )
		return 1;
	if( toupper(*a) != toupper(*b) )
		return 0;
	return strcasecmp(a,b) == 0;
}
int strncaseeq(PCStr(a),PCStr(b),int n)
{
	return strncasecmp(a,b,n) == 0;
}

char *strtoupperX(PCStr(s1),xPVStr(s2),int siz)
{	unsigned char ch;
	const char *xp;

	xp = s2 + (siz - 1);
	while( s2 < xp && (ch = *s1++) )
		setVStrPtrInc(s2,islower(ch) ? toupper(ch) : ch);
	setVStrPtrInc(s2,0);
	return (char*)s2;
}
char *strtolowerX(PCStr(s1),xPVStr(s2),int siz)
{	unsigned char ch;
	const char *xp;

	xp = s2 + (siz - 1);
	while( s2 < xp && (ch = *s1++) )
		setVStrPtrInc(s2,isupper(ch) ? tolower(ch) : ch);
	setVStrPtrInc(s2,0);
	return (char*)s2;
}
const char *skipspaces(PCStr(str))
{	const char *sp;
	char sc;

	for( sp = str; sc = *sp; sp++ )
		if( !isspace(sc) )
			break;
	return sp;
}
const char *nextword(PCStr(str))
{	const char *sp;
	char sc;

	for( sp = str; sc = *sp; sp++ )
		if( isspace(sc) )
			break;
	return skipspaces(sp);
}
int del8bits(PVStr(dst),PCStr(src))
{	const char *sp;
	refQStr(dp,dst); /**/
	char sc;

	for( sp = src; sc = *sp; sp++ ){
		assertVStr(dst,dp);
		if( (sc & 0x80) == 0 ){
			if( dp != sp )
				setVStrElem(dp,0,sc);
			dp++;
		}
	}
	if( dp != sp )
		setVStrEnd(dp,0);
	return sp - dp;
}
void strdelchr(PCStr(src),PVStr(dst),PCStr(del))
{	const char *sp;
	char sc;
	refQStr(dp,dst); /**/

	for( sp = src; sc = *sp; sp++ ){
		assertVStr(dst,dp+1);
		if( strchr(del,sc) == 0 ){
			if( dp == sp )
				dp++;
			else	setVStrPtrInc(dp,sc);
		}
	}
	if( dp != sp )
		setVStrEnd(dp,0);
}

int rexpmatchX(PCStr(rexp),PCStr(str),PCStr(ropts));
int rexpmatch(PCStr(rexp),PCStr(str))
{
	return rexpmatchX(rexp,str,"");
}
#define RX_IGNCASE	2
#define chrcaseeq(a,b)	((isupper(a)?tolower(a):a) == (isupper(b)?tolower(b):b))
int rexpmatchX(PCStr(rexp),PCStr(str),PCStr(ropts))
{	int topx;
	const char *sp;
	const char *tp;
	const char *rp;
	char sc,tc,rc;
	const char *op;
	int opts = 0;

	if( *rexp == '*' ){
		if( rexp[1] == 0 ) /* any string */
			return 1;
		rexp++;
		topx = 1;
	}else	topx = 0;

	for( op = ropts; *op; op++ ){
		switch( *op ){
			case 'c': opts |= RX_IGNCASE; break;
		}
	}

	sp = str;
	for(;;){
		tp = sp++; sc = *tp++;
		rp = rexp; rc = *rp++;
		/*
		while( sc == rc ){
		*/
		while( sc == rc
		 || (opts & RX_IGNCASE) && chrcaseeq(sc,rc)
		){
			if( rc == 0 ) /* exactly matched to the end */
				return 1;
			sc = *tp++;
			rc = *rp++;
		}
		if( rc == '*' ) /* remaining string matches with *  */
			return 1;
		if( sc == 0 ) /* pattern is longer than string */
			return 0;
		if( !topx )
			break;
	}
	return 0;
}

int RexpMatch(PCStr(str),PCStr(rexp))
{	const unsigned char *rp;
	const unsigned char *sp;
	unsigned char rch1,rch2,sch;
	int negate,match;

	sp = (unsigned char*)str;
	match = 1;
	for( rp = (unsigned char*)rexp; match && (rch1 = *rp); rp++ ){
		sch = *sp++;
		if( rch1 == '[' ){
			rch1 = *++rp;
			if( rch1 == '^' ){
				rp++;
				negate = 1;
				match = 1;
			}else{
				negate = 0;
				match = 0;
			}
			for(; rch1 = *rp; rp++ ){
				if( negate && match || !negate && !match ){
					if( rp[1] == '-' && rp[2] != 0 ){
						rp += 2;
						rch2 = *rp;
					}else	rch2 = rch1;
					match = (rch1 <= sch && sch <= rch2);
					if( negate )
						match = !match;
				}
				if( rch1 == ']' )
					break;
			}
		}else{
			match = (rch1 == sch);
		}
	}
	return match;
}

int vtos(char *av[],PVStr(abuf),int size)
{	int ac;
	refQStr(ap,abuf); /**/
	const char *a1;

	for(ac = 0; a1 = av[ac]; ac++){
		if( ac == 0 )
			strcpy(ap,a1);
		else{
			setVStrElem(ap,0,',');
			Xstrcpy(QVStr(ap+1,abuf),a1);
		}
		ap += strlen(ap);
	}
	setVStrEnd(ap,0);
	return ac;
}

char *strchrX(PCStr(str),int fch,PCStr(inc),PCStr(dec)){
	const char *sp;
	int lev = 0;
	int ch;

	for( sp = str; ch = *sp; sp++ ){
		if( ch==inc[0] || inc[1]&&ch==inc[1] || inc[2]&&ch==inc[2] ){
			lev++;
		}else
		if( ch==dec[0] || dec[1]&&ch==dec[1] || dec[2]&&ch==dec[2] ){
			if( 0 < lev )
				lev--;
		}else
		if( ch == fch ){
			if( lev == 0 ){
				return (char*)sp;
			}
		}
	}
	return NULL;
}

static char *xstrchr(PCStr(str),int del){
	const char *sp;
	int lev = 0;
	int ch;

	for( sp = str; ch = *sp; sp++ ){
		if( ch == '{' ){
			lev++;
		}else
		if( ch == '}' ){
			lev--;
		}else
		if( ch == del ){
			if( lev <= 0 ){
				return (char*)sp;
				/*
this code was introduced in 9.1.1 maybe to enable STLS="fsv:ftps,https"
which is expanded to CMAP="sslway:FSV:stattls//{ftps,https}" but this bug
disabled the bare protoList as CMAP="sslway:FSV:ftps,https".
				break;
				*/
			}
		}
	}
	return NULL;
}
int stoVX(PCStr(abuf),int mac,const char *av[],int sep,int depth);
int stoV(PCStr(abuf),int mac,const char *av[],int sep)
{
	return stoVX(abuf,mac,av,sep,0);
}
int stoVX(PCStr(abuf),int mac,const char *av[],int sep,int depth)
{	const char *ap; /* not "const" but fixed length */
	const char *np;
	int ac;

	ac = 0;
	for( ap = abuf; *ap; ap = np+1 ){
		av[ac++] = (char*)ap;
		if( mac <= ac )
			break;
		/*
		if( (np = strchr(ap,sep)) == 0 )
		*/
		if( depth )
			np = xstrchr(ap,sep);
		else	np = strchr(ap,sep);
		if( np == 0 )
			break;
		truncVStr(np);
	}
	if( ac < mac )
	av[ac] = 0;
	return ac;
}
char **Dupv_FL(FL_PAR_P, const char *const ev[]){
	int ei,en,sl;
	const char *e1;
	char *ea;
	defQStr(ep);
	char **ex;

	sl = 0;
	for( ei = 0; e1 = ev[ei]; ei++ ){
		sl += strlen(e1) + 1;
	}
	en = ei + 1;
	sl += en * sizeof(char*);
	ex = (char**)Xmalloc(FL_BAR_P,sl);
	setQStr(ep,(char*)&ex[en],sl);
	for( ei = 0; e1 = ev[ei]; ei++ ){
		ex[ei] = (char*)ep;
		strcpy(ep,e1);
		ep += strlen(ep) + 1;
	}
	for(; ei < en; ei++ ){
		ex[ei] = 0;
	}
	return ex;
}
const char **Xdupv(FL_PAR_P, const char*const*sv,int length)
{	int na,ai;
	char **dv;
	int len,lx;

	for( na = 0; sv[na]; na++)
		;
	dv = (char**)Xmalloc(FL_BAR_P, sizeof(char*)*(na+1));

	for( ai = 0; ai < na; ai++ ){
		if( length )
			len = length;
		else	len = strlen(sv[ai]) + 1;
		dv[ai] = (char*)Xmalloc(FL_BAR_P, len);
		for( lx = 0; lx < len; lx++ )
			dv[ai][lx] = sv[ai][lx];
	}
	dv[ai] = 0;
	return (const char**)dv;
}
void freev(char *sv[])
{	int vx;

	for( vx = 0; sv[vx]; vx++ )
		free(sv[vx]);
	free(sv);
}
int cmpv(const char *v1[],const char *v2[],int len)
{	int vx;
	const char *v1s;
	const char *v2s;

	for( vx = 0; ; vx++ ){
		v1s = v1[vx];
		v2s = v2[vx];

		if( v1s == 0 && v2s == 0 ) return 0;
		if( v1s == 0 || v2s == 0 ) return 1;
		if( len ){
			if( bcmp(v1s,v2s,len) != 0 )
				return 1;
		}else{
			if( strcmp(v1s,v2s) != 0 )
				return 1;
		}
	}
}
char *getvX(const char *av[],PCStr(name),int *ax);
char *getv(const char *av[],PCStr(name))
{
	return getvX(av,name,NULL);
}
char *getvX(const char *av[],PCStr(name),int *ax)
{	const char *val;
	const char *rval;
	int ai;
	int nlen;

	if( ax ) *ax = -1;
	if( av == 0 || name == 0 )
		return 0;

	nlen = strlen(name);
	rval = 0;
	for(ai = 0; val = av[ai]; ai++)
		if( *name == *val && strncmp(name,val,nlen) == 0 )
		if( val[nlen] == '=' )
		{
			rval = val+nlen+1;
			if( ax ) *ax = ai;
		}
	return (char*)rval;
}
int scanv(const char *av[],PCStr(name),iFUNCP func,void *arg1)
{	int ai;
	int nlen;
	const char *val;
	int nhit;

	nhit = 0;
	nlen = strlen(name);
	for( ai = 0; val = av[ai]; ai++ ){
		if( *name == *val && strncmp(name,val,nlen) == 0 )
		if( val[nlen] == '=' ){
			(*func)(arg1,val+nlen+1);
			nhit++;
		}
	}
	return nhit;
}

/*######DEBUG########*/
int StrBufDebug;

typedef struct strBuffer {
	struct strBuffer *sb_next;
	int	sb_size;
	int	sb_last;
	char   *sb_buff;
} StrBuffer;
static StrBuffer *STRBUFFST[8];

/*
 * buff address will be randmized by alloca() for randstack ...
 */
void *addStrBuffer_FL(FL_PAR_P, int lev,void *buff,int size)
{	StrBuffer *nsb;

	if( lMULTIST() ){
		return 0;
	}
	if( StrBufDebug == 0 ){
		const char *env;
		if( env = getenv("STRBUFDEBUG") ){
			StrBufDebug = atoi(env);
			if( StrBufDebug == 0 )
				StrBufDebug = 1;
		}else	StrBufDebug = -1;
	}
	/*
	nsb = (StrBuffer*)calloc(1,sizeof(StrBuffer));
	*/
	nsb = (StrBuffer*)Xcalloc(FL_BAR_P, 1,sizeof(StrBuffer));
	nsb->sb_size = size;
	nsb->sb_buff = (char*)buff;
	nsb->sb_last = 0;
	nsb->sb_next = STRBUFFST[lev];
	STRBUFFST[lev] = nsb;
	if( 0 < StrBufDebug ){
		fprintf(stderr,"#SB# [%d] bank=%X %X %d added.\n",
			lev,p2i(nsb),p2i(buff),size);
	}
	return nsb;
}
void delStrBuffer(int lev)
{	StrBuffer *sb;

	if( lMULTIST() ){
		return;
	}
	if( 0 < StrBufDebug ){
		sb = STRBUFFST[lev];
		fprintf(stderr,"#SB# [%d] bank=%X freed.\n",lev,p2i(sb));
		if( sb )
		free(sb);
	}
	STRBUFFST[lev] = NULL;
}
void freeStrBuffer(int lev,void *bp){
	if( lMULTIST() ){
		return;
	}
	if( STRBUFFST[lev] == bp ){
		STRBUFFST[lev] = 0;
		free(bp);
	}
}
char *getStrBuffer(int lev,int size,int al)
{	StrBuffer *sb;
	const char *sp;
	int last,rem,odd;
	unsigned long int top;

	if( lMULTIST() ){
		return 0;
	}
	if( lev == SB_HEAP )
		return NULL;

	for( sb = STRBUFFST[lev]; sb; sb = sb->sb_next ){
		last = sb->sb_last;
		top = (unsigned long int)&sb->sb_buff[last];
		if( odd = top % al )
			last += al - odd;
		rem = sb->sb_size - last;
		if( rem <= size )
			continue;

		sp = &sb->sb_buff[last];
		sb->sb_last = last + size;
		if( 1 < StrBufDebug ){
			fprintf(stderr,
				"#SS# [%d] bank=%X %X %X size=%4d last=%d/%d\n",
				lev,
				p2i(sb),p2i(sb->sb_buff),p2i(sp),size,sb->sb_last,sb->sb_size);
		}
		return (char*)sp;
	}
	return NULL;
}
#define PTRALIGN	(sizeof(char*) < 8 ? 8 : sizeof(char*))
int *StructAlloc(int size)
{	const char *sp;

	if( sp = getStrBuffer(1,size,PTRALIGN) ){
		bzero((char*)sp,size);
		return (int*)sp;
	}else	return (int*)Xcalloc(FL_ARG_r,1,size);
}
void PutEnv(PCStr(name),PCStr(value))
{	int len;
	const char *ep;

	len = strlen(name) + 1 + strlen(value) + 1;
	if( ep = getStrBuffer(1,len,1) ){

	}else	ep = (char*)Xmalloc(FL_ARG_r,len);
	Xsprintf(ZVStr((char*)ep,len),"%s=%s",name,value);
	putenv((char*)ep);
}
char *StrAlloc_FL(FL_PAR, PCStr(str))
{	const char *sp;

	if( *str == 0 )
		return (char*)""; /* will never be applied free() */
	if( sp = getStrBuffer(1,strlen(str)+1,1) ){
		return (char*)memcpy((char*)sp,str,strlen(str)+1);
	}
	sp = stralloc_FL(FL_BAR_r, str);
	return (char*)sp;
}
char *stralloc_FL(FL_PAR_P, PCStr(str))
{	const char *dp;
	int len = strlen(str);

	dp = (char*)Xmalloc(FL_BAR_P, len+1);
	if( dp == NULL ){
		syslog_ERROR("strdup(%d) failed,errno=%d\n",istrlen(str),errno);
		exit(1);
	}
	Xstrcpy(ZVStr((char*)dp,len+1),str);
	if( 2 < StrBufDebug )
		fprintf(stderr,"## %X strdup(%s)\n",p2i(dp),str);
	return (char*)dp;
}
void strfree_FL(FL_PAR, void *str)
{
	Xfree(FL_BAR, str);
}
char *Strdup_FL(FL_PAR, char **dst,PCStr(src))
{
	const char *ds;

	if( *dst == src )
		return *dst;
	if( ds = *dst ){
		if( strcmp(ds,src) == 0 ){
			return (char*)ds;
		}
		if( strlen(src) <= strlen(ds) ){
			Xstrcpy(ZVStr(ds,strlen(ds)+1),src);
			return (char*)ds;
		}
	}
	if( *dst != (char*)0 )
	{
		/* avoid *dst being referred during its Xfree(*dst), which
		 * could take long time for mutex (but anyway it might be
		 * under usage by other threads ...)
		Xfree(FL_BAR, *dst);
		 */
		char *odst = *dst;
		*dst = 0;
		Xfree(FL_BAR, odst);
	}

	*dst = stralloc_FL(FL_BAR_r,src);
	return *dst;
}
char *MallocX(FL_PAR, void *ptr,int size)
{	const char *nptr;

	if( ptr == NULL )
		nptr = (char*)Xmalloc(FL_BAR_r, size);
	else	nptr = (char*)Xrealloc(FL_BAR_r, ptr,size);
	/*
		nptr = (char*)malloc(size);
	else	nptr = (char*)realloc(ptr,size);
	*/
	if( nptr == NULL ){
		fprintf(stderr,"[%d] DeleGate: Malloc() failed\n",getpid());
		syslog_ERROR("Malloc(%d) failed,errno=%d\n",size,errno);
		exit(1);
	}
	return (char*)nptr;
}



char *strncpy0(PVStr(d),PCStr(s),int len)
{
	strncpy(d,s,len);
	setVStrEnd(d,len);
	return (char*)d;
}

int strtailchr(PCStr(str))
{
	if( *str == 0 )
		return 0;
	else	return str[strlen(str)-1];
}

char *strtailstrX(PCStr(str1),PCStr(str2),int igncase);
char *strtailstr(PCStr(str1),PCStr(str2))
{
	return strtailstrX(str1,str2,0);
}
char *strtailstrX(PCStr(str1),PCStr(str2),int igncase)
{	const char *s1;
	const char *s2;

	for( s1 = str1; *s1 && s1[1]; s1++ );
	for( s2 = str2; *s2 && s2[1]; s2++ );

	if( *s2 == 0 ){
		if( *s1 == 0 )
			return (char*)s1;
		else	return (char*)s1 + 1;
	}

	for(;;){
		/*
		if( *s1 != *s2  ) return 0;
		*/
		if( *s1 != *s2  ){
			if( !igncase ) return 0;
			if( !chrcaseeq(*s1,*s2) ) return 0;
		}
		if( s2 == str2 )
			return (char*)s1;
		s2--;
		if( s1 == str1 ) return 0;
		s1--;
	}
}
const char *strheadstrX(PCStr(str1),PCStr(str2),int igncase){
	const char *s1,*s2;

	if( *str2 == 0 )
		return str1;
	s1 = str1;
	s2 = str2;
	while( *s1 == *s2 || igncase && chrcaseeq(*s1,*s2) ){
		s1++;
		s2++;
		if( *s2 == 0 ) return s1;
	}
	return 0;
}

const char *awordscanX(PCStr(str),PVStr(word),int size)
{	const char *sp;
	refQStr(wp,word); /**/
	unsigned char ch;
	const char *ox;

	ox = word + (size - 1);
	for(sp = str; wp < ox && (ch = *sp); sp++){
		if( !isalpha(ch) )
			break;
		setVStrPtrInc(wp,ch);
	}
	setVStrEnd(wp,0);
	return sp;
}

const char *scanint(PCStr(str),int *valp)
{	const char *sp;
	unsigned char ch;
	int val;

	val = 0;
	for( sp = str; ch = *sp; sp++ ){
		if( !isdigit(ch) )
			break;
		val = val*10 + (ch-'0');
	}
	*valp = val;
	return sp;
}
char *wordscanX(PCStr(s),xPVStr(d),int size)
{	int cc,ch;

	for(; ch = *s; s++){
		if( ch!=' ' && ch!='\t' && ch!='\r' && ch!='\n' && ch!='\f' )
			break;
	}
	for(cc = 1; (size == 0 || cc < size) && (ch = *s); cc++,s++){
		if( ch==' ' || ch=='\t' || ch=='\r' || ch=='\n' || ch=='\f' )
			break;
		setVStrPtrInc(d,ch);
	} 
	setVStrEnd(d,0);

#ifdef WITH_QVSTR
	if( *s != 0 )
	if( UTail(d) <= d ){
		VStr_overflow("wordscanX",BVStr(d),cc,size,"");
	}
#endif
	return (char*)s;
}
char *linescanX(PCStr(s),xPVStr(d),int size)
{	int cc,ch;

	for(; ch = *s; s++){
	/* if( ch!=' ' && ch!='\t' && ch!='\r' && ch!='\n' && ch!='\f' ) */
		if( ch!=' ' && ch!='\t' )
			break;
	}
	for(cc = 1; (cc < size) && (ch = *s); cc++,s++){
		if( ch=='\n' || ch=='\r' && (s[1]=='\n' || s[1]==0) )
			break;
		setVStrPtrInc(d,ch);
	} 
	setVStrEnd(d,0);
	return (char*)s;
}
char *sgetsX(PCStr(src),PVStr(line),int cr,int lf){
	const char *sp;
	char sc;
	refQStr(op,line);
	for( sp = src; sc = *sp; sp++ ){
		if( sc == '\r' ){
			if( cr ) setVStrPtrInc(op,sc);
			continue;
		}
		if( sc == '\n' ){
			if( lf ) setVStrPtrInc(op,sc);
			sp++;
			break;
		}
		setVStrPtrInc(op,sc);
	}
	setVStrEnd(op,0);
	return (char*)sp;
}

char *wordscanY(PCStr(str),PVStr(val),int siz,PCStr(pat))
{	refQStr(vp,val); /**/
	const char *xp = val + (siz - 1);
	char ch;
	const char *sp;
	int Not = 0;

	if( pat && *pat == '^' ){
		pat++;
		Not = 1;
	}
	for( sp = str; vp < xp && (ch = *sp); sp++ ){
		if( pat ){
			if( !Not ){
				if( strchr(pat,ch) == NULL )
					break;
			}else{
				if( strchr(pat,ch) != NULL )
					break;
			}
		}
		setVStrPtrInc(vp,ch);
	}
	setVStrEnd(vp,0);

#ifdef WITH_QVSTR
	if( UTail(val) <= vp || siz-1 <= vp-val ){
		VStr_overflow("wordscanY",BVStr(val),vp-val,siz,"");
	}
#endif
	return (char*)sp;
}
char *valuescanX(PCStr(str),PVStr(val),int siz)
{
	if( *str == '"' )
		return wordscanY(str+1,BVStr(val),siz,"^\"");
	else	return wordscanY(str,BVStr(val),siz,"^; \t\r\n>\"");
}
char *valuescanY(PCStr(str),PVStr(val),int siz){
	if( *str == '\'' )
		return wordscanY(str+1,BVStr(val),siz,"^'");
	else	return valuescanX(str,BVStr(val),siz);
}
char *numscanX(PCStr(str),xPVStr(val),int siz)
{
	if( *str == '-' ){
		setVStrPtrInc(val,*str++);
		siz--;
	}
	return wordscanY(str,BVStr(val),siz,".0123456789");
}

void scanwords(PCStr(sp),int wc,const char *words[])
{	int wi;
	unsigned char ch;

	for( wi = 0; wi < wc; wi++ ){
		for(; ch = *sp; sp++ )
			if( !isspace(ch) )
				break;
		words[wi] = (char*)sp;

		for(; ch = *sp; sp++ ){
			if( isspace(ch) ){
				*(char*)sp++ = 0; /* not "const" but fixed */
				break;
			}
		}
	}
}

#define STR_VOLA        0
#define STR_ALLOC       1
#define STR_OVWR        2
#define STR_RO		4	/* dont set NULL on the delimiter */

#if 0
static const char *SLNEP; /* Next Element Pointer for scan_List() callback */
#endif
/* 9.8.2 to let SLNEP be multi-threads safe */
typedef struct {
	const char  *sl_SLNEPb;
	const char **sl_SLNEPp;
} SLArg;
#define SLAC const char *SLNEPb = 0,**SLNEPp = &SLNEPb
#define SLAP const char **SLNEPp
#define SLAA &SLNEPb
#define SLAB SLNEPp
#define SLNEP *SLNEPp

int scan_ListX(PCStr(a_list),int sep,int allocm,SLAP,scanListFuncP func, ...);
int scan_List(PCStr(a_list),int sep,int allocm,scanListFuncP func, ...)
{
	int rcode;
	VARGS(16,func);
	rcode = scan_ListX(a_list,sep,allocm,0,func,VA16);
	return rcode;
}
int scan_ListX(PCStr(a_list),int sep,int allocm,SLAP,scanListFuncP func, ...)
{	const char *list = a_list; /* destroying "const" with OVWR ... */
	const char *lp;
	const char *alist;
	const char *np; /* not "const" but fixed */
	int rcode;
	int lev;
	int cch,nch,pch;
	int nelm;
	IStr(lbuf,1024);
	int care_quote = 0;
	int in_quote = 0;
	VARGS(16,func);

	if( list == 0 || *list == 0 )
		return 0;

	if( care_quote = (allocm & STR_QUOTE) ){
		allocm &= ~STR_QUOTE;
	}

	nelm = 0;
	alist = list;
	/*
	if( allocm != STR_OVWR )
	*/
	if( (allocm & STR_OVWR) == 0 )
		if( (allocm & STR_ALLOC)==0 && strlen(list) < sizeof(lbuf)-1 ){
			strcpy(lbuf,list);
			list = lbuf;
		}else
		list = stralloc_FL(FL_ARG,(allocm&STR_ALLOC)!=0, list);

	for( lp = list; *lp; lp = np ){
		int npa;
		npa = 0;
		lev = 0;
		nch = 0;
		for( np = (char*)lp; cch = *np; ){
			if( care_quote && in_quote != 0 ){
				if( cch == in_quote ){
					in_quote = 0;
				}
				np++;
			}else
			if( care_quote && in_quote == 0 && cch == '"' ){
				in_quote = cch;
				np++;
			}else
			if( cch == '\\' ){
				nch = np[1];
				if( nch == sep || nch == '{' || nch == '}' )
					ovstrcpy((char*)np,np+1);
				np++;
			}else
			if( cch == '{' ){
				np++;
				lev++;
			}else
			if( cch == '}' ){
				lev--;
				if( lev == 0 && *lp == '{'
				 && npa++ == 0 /* not {L1}@{L2} */
				 && (np[1] == sep || np[1] == 0) ){
					lp++;
					if( (allocm & STR_RO) == 0 )
					truncVStr(np); np++;
				}else	np++;
			}else
			if( lev == 0 && cch == sep ){
				if( (allocm & STR_RO) == 0 )
				truncVStr(np); np++;
				break;
			}else{
				np++;
			}
		}
		nelm++;
		if( SLNEPp == 0 ){
		}else
		if( cch == 0 )
			SLNEP = 0;
		else
		if( list != alist && allocm == STR_VOLA ){
			/* 9.8.2 must point into non-volatile area */
			SLNEP = alist + (np-list);
		}else
		SLNEP = np;
		if( func != 0 )
		{
			if( SLNEPp ){
				rcode = (*func)(lp,SLAB,VA16);
			}else{
				rcode = (*func)(lp,VA16);
			}
			if( rcode ){
if( list != alist && allocm != STR_ALLOC )
if( list != lbuf )
porting_dbg("scan_List SLNEP: MUST FREE %X: %s",p2i(list),a_list);
				/* must free the list before return ?? */
				return rcode;
			}
		/*
		if( rcode = (*func)(lp,VA16) )
			return rcode;
		*/
		}

		if( np == 0 )
			break;
	}
	if( list != alist && allocm != STR_ALLOC )
	{
		if( list == lbuf ){
		}else
		free((char*)list);
	}
	if( func == 0 )
		return nelm;
	return 0;
}

#ifdef MAIN
static pr1(PCStr(s)){
	printf("[%s] ",s);
	return 0;
}
static prs(PCStr(s)){
	printf("##[ %-25s] ",s);
	scan_commaList(s,0,pr1);
	printf("\n");
}
main(){
	prs("a,b,c,d");
	prs("{a,b,c,d}");
	prs("{{a,b,c}}");
	prs("{a,b},{c,d}");
	prs("a@{c,d}");
	prs("{a,b}@c");
	prs("{a,b}@{c,d}");
	prs("{a,b}@{c,d},e,f");
	prs("{a,b}@{c,d},{e,f},g,h");
}
#endif

int num_ListElems(PCStr(list),int sep)
{
	return scan_List(list,sep,0,(scanListFuncP)0);
}
int scan_ListLX(PCStr(list),int sep,int allocm,SLAP,scanListFuncP func, ...);
int scan_ListL(PCStr(list),int sep,int allocm,scanListFuncP func, ...)
{
	VARGS(16,func);
	return scan_ListLX(list,sep,allocm,0,func,VA16);
}
int scan_ListLX(PCStr(list),int sep,int allocm,SLAP,scanListFuncP func, ...)
{	int rcode;
	const char *tp;
	VARGS(16,func);

	/*
	if( *list == '{' && (tp = strchr(list,'}')) && tp[1] == 0 ){
	*/
	if( *list == '{' ){
	  if( tp = strchr(list,'}') ){
	    if( tp[1] == 0 ){
		*(char*)tp = 0;
		/*
		rcode = scan_List(list+1,sep,allocm,func,VA16);
		*/
		rcode = scan_ListX(list+1,sep,allocm,SLAB,func,VA16);
		*(char*)tp = '}';
		return rcode;
	    }
	  }else{
		syslog_ERROR("ERROR: IGNORE unbalanced '{': %s\n",list);
		list += 1;
	  }
	}
	/*
	return scan_List(list,sep,allocm,func,VA16);
	*/
	return scan_ListX(list,sep,allocm,SLAB,func,VA16);
}
/*
static scanListFunc list1(PCStr(l1),int *ac,QPtr qv[],int mac)
*/
static scanListFunc list1(PCStr(l1),SLAP,int *ac,QPtr qv[],int mac)
{
	if( mac <= *ac )
		return -1;

	if( qv[*ac].q )
	Xstrcpy(BVStr(qv[*ac].q),l1);
	*ac += 1;
	if( *ac == mac && SLNEP ){
		/* leave SLNEP set after exit from scan_List() */
		return -1;
	}
	return 0;
}
int scan_Listlist(PCStr(list),int sep,PVStr(e1),PVStr(e2),PVStr(e3),PVStr(e4),PVStr(e5))
{	int mac,ac;
	QPtr qv[8]; /**/
	SLAC;

	if( e2 == 0 ) mac = 1; else
	if( e3 == 0 ) mac = 2; else
	if( e4 == 0 ) mac = 3; else
	if( e5 == 0 ) mac = 4; else
		      mac = 5;
	if( 0 < mac ) cpyQPtr(qv[0],e1);
	if( 1 < mac ) cpyQPtr(qv[1],e2);
	if( 2 < mac ) cpyQPtr(qv[2],e3);
	if( 3 < mac ) cpyQPtr(qv[3],e4);
	if( 4 < mac ) cpyQPtr(qv[4],e5);

	ac = 0;
	/*
	scan_List(list,sep,0,scanListCall list1,&ac,qv,mac);
	*/
	scan_ListX(list,sep,0,SLAA,scanListCall list1,&ac,qv,mac);

	/* let the last element contain all remainings
	 * like "A:B:C:D:E"/3 -> [A][B][C:D:E] */
	if( ac == mac )
	if( SLNEP ){
		QPtr qp = qv[mac-1];
		Xsprintf(TVStr(qp.q),"%c%s",sep,SLNEP);
	}
	return ac;
}
char *scan_ListElem1(PCStr(list),int sep,PVStr(e1)){
	int mac,ac;
	const char *next;
	QPtr qv[1];
	SLAC;

	cpyQPtr(qv[0],e1);
	ac = 0;
	mac = 1;
	/*
	scan_List(list,sep,0,scanListCall list1,&ac,qv,mac);
	*/
	scan_ListX(list,sep,0,SLAA,scanListCall list1,&ac,qv,mac);
	if( SLNEP )
		next = SLNEP;
	else	next = list+strlen(list);
	return (char*)next;
}
int scan_commaList(PCStr(list),int allocm,scanListFuncP func,...)
{	VARGS(16,func);
	return scan_List(list,',',allocm,func,VA16);
}
int scan_commaListL(PCStr(list),int allocm,scanListFuncP func,...)
{	VARGS(16,func);
	return scan_ListL(list,',',allocm,func,VA16);
}

void strsubst(PVStr(str),PCStr(pat),PCStr(subs))
{	refQStr(dp,str); /**/
/*
	CStr(tmp,1024);
*/
	CStr(tmp,0x10000);
	const char *sp;

	if( *pat == 0 ){
		syslog_ERROR("WARNING: strsubst() empty pattern\n");
		Strins(BVStr(str),subs);
		return;
	}
	sp = str;
	while( dp = strstr(sp,pat) ){
		strcpy(tmp,dp+strlen(pat));
		strcpy(dp,subs); dp += strlen(dp); strcpy(dp,tmp);
		sp = dp;
	}
}
void onoff_flags(PVStr(flags),PCStr(delta),int on)
{	CStr(map,256); /* non-var */
	UrefQStr(fp,flags);
	int mi;

	for( mi = 1; mi < 256; mi++ )
		setVStrEnd(map,mi);

	for( UcpyQStr(fp,flags); *fp; fp++ )
		setVStrElem(map,*fp,on);
	for( fp = (unsigned char*)delta; *fp; fp++ )
		setVStrElem(map,*fp,on);

	UcpyQStr(fp,flags);
	for( mi = 1; mi < 256; mi++ )
		if( map[mi] )
			setVStrPtrInc(fp,mi);
	setVStrEnd(fp,0);
}

int numscan(const char **spp)
{	const char *sp;
	char sc;
	int sign,width;

	sp = *spp;
	sc = *sp;
	if( sc == '-' ){
		sign = -1;
		sc = *++sp;
	}else	sign = 1;

	width = 0;
	while( '0' <= sc && sc <= '9' ){
		width = (width * 10) + (sc - '0');
		sc = *++sp;
	}

	*spp = sp;
	return sign*width;
}

#ifndef ovstrcpy
char *ovstrcpy(char s1[],PCStr(s2))
{	char *dp; /* ovstrcpy(dst) */

	dp = s1;
	while( 1 )
		if( (*dp++ = *s2++) == 0 )
			break;
	/*
	*dp = 0;
	*/
	return s1;
}
#endif

/*
 *	s1 will be zero terminated, without padded, with max. length n-1.
 */
#ifndef WITH_QVSTR
char *Strncpy(char dst[],PCStr(src),int n)
{	char *dp; /* Strncpy(dst) must be PVStr */

	dp = dst;
	while( 1 < n-- ){
		if( (*dp++ = *src++) == 0 )
			break;
	}
	*dp = 0;
	return dst;
}
#endif

void Strins(PVStr(str),PCStr(ins))
{
	Strrplc(BVStr(str),0,ins);
}

unsigned int FQDN_hash(PCStr(key))
{       const unsigned char *ks;
        unsigned int kc,kx,ky;

        kx = 0;
        for( ks = (unsigned char*)key; kc = *ks++; ){
		ky = (kx >> 27) & 0x1F;
                kx = ((kx << 5) | ky) ^ kc;
	}
        return kx;
}

double Scan_period(PCStr(period),int dfltunit,double dflt)
{	double num,clock;
	char unit;

	if( period == 0 || period[0] == 0 )
		return dflt;
	num = 0;
	unit = dfltunit;
	sscanf(period,"%lf%c",&num,&unit);

	switch( unit ){
		default:
		case 'w': clock = num*24*60*60*7; break;
		case 'd': clock = num*24*60*60; break;
		case 'h': clock = num*60*60; break;
		case 'm': clock = num*60; break;
		case 's': clock = num; break;
	}
	if( clock < 0 ) clock = 0;
	return clock;
}
int scan_period(PCStr(period),int dfltunit,int dflt)
{
	return (int)Scan_period(period,dfltunit,(double)dflt);
}

char *strrpbrk(PCStr(str),PCStr(brk))
{	char ch;
	const char *tp;
	const char *dp;

	if( brk[0] == 0 )
		return (char*)str;
	if( str[0] == 0 )
		return 0;

	tp = 0;
	for( dp = str; ch = *dp; dp++ )
		if( strchr(brk,ch) )
			tp = dp;
	return (char*)tp; /* the last match */
}

char *strip_spaces(PCStr(value))
{	const char *vp;
	const char *tp;

	for( vp = value; *vp == ' ' || *vp == '\t'; vp++)
		;
	for( tp = vp; *tp; tp++ )
		;
	while( vp < tp && tp[-1] == ' ' )
		tp--;
	*(char*)tp = 0; /* not "const" but fixed length */
	return (char*)vp;
}

/*
 *	case sensitive when a capital character is in "elem"
 */
typedef struct {
	iFUNCP	 l_logfunc;
	void	*l_logfile;
	int	 l_top;
	int	 l_bottom;
	int	 l_nextch;
	int	 l_negate;
	int	 l_seecase;
} LMarg;

static scanListFunc strmatch1(PCStr(pattern),PCStr(target),int *matches,LMarg *lma)
{	int negate,seecase,top,btm,nextch;
	const char *match;
	const char *pat0;
	CStr(pat1,256);
	refQStr(pp,pat1); /**/
	const char *px = &pat1[sizeof(pat1)-1];
	const char *sp;
	char sc;
	int plen;

	negate  = lma->l_negate;
	seecase = lma->l_seecase;
	top     = lma->l_top;
	btm     = lma->l_bottom;
	nextch  = lma->l_nextch;

	for( sp = pat0 = strip_spaces(pattern); sc = *sp; sp++ ){
		if( px <= pp )
			break;
		if( sc == '!' && sp == pat0 ){ negate = 1; }else
		if( sc == '*' && pp == pat1 ){ top = 0; }else
		if( sc == '^' && pp == pat1 ){ top = 1; }else
		if( sc == '*' && sp[1] == 0 ){ btm = 0; nextch = 0; }else
		if( sc == '$' && sp[1] == 0 ){ btm = 1; }else
			setVStrPtrInc(pp,sc);
	}
	XsetVStrEnd(AVStr(pp),0);
	plen = pp - pat1;

	for( pp = pat1; *pp; pp++ ){
		if( isupper(*pp) ){
			seecase = 1;
			break;
		}
	}

	if( seecase )
		match = strstr(target,pat1);
	else	match = strcasestr(target,pat1);

	if( match ){
		if( top && match != target )
			match = 0;
		if( btm && target[plen] != 0 )
			match = 0;
		if( nextch && target[plen] != nextch )
			match = 0;
	}

	if( match ){
		if( negate )
			*matches = 0;
		else	*matches = 1;
	}

EXIT:
	if( lma->l_logfunc )
		(*lma->l_logfunc)(lma->l_logfile,
			"allow = %d <-- [%s] / [%s] \r\n",*matches,target,pat0);
	return 0;
}

int strmatch_list(PCStr(str),PCStr(list),PCStr(cntrl),iFUNCP lfunc,void *lfile)
{	int matches;
	/*
	CStr(buff,1024);
	*/
	CStr(buffb,1024);
	refQStr(buff,buffb);
	LMarg lma;
	char tch;

	lma.l_logfunc = lfunc;
	lma.l_logfile = lfile;
	lma.l_negate = 0;
	lma.l_seecase = 0;
	lma.l_top = cntrl[0] == '^';
	tch = strtailchr(cntrl);
	lma.l_bottom = tch == '$';
	lma.l_nextch = tch != '^' ? tch : 0;

	if( strlen(list) < sizeof(buffb) ){
		setQStr(buff,buffb,sizeof(buffb));
	strcpy(buff,list);
	}else{
		setQStr(buff,stralloc(list),strlen(list)+1);
	}
	if( *buff == '!' )
		matches = 1;
	else	matches = 0;
	scan_commaList(buff,0,scanListCall strmatch1,str,&matches,&lma);
	if( buff != buffb ){
		free((char*)buff);
	}
	return matches;
}

char *strcats3(PVStr(dst),PCStr(s0),PCStr(s1),PCStr(s2))
{	const char *sv[4]; /**/
	const char *sp;
	char sc;
	refQStr(dp,dst); /**/
	int si;

	sv[0] = s0;
	sv[1] = s1;
	sv[2] = s2;
	sv[3] = 0;

	for( cpyQStr(dp,dst); *dp; dp++ )
		;

	for( si = 0; sp = sv[si]; si++ ){
		assertVStr(dst,dp);
		while( sc = *sp++ )
			setVStrPtrInc(dp,sc);
	}
	setVStrEnd(dp,0);
	return (char*)dp;
}



static scanListFunc subSetList2(PCStr(s1),PCStr(s2))
{
	return strcmp(s1,s2) == 0;
}
static scanListFunc subSetList1(PCStr(s1),PCStr(s2),char **sbp,PVStr(sb))
{
	if( scan_commaListL(s2,STR_VOLA,scanListCall subSetList2,s1) == 0 ){
		Xstrcpy(QVStr(*sbp,sb),s1);
		Xstrcat(QVStr(*sbp,sb),",");
		*sbp += strlen(s1) + 1;
	}
	return 0;
}
void subSetList(PCStr(s1),PCStr(s2),PVStr(sb))
{
	setVStrEnd(sb,0);
	scan_commaListL(s1,STR_VOLA,scanListCall subSetList1,s2,&sb,BVStr(sb));
	if( *sb )
		setVStrEnd(sb,strlen(sb)-1);
}

static scanListFunc strmatch(PCStr(s1),PCStr(s2)){ return strcmp(s1,s2) == 0; }
int wordIsinList(PCStr(list),PCStr(word))
{
	if( scan_commaListL(list,0,scanListCall strmatch,word) )
		return 1;
	return 0;
}

static scanListFunc strmatch2(PCStr(s1),PCStr(s2),int *nth)
{
	*nth += 1;
	if( *s2 != ' ' && *s2 != '\t' ){
		while( *s1 == ' ' || *s1 == '\t' )
			s1++;
	}
	return strcmp(s1,s2) == 0;
}
int isinList(PCStr(list),PCStr(word))
{	int nth;

	nth = 0;
	if( scan_commaListL(list,0,scanListCall strmatch2,word,&nth) )
		return nth;
	return 0;
}

#define SM_IGNWHITE	1 /* 'w' */
#define SM_IGNCASE	2 /* 'c' */
#define SM_SUBSTR	4 /* 's' */
#define SM_HEAD		0x08 /* 'h' */
#define SM_TAIL		0x10 /* 't' */
#define SM_HEADX	0x20 /* 'H' */
#define SM_VISUAL	0x40 /* 'v' for "\n\r\s\t" */
#define SM_OFFSETOF	0x80 /* 'o' return the offset of matched string */
#define SM_DEBUGx	0x8000 /* 'D' */

/*
int vstrncmp(PCStr(s1),PCStr(s2),int len,int optm){
	int c1,c2;

	while( (c1 = *s1++) && (c2 = *s2++) ){
		if( c1 == c2 ){
			continue;
		}
		if( c1 == '\\' ){
			if( *s1 == 'n' && c2 == '\n'
			 || *s1 == 'r' && c2 == '\r'
			 || *s1 == 's' && c2 ==  ' '
			 || *s1 == 't' && c2 == '\t'
			){
				s1++;
				continue;
			}
		}
		break;
	}
	return *s2 - *s1;
}
*/

static scanListFunc sm2X(PCStr(s1),PCStr(s2),int *nth,int optm,int *match){
	*nth += 1;

	if( optm & SM_IGNWHITE ){
		if( *s2 != ' ' && *s2 != '\t' ){
			while( *s1 == ' ' || *s1 == '\t' )
				s1++;
		}
	}
	if( optm & SM_HEADX ){
		int len2 = strlen(s2);
		if( optm & SM_IGNCASE )
			*match |= strncasecmp(s1,s2,len2) == 0 ? SM_HEADX:0;
		else	*match |=     strncmp(s1,s2,len2) == 0 ? SM_HEADX:0;
	}
	if( optm & SM_HEAD ){
		if( optm & SM_IGNCASE )
			*match |= strncasecmp(s2,s1,strlen(s1)) == 0;
		else	*match |= strncmp(s2,s1,strlen(s1)) == 0;
	}else
	if( optm & SM_TAIL ){
		if( optm & SM_IGNCASE )
			/*
			*match |= strcasetailstr(s2,s1) != 0;
			*/
			*match |= strtailstr(s2,s1) != 0;
		else	*match |= strtailstr(s2,s1) != 0;
	}else
	if( optm & SM_SUBSTR ){
		if( optm & SM_IGNCASE )
			*match |= strcasestr(s2,s1) != 0;
		else	*match |= strstr(s2,s1) != 0;
	}else
	if( optm & SM_IGNCASE )
		*match |= strcasecmp(s1,s2) == 0;
	else	*match |= strcmp(s1,s2) == 0;
	if( optm & SM_OFFSETOF ){
		if( *match ){
			*(const char**)match = s1;
			return 1;
		}
	}
	return 0;
}
int isinListX(PCStr(list),PCStr(word),PCStr(sopts)){
	int nth = 0;
	int optm = 0;
	int match = 0;
	int del = ',';

	for(; *sopts; sopts++ ){
		if( *sopts == 'c' ) optm |= SM_IGNCASE;
		if( *sopts == 'w' ) optm |= SM_IGNWHITE;
		if( *sopts == 's' ) optm |= SM_SUBSTR;
		if( *sopts == 'h' ) optm |= SM_HEAD;
		if( *sopts == 't' ) optm |= SM_TAIL;
		if( *sopts == 'v' ) optm |= SM_VISUAL;
		if( *sopts == 'H' ) optm |= SM_HEADX;
		if( *sopts == 'D' ) optm |= SM_DEBUGx;
		if( *sopts == 'o' ) optm |= SM_OFFSETOF;
		if( strchr("+,./:;&|",*sopts) ) del = *sopts;
		if( strchr(" \t\r\n", *sopts) ) del = *sopts;
	}
	if( optm & SM_OFFSETOF ){
		const char *listb;
		const char *found = 0;
		int len = strlen(list);
		int off = -1;
		listb = stralloc(list);
		scan_ListL(listb,del,STR_OVWR,scanListCall sm2X,word,&nth,optm,
			&found);
		if( found && listb <= found && found < listb+len ){
			off = found - listb;
		}
		free((char*)listb);
		return off;
	}
	scan_ListL(list,del,0,scanListCall sm2X,word,&nth,optm,&match);
	return match;
}

int comp_args(PVStr(ab),int ac,const char *av[]){
	int ai;
	int quot;
	refQStr(ap,ab);
	const char *arg;
	const char *a1;
	char ch;

	for( ai = 0; ai < ac; ai++ ){
		arg = av[ai];
		if( 0 < ai )
			setVStrPtrInc(ap,' ');
		if( strpbrk(arg," \t") != 0 ){
			if( strchr(arg,'"') )
				quot = '\'';
			else	quot = '"';
			setVStrPtrInc(ap,quot);
		}else{
			quot = 0;
		}
		for( a1 = av[ai]; ch = *a1; a1++ ){
			setVStrPtrInc(ap,ch);
		}
		if( quot )
			setVStrPtrInc(ap,quot);
	}
	setVStrEnd(ap,0);
	return strlen(ab);
}
int decomp_args(const char *av[],int mac,PCStr(args),PVStr(argb))
{	const char *sp;
	refQStr(dp,argb); /**/
	char ch;
	int arglen;
	int quoting;
	int ac;

	ac = 0;
	quoting = 0;
	arglen = 0;

	for( sp = args; ch = *sp; sp++ ){
		assertVStr(argb,dp+1);
		switch( ch ){
			case '"':
			case '\'':
				if( quoting == 0 )
					quoting = ch;
				else
				if( quoting == ch )
					quoting = 0;
				break;

			case ' ':
			case '\t':
				if( quoting )
					goto ARGCH1;
				else
				if( arglen ){
					setVStrPtrInc(dp,0);
					arglen = 0;
				}
				break;

			case '\\':
				if( sp[1] == '"' )
					ch = *++sp;

			ARGCH1:
			default:
				if( arglen == 0 ){
					av[ac++] = (char*)dp;
					if( mac-1 <= ac ){
						int ch;
						do {
							ch = *sp++;
							setVStrPtrInc(dp,ch);
						} while( ch ); 
						goto EXIT;
					}
				}
				setVStrPtrInc(dp,ch);
				arglen++;
				break;
		}
	}
EXIT:
	setVStrEnd(dp,0);
	av[ac] = 0;

/*
	{
	int ai;
	for( ai = 0; ai < ac; ai++ )
	printf("[%d] [%s]\n",ai,av[ai]);
	}
*/
	return ac;
}

/*
static scanListFunc addelem(PCStr(elem),int ac,char *av[],int *aip,PCStr(tail))
*/
static scanListFunc addelem(PCStr(elem),SLAP,int ac,char *av[],int *aip,PCStr(tail))
{	int ai;

	ai = *aip;
	av[ai++] = (char*)elem;
	(*aip) = ai;
	if( ac <= ai+1 ){
		/* the last element must contain whole of the rest if exists
		 * after the delimiter character following to this element.
		 */
		/*
		if( elem+strlen(elem)+1 < tail ){
		*/
		if( SLNEP != 0 && SLNEP <= tail ){
			/*
				the element can be wrapped with "{}"
				to increment the offset of the last element
				like "list1:{list2}:list3" for ac==3
			av[ai] = (char*)elem+strlen(elem)+1;
			if( av[ai][0] == 0 && av[ai]+1 == SLNEP )
			*/
			av[ai] = (char*)SLNEP;
			(*aip) += 1;
		}
		return 1;
	}else	return 0;
}
int list2vect(PCStr(list),int del,int ac,const char *av[])
{
	return list2vectX(list,del,STR_OVWR,ac,av);
}
int list2vectX(PCStr(list),int del,int allocm,int ac,const char *av[])
{	int cc,ci;
	SLAC;

	if( ac <= 1 ){
		av[0] = (char*)list;
		return 1;
	}
	cc = 0;
	/*
	scan_ListL(list,del,allocm,scanListCall addelem,ac,av,&cc,list+strlen(list));
	*/
	scan_ListLX(list,del,allocm,SLAA,scanListCall addelem,ac,av,&cc,list+strlen(list));
	return cc;
}

int streq(PCStr(a),PCStr(b))
{
	if( a == b )
		return 1;
	if( a == 0 || b == 0 )
		return 0;

	if( *a != *b )
		return 0;
	return strcmp(a,b) == 0;
}
int strneq(PCStr(a),PCStr(b),int n)
{
	if( a == b )
		return 1;
	if( a == 0 || b == 0 )
		return 0;

	if( *a != *b )
		return 0;
	return strncmp(a,b,n) == 0;
}
char *strtail(PCStr(s))
{
	if( s[0] ){
		while( s[1] )
			s++;
	}
	return (char*)s;
}

char *FMT_Sprintf(PVStr(s),PCStr(fmt), ...)
{
	VARGS(16,fmt);
	setVStrEnd(s,0);
	if( fmt[0]=='%' && fmt[1]=='s' && fmt[2]==0 ){
		Xstrcpy(BVStr(s),va[0]);
	}else{
		Xsprintf(BVStr(s),fmt,VA16);
	}
	return (char*)s + strlen(s);
}
/*
int tsprintf(xPVStr(s),const char *fmt, ...)
{	VARGS(16,fmt);
	int wcc;

	s += strlen(s);
	wcc = Xsprintf(BVStr(s),fmt,VA16);
	return wcc;
}
*/

#define isSP(ch)  (ch==0||ch==' '||ch=='\t'||ch=='\r'||ch=='\n')

char *Str2vstr(PCStr(sstr),int slen,PVStr(vstr),int vlen)
{	const char *sp;
	const char *sx;
	char sc;
	refQStr(vp,vstr); /**/
	const char *vx = vstr+vlen;
	int in2bytes;

	in2bytes = 0;
	sp = sstr;
	sx = sstr+slen;

	while( sp < sx ){
		if( vx <= vp+1 )
			break;
		sc = *sp++;
		/* now, sp points to next character */

		if( sc & 0x80 ){
		}else
		switch( sc ){
			case '\0':
			case 'G'-0x40:
			case 'N'-0x40:
			case 'O'-0x40:
			case '\t':
			case '\r':
				if( vx <= vp+2 )
					break;
				setVStrPtrInc(vp,'^');
				setVStrPtrInc(vp,sc+0x40);
				break;

			case 033:
				if( !isSP(sp[1]) ){
					if( sp[0] == '$' ) in2bytes = 1; else
					if( sp[0] == '(' ) in2bytes = 0;
				}

			default:
				setVStrPtrInc(vp,sc);
				break;
		}
		if( in2bytes && isSP(*sp) ){
			if( vx <= vp+3 )
				break;
			strcpy(vp,"\033(B");
			vp += strlen(vp);
			in2bytes = 0;
		}
	}
	setVStrEnd(vp,0);
	return (char*)vp;
}

/**/
void SVinit(StrVec *Sv,PCStr(what),const char **ev,int ecmax,PVStr(eb),int ebsiz)
{
	Xstrncpy(AVStr(Sv->sv_id),what,sizeof(Sv->sv_id)-1); XsetVStrEnd(AVStr(Sv->sv_id),sizeof(Sv->sv_id)-1);
	Sv->sv_ev = ev;
	Sv->sv_ecmax = ecmax;
	Sv->sv_ec = 0;
	str_sopen(&Sv->sv_MemF,what,(char*)eb,ebsiz,0,"w");
}

char *MemFStr(MemFile *MemF){
	return (char*)str_sptell((struct _StrHead*)MemF);
}
char *EnvpStr(StrVec *Evp){
	return MemFStr(&Evp->sv_MemF);
}
char *FMT_SPrintf(MemFile *MemF,PCStr(fmt),...)
{	const char *top;
	VARGS(16,fmt);

	top = str_sptell((struct _StrHead*)MemF);
	str_sprintf((struct _StrHead*)MemF,fmt,VA16);
	str_sputc(0,(struct _StrHead*)MemF);
	return (char*)top;
}

char *FMT_SVaddEnvf(StrVec *Evp,PCStr(fmt),...)
{	const char *top;
	const char *dp;
	const char **ev;
	int en,ec,ei,len;
	VARGS(16,fmt);

	top = FMT_SPrintf(&Evp->sv_MemF,fmt,VA16);
	en = -1;
	if( top && (dp = strchr(top,'=')) ){
		len = dp - top;
		ev = Evp->sv_ev;
		ec = Evp->sv_ec;
		for( ei = 0; ei < ec; ei++ )
			if( strncmp(ev[ei],top,len) == 0
			 && ev[ei][len] == '=' ){
				en = ei;
				break;
			}
	}
	if( 0 <= en ){
		if( strcmp(top,Evp->sv_ev[en]) != 0 )
		syslog_ERROR("addEnvf:overwrite %s[%d][%s][%s]\n",
			Evp->sv_id,en,Evp->sv_ev[en],top);
		Evp->sv_ev[en] = (char*)top;
	}else
	if( Evp->sv_ec+1 < Evp->sv_ecmax )
		Evp->sv_ev[Evp->sv_ec++] = (char*)top;
	else{
		syslog_ERROR("ERROR: addEnvf overflow %s[%d]\n",
			Evp->sv_id,Evp->sv_ecmax);
	}
	return (char*)top;
}

char *paramscanX(PCStr(src),PCStr(brk),PVStr(dst),int size)
{	char sc,bc;
	refQStr(dp,dst); /**/
	const char *xp = dst + (size - 1);
	const char *sp;
	const char *bp;

	for( sp = src; sc = *sp; sp++ ){
		if( sc == '\r' || sc == '\n' )
			break;
		if( xp <= dp )
			break;
		for( bp = brk; bc = *bp; bp++ ){
			if( sc == bc )
				goto EXIT;
		}
		setVStrPtrInc(dp,sc);
	}
EXIT:
	setVStrEnd(dp,0);
	return (char*)sp;
}
int scan_namebody(PCStr(namebody),PVStr(name),int nsiz,PCStr(nbrk),PVStr(body),int bsiz,PCStr(bbrk))
{	const char *dp;

	if( name != NULL )
		dp = paramscanX(namebody,nbrk,BVStr(name),nsiz);
	else	dp = paramscanX(namebody,nbrk,BVStr(body),bsiz); /* skip name */
	if( *dp && strchr(nbrk,*dp) ){
		dp++;
		if( bbrk )
			paramscanX(dp,bbrk,BVStr(body),bsiz);
		else	wordscanX(dp,BVStr(body),bsiz);
	}else	setVStrEnd(body,0);
	if( *body != 0 )
		return 2;
	else	return 0;
}
void scan_field1(PCStr(field),PVStr(name),int nsiz,PVStr(body),int bsiz)
{	const char *dp;

	dp = paramscanX(field,":",BVStr(name),nsiz);
	if( *dp == ':' ){
		dp++;
		while( *dp == ' ' || *dp == '\t' )
			dp++;
		linescanX(dp,BVStr(body),bsiz);
	}else	setVStrEnd(body,0);
}

int ustrcmp(UTag *tag,PCStr(str))
{
	return strncmp(tag->ut_addr,str,tag->ut_leng);
}
int utosX(UTag *tag,PVStr(str),int siz)
{	int len;

	if( tag == NULL || tag->ut_addr == 0 ){
		setVStrEnd(str,0);
		return -1;
	}else{
		len = siz - 1;
		if( tag->ut_leng < len )
			len = tag->ut_leng;
		Bcopy(tag->ut_addr,str,len); setVStrEnd(str,len);
		return len;
	}
}
int utoi(UTag *tag)
{
	if( tag == NULL || tag->ut_addr == 0 )
		return 0;
	else	return atoi(tag->ut_addr);
}
static int fmtlen(PCStr(fmt))
{	const char *fp;
	char fx;

	fp = fmt;
	if( *fp != '%' )
		return 0;

	fp++;
	if( *fp == '-' )
		fp++;
	while( isdigit(*fp) || *fp =='.' )
		fp++;

	switch( *fp ){
		case '[': fx = ']'; break;
		case '(': fx = ')'; break;
		default: fx = 0;
	}
	if( fx ){
		for(; *fp; fp++ ){
			if( *fp == fx ){
				fp++;
				break;
			}
		}
	}else{
		fp++;
	}
	return fp-fmt;
}
static int fmtvec(PCStr(fmt),int mac,const char *sv[],int lv[])
{	const char *fp;
	int fn,flen;

	fn = 0;
	for( fp = fmt; *fp; fp++ ){
		if( *fp == '%' && (flen = fmtlen(fp)) ){
			if( fp[flen-1] == '%' ){
				fp++;
			}else{
				if( mac <= fn )
					break;
				sv[fn] = fp;
				lv[fn] = flen;
				fn++;
			}
		}
	}
	return fn;
}
void uvfmtreverse(PCStr(src),PCStr(dst),const char **rsrc,const char **rdst)
{	const char *sv[32]; /**/
	const char *dv[32]; /**/
	const char *fp;
	const char *ip;
	char ic;
	CStr(buf,1024);
	refQStr(op,buf); /**/
	const char *ox = buf + sizeof(buf) -1;
	int ov[32],on,oi,ii;
	int sl[32],dl[32];
	int fi,sn,dn,num,flen,xlen,subst,ti;

	sn = fmtvec(src,elnumof(sv),sv,sl);
	dn = fmtvec(dst,elnumof(dv),dv,dl);

	/*
	 * convert output generation format to input matching pattern
	 */
	on = 0;
	ti = 0;

	for( ip = dst; ic = *ip; ){
		if( ic == '%' && (flen = fmtlen(ip)) ){
			switch( ip[flen-1] ){
				case 'S': num = ti++; break;
				case ')': num = atoi(&ip[2]); break;
				 default: num = -1; break;
			}
			if( num < sn )
			if( 0 <= num ){
				ov[on++] = num;
				xlen = sl[num];
				Bcopy(sv[num],op,xlen);
				if( op[xlen-1] == 's' ){
					Xsprintf(QVStr(&op[xlen-1],buf),"[^%c]",
						ip[flen]?ip[flen]:' ');
					op += strlen(op);
				}else{
					op += xlen;
				}
			}else{
				Bcopy(ip,op,flen);
				op += flen;
			}
			ip += flen;
		}else{
			setVStrPtrInc(op,ic);
			ip += 1;
		}
		if( ox <= op ){
			op = (char*)ox;
			break;
		}
	}
	setVStrEnd(op,0);
	*rdst = strdup(buf);

	/*
	 * convert input matching pattern to output generation format
	 */
	ox = buf + sizeof(buf) -1;
	op = buf;
	ii = 0;
	for( ip = src; ic = *ip; ){
		if( ic == '%' && (flen = fmtlen(ip)) ){
			subst = 0;
			if( ip[flen-1] != '%' ){
				for( oi = 0; oi < on; oi++ ){
					if( ov[oi] == ii ){
						sprintf(op,"%%(%d)",oi);
						op += strlen(op);
						ii++;
						subst = 1;
						break;
					}
				}
			}
			if( subst == 0 ){
				Bcopy(ip,op,flen);
				op += flen;
			}
			ip += flen;
		}else{
			setVStrPtrInc(op,ic);
			ip += 1;
		}
		if( ox <= op ){
			op = (char*)ox;
			break;
		}
	}
	setVStrEnd(op,0);
	*rsrc = strdup(buf);

	syslog_ERROR("#### %s >> %s ####\n",src,dst);
	syslog_ERROR("#### %s << %s ####\n",*rsrc,*rdst);
}
int uvtosf(PVStr(str),int siz,PCStr(fmt),UTag *tagv[])
{	int ti,tj,tj1,tj2,tjinc,tx;
	refQStr(dp,str); /**/
	const char *xp = str + (siz - 1);
	const char *fp;
	char fc;
	CStr(sep,32);

	ti = 0;
	for( tx = 0; tagv[tx] && tagv[tx]->ut_addr; tx++ );

	for( fp = fmt; fc = *fp; fp++ ){
		if( xp <= dp )
			break;

		if( fc != '%' ){
			setVStrPtrInc(dp,fc);
		}else{
			fp++;
			switch( *fp ){
				case 0:	goto EXIT;
				case '%':
					setVStrPtrInc(dp,'%');
					break;
				case 'S':
				case 's':
					if( tagv[ti] == 0 ){
						/* error */
					}else	dp += utosX(tagv[ti++],AVStr(dp),xp-dp);
					break;
				case '(':
					fc = *++fp;
					if( !isdigit(fc) )
						break;

					tj1 = tj2 = fc - '0';
					fc = *++fp;
					if( fc == '-' ){
						fc = *++fp;
						if( isdigit(fc) ){
							tj2 = fc - '0';
							fc = *++fp;
						}else	tj2 = tx - 1;
					}
					sep[0] = 0;
					while( fc != ')' ){
						refQStr(sp,sep); /**/
					const char *sx=&sep[sizeof(sep)-1];
						for(;sp < sx;){
							setVStrPtrInc(sp,fc);
							if( fp[1] == 0 )
								break;
							fc = *++fp;
							if( fc==0 || fc==')')
								break;
						}
						setVStrEnd(sp,0);
					}
					if( tj1 <= tj2 )
						tjinc = 1;
					else{
						tj = tj2;
						tj2 = tj1;
						tj1 = tj;
						tjinc = -1;
					}
					for( tj = tj1; tj < tx; tj += tjinc ){ 
						if( sep[0] && tj != tj1 ){
							strcat(dp,sep);
							dp += strlen(dp);
						}
						dp += utosX(tagv[tj],AVStr(dp),xp-dp);
						if( tj == tj2 )
							break;
					}
					break;
				default:
					break;
			}
		}
	}
EXIT:
	setVStrEnd(dp,0);
	return dp - str;
}

int ufromsf(PCStr(str),int siz,PCStr(fmt),UTag *tagp)
{	UTag *tagv[2];

	uvinit(tagv,tagp,1);
	return uvfromsf(str,siz,fmt,tagv);
}
int uvfromsf(PCStr(str),int siz,PCStr(fmt),UTag *tagv[])
{
	return uvfromsfX(str,siz,fmt,tagv,NULL,NULL);
}
int uvfromsfX(PCStr(str),int siz,PCStr(fmt),UTag *tagv[],const char **rsp,const char **rfp)
{	int ti,neg,supp,isin,width;
	const char *sp;
	const char *xp;
	const char *sx;
	const char *s1;
	const char *tp;
	const char *fp;
	const char *st;
	char sc,fc;
	const char *osp;
	const char *ofp;

	sp = str;
	if( siz )
		xp = str + siz;
	else	xp = NULL;
	ti = 0;
	
	for( fp = fmt;;){
		fc = *fp;
		if( xp == 0 ){
			if( fc == 0 )
				break;
		}else{
			if( xp <= sp )
				break;
		}

		if( tagv[ti] == 0 )
			break;
		if( fc == ' ' || fc == '\t' ){
			while( *fp == ' ' || *fp == '\t' ) fp++;
			while( *sp == ' ' || *sp == '\t' ) sp++;
		}else
		if( fc != '%' ){
			if( *sp != fc ){
				goto EXIT;
			}else{
				fp++;
				sp++;
			}
		}else{
			ofp = fp;
			osp = sp;
			supp = 0;
			width = 0;
			for( fp++; fc = *fp; fp++ ){
				if( fc == '*' ){
					supp = 1;
				}else
				if( '1' <= fc && fc < '9' ){
					width = width*10 + (fc-'0');
				}else	break;
			}

			switch( fc ){
			default: /* error */
			goto EXIT;

			case 'd': /* decimal integer */
			while( *sp && isspace(*sp) ) sp++;
			tagv[ti]->ut_addr = (char*)(st = sp);
			if( *sp == '+' || *sp == '-' )
				sp++;
			if( !isdigit(*sp) ){
				tagv[ti]->ut_addr = 0;
				goto EXIT; /* unmatch */
			}
			while( isdigit(*sp) ) sp++;
			tagv[ti]->ut_leng = sp - st;
			if( !supp ) ti++;
			fp++;
			break;

			case 'c':
				if( width == 0 )
					width = 1;
				sx = sp + width;
				tagv[ti]->ut_addr = (char*)(st = sp);
				while( sp < sx && *sp ) sp++;
				tagv[ti]->ut_leng = sp - st;
				if( !supp ) ti++;
				fp++;
				break;

			case 'S': /* %Sx means %[^x]x, or eq. %s if x is NULL  */
			{	int elen,match;
				char ec;
				CStr(estr,32);
				refQStr(ep,estr); /**/
				const char *ex = estr + (sizeof(estr) - 1);

				for( fp++; ec = *fp; fp++ ){
					if( ec == '%' )
						break;
					setVStrPtrInc(ep,ec);
					if( ex <= ep )
						break;
				}
				setVStrEnd(ep,0);
				elen = ep - estr;

				tagv[ti]->ut_addr = (char*)(st = sp);
				if( elen == 0 ){
				    for(; *sp; sp++ ){
					if( isspace(*sp) )
						break;
				    }
				}else{
				    match = 0;
				    for(; *sp; sp++ ){
					if( *sp == *estr )
					if( strncmp(sp,estr,elen) == 0 ){
						match = 1;
						break;
					}
				    }
				    if( match == 0 ){
					fp = ofp;
					sp = osp;
					goto EXIT;
				    }
				}
				tagv[ti]->ut_leng = sp - st;
				if( !supp ) ti++;
				sp += elen;
				break;
			}

			case 's': /* non-white-space string */
			while( *sp && isspace(*sp) ) sp++;
			if( *sp == 0 ){
				goto EXIT; /* unmatch */
			}
			tagv[ti]->ut_addr = (char*)(st = sp);
			while( *sp && !isspace(*sp) ) sp++;
			tagv[ti]->ut_leng = sp - st;
			if( !supp ) ti++;
			fp++;
			break;

			case '[': /* character set */
			fp++;
			if( neg = *fp == '^' )
				fp++;
			tp = fp;
			while( *fp && *fp != ']' )
				fp++;
			tagv[ti]->ut_addr = (char*)(st = sp);
			while( sc = *sp ){
				isin = 0;
				for( s1 = tp; s1 < fp; s1++ ){
					if( *s1 == sc ){
						isin = 1;
						break;
					}
					if( s1+1 < fp && s1[1] == '-' ){
						if( fp <= s1+2 ){ /* error */
							s1++;
							break;
						}
						if( *s1 <= sc && sc <= s1[2] ){
							isin = 1;
							break; 
						}
						s1 += 2;
					}
				}
				if( neg && isin || !neg && !isin )
					break;
				sp++;
				if( width && st+width <= sp )
					break;
			}
			tagv[ti]->ut_leng = sp - st;
			if( !supp ) ti++;
			if( *fp == ']' )
				fp++;
			break;
			}
		}
	}
EXIT:
	if( tagv[ti] ){
		tagv[ti]->ut_addr = 0;
	}
	if( rsp ) *rsp = (char*)sp;
	if( rfp ) *rfp = (char*)fp;
	return ti;
}

UTag UTset(const void *bp,int size){
	UTag ut;
	ut.ut_size = size;
	ut.ut_strg = 0;
	setQStr(ut.ut_addr,(char*)bp,ut.ut_size);
	return ut;
}
UTag UTalloc_FL(FL_PAR, int lev,int size,int algn){
	UTag ut;
	const char *bp; /**/

	ut.ut_size = size;
	if( bp = getStrBuffer(lev,size,algn) )
		ut.ut_strg = 0;
	else{
		/*
		bp = (char*)malloc(ut.ut_size);
		*/
		bp = (char*)Xmalloc(FL_BAR_s, ut.ut_size);
		ut.ut_strg = 1;
	}
	setQStr(ut.ut_addr,(char*)bp,ut.ut_size);
	return ut;
}
void UTfree_FL(FL_PAR, UTag *up)
{
	if( up->ut_strg && up->ut_addr )
		Xfree(FL_BAR, (char*)up->ut_addr);
	bzero(up,sizeof(UTag));
}
void UTclear_FL(FL_PAR, UTag *up)
{
	bzero(up,sizeof(UTag));
}

void copyiv(int di[],int si[],int ni)
{	int ii;

	for( ii = 0; ii < ni; ii++ )
		di[ii] = si[ii];
}
void setiv(int di[],int ni,int iv)
{	int ii;

	for( ii = 0; ii < ni; ii++ )
		di[ii] = iv;
}
char *htoniv(xPVStr(bp),int bsiz,PCStr(what),int ic,int iv[])
{	int si;

	sprintf(bp,"(%s %d",what,ic);
	bp += strlen(bp);
	for( si = 0; si < ic; si++ ){
		sprintf(bp," %d",iv[si]);
		bp += strlen(bp);
	}
	sprintf(bp,")");
	bp += strlen(bp);
	return (char*)bp;
}
char *ntohiv(PCStr(buf),PCStr(bp),int blen,PCStr(what),int ic,int iv[],int *np)
{	CStr(iwhat,32);
	CStr(tag,32);
	const char *ap;
	int si,iic;

	sprintf(tag,"(%s ",what);
	if( strncmp(bp,tag,strlen(tag)) != 0 ){
		ap = strstr(buf,tag);
		if( ap == 0 ){
			*np = 0;
			return (char*)bp;
		}
		bp = ap;
	}
	Xsscanf(bp,"(%s %d",AVStr(iwhat),&iic);
	*np = iic;
	bp = strchr(bp,' ') + 1;
	bp = strpbrk(bp," )") + 1;
	if( iic == 0 )
		return (char*)bp;
	for( si = 0; si < iic && si < ic; si++ ){
		iv[si] = atoi(bp);
		bp = strpbrk(bp," )") + 1;
	}
	if( *bp == ')' )
		bp++;
	return (char*)bp;
}

void reverseDomainX(PCStr(dom),PVStr(rdom),int dlm,PCStr(sep))
{	CStr(dombuf,1024);
	const char *dp;

	lineScan(dom,dombuf);
	setVStrEnd(rdom,0);
	while( dp = strrchr(dombuf,dlm) ){
		strcat(rdom,dp+1);
		strcat(rdom,sep);
		truncVStr(dp);
	}
	strcat(rdom,dombuf);
}
void reverseDomain(PCStr(dom),PVStr(rdom))
{
	reverseDomainX(dom,BVStr(rdom),'.',".");
}
void strreverse(PCStr(str))
{	int i,len,len0,len2,ch;

	len = strlen(str);
	len0 = len - 1;
	len2 = len / 2;
	for( i = 0; i < len2; i++ ){
		ch = str[i];
		((char*)str)[i] = str[len0-i]; /**/
		((char*)str)[len0-i] = ch; /**/
	}
}

/* represent zero in UTF-8 {0xC0 0x80} without string terminator '\0' */
int FGSZ_flags = FGSZ_KILL;
const char *fgetsZ(PVStr(str),int siz,FILE *fp){
	int ch;
	refQStr(sp,str);
	const char *sx;

	sx = &str[siz-2];
	for( sp = str; sp < sx; ){
		ch = getc(fp);
		if( ch == EOF )
			break;
		if( ch == 0 ){
			if( FGSZ_flags & FGSZ_KILL ){
			}else
			if( FGSZ_flags & FGSZ_UTF8 ){
				setVStrPtrInc(sp,0xC0);
				setVStrPtrInc(sp,0x80);
			}else{
				setVStrPtrInc(sp,ch);
			}
		}else{
			setVStrPtrInc(sp,ch);
			if( ch == '\n' )
				break;
		}
	}
	setVStrEnd(sp,0);
	if( sp == str && feof(fp) )
		return NULL;
	if( sp == str && ch == EOF ){
		return NULL;
	}
	return str;
}
int fputsZ(PCStr(str),FILE *fp){
	const unsigned char *sp;
	unsigned char ch;

	for( sp = (const unsigned char*)str; ch = *sp; sp++ ){
		if( (FGSZ_flags & FGSZ_UTF8) && ch == 0xC0 && sp[1] == 0x80 ){
			putc(0,fp);
			sp++;
		}else{
			putc(ch,fp);
		}
	}
	return 0;
}

int getthreadid();
static const char *Evc[32];
static CriticalSec EnvCSC;
const char *GetEnv(PCStr(name)){
	int ei,nlen;
	const char *eval,*evp,*oenv,*ev1,*nenv;
	IStr(ebuf,1024);

	eval = getenv(name);
	if( eval == 0 )
		return 0;
	nlen = strlen(name);
	if( eval[-1] == '=' && strneq(name,eval-1-nlen,nlen) ){
		evp = eval - 1 - nlen;
	}else{
		sprintf(ebuf,"%s=%s",name,eval);
		evp = ebuf;
	}
	if( numthreads() ){
		setupCSC("GetEnv",EnvCSC,sizeof(EnvCSC));
		enterCSC(EnvCSC);
	}
	nenv = 0;
	for( ei = 0; ei < elnumof(Evc); ei++ ){
		if( (oenv = Evc[ei]) == 0 )
			break;
		if( !strneq(oenv,name,nlen) || oenv[nlen] != '=' )
			continue;
		ev1 = oenv + nlen + 1;
		if( streq(eval,ev1) ){
			nenv = oenv;
	if( lENVIRON() )
	fprintf(stderr,"-- -de %X GetEnv[%d] reu %s\n",getthreadid(),ei,nenv);
			break;
		}
	}
	if( nenv == 0 ){
		nenv = StrAlloc(evp);
		if( ei < elnumof(Evc) ){
	if( lENVIRON() )
	fprintf(stderr,"-- -de %X GetEnv[%d] new %s\n",getthreadid(),ei,nenv);
			Evc[ei] = nenv;
		}else{
	if( lENVIRON() )
	fprintf(stderr,"-- -de %X GetEnv[%d] ovf %s\n",getthreadid(),ei,nenv);
		}
	}
	if( numthreads() ){
		leaveCSC(EnvCSC);
	}
	return nenv + nlen + 1;
}

typedef struct {
	const char **av;
} AVCache;
static AVCache avcache[8];
static CriticalSec avcCSC;
char **DupvCached(const char *const av[]){
	const char **nav;
	int ci;

	nav = 0;
	if( numthreads() ){
		setupCSC("DupCached",avcCSC,sizeof(avcCSC));
		enterCSC(avcCSC);
	}
	for( ci = 0; ci < elnumof(avcache); ci++ ){
		if( avcache[ci].av == 0 )
			break;
		if( cmpv(avcache[ci].av,(const char**)av,0) == 0 ){
			nav = avcache[ci].av;
			if( lENVIRON() )
		fprintf(stderr,"-- -de %X Dupv[%d] reu\n",getthreadid(),ci);
			break;
		}
	}
	if( nav == 0 ){
		nav = (const char**)Dupv(av);
		if( ci < elnumof(avcache) ){
			avcache[ci].av = nav;
			if( lENVIRON() )
		fprintf(stderr,"-- -de %X Dupv[%d] new\n",getthreadid(),ci);
		}else{
			if( lENVIRON() )
		fprintf(stderr,"-- -de %X Dupv[%d] ovf\n",getthreadid(),ci);
		}
	}
	if( numthreads() ){
		leaveCSC(avcCSC);
	}
	return (char**)nav;
}
