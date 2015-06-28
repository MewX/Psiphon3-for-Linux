/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1998 Electrotechnical Laboratry (ETL), AIST, MITI
Copyright (c) 1998 Yutaka Sato

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
Program:	TLEX.c (Tiny LEXical analizer)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	860408	created as a part of scanner generator of COSMOS
	921116	added SMALL type state.
	980414	modified to be independent of COSMOS
	980604	added atbitrary string "**", char "[]" and frex_*()
//////////////////////////////////////////////////////////////////////#*/

#include <stdio.h>
#include "ystring.h"
#include <stdlib.h>
#include "log.h"

#ifndef NULL
#define NULL 0L
#endif

#undef ctos /* in OSF/1 sys/wait.h ? */
static char *ctos(int ch,PVStr(str))
{
	if( 0x20 < ch && ch < 0x7F )
		sprintf(str,"'%c'",ch);
	else	sprintf(str,"%02xH",ch);
	return (char*)str;
}

#ifdef MAIN
#define syslog_DEBUG	printf
#define syslog_ERROR	printf
main(){ fa_test(); }
#endif

/*######################################################*
 *							*
 *	FINITE AUTOMATON GENERATOR AND INTERPRETER	*
 *		Y.Sato	1986,4/8			*
 *							*
 *######################################################*/

#define CHARSETSIZE	256
typedef struct {
	struct fa_stat *nvec[CHARSETSIZE];
} FaVect;

#define FA_SMALL	4
typedef struct fa_stat {
	int		stid;	/* Status Id-Number		*/
	int		xclass;	/* Class of expression end here	*/
	int		eclass; /* class for strings end here	*/
	struct fa_stat *plink;	/* Link to the previous status	*/
	struct fa_stat *alink;	/* Link to the last allocated status */

	unsigned	upper;	/* Upper bound of input		*/
	unsigned	lower;	/* Lower			*/

	int		nnexts;
	unsigned char	in_ch[FA_SMALL];
	struct fa_stat *nstat[FA_SMALL];
	FaVect	       *Nstat;	/* for large sets		*/
	struct fa_stat *other;	/* back track to "arbitrary string" */
} FaStat;
#define PREV(fsp)		( fsp->plink )

#define NEXT(fsp,ch) \
	( fsp->Nstat ? fsp->Nstat->nvec[ch] : fsp->nnexts ? next(fsp,ch) : 0 )

static FaStat *next1(FaStat *fsp,int ch)
{	FaStat *nfsp;
	int si;
	const unsigned char *in_ch = fsp->in_ch;

	if( fsp->Nstat ){
		if( nfsp = fsp->Nstat->nvec[ch] )
			return nfsp;
	}else{
		for( si = 0; si < FA_SMALL; si++ )
			if( in_ch[si] == ch )
				return fsp->nstat[si];
	}
	return 0;
}

static int fa_backed;
static FaStat *next(FaStat *fsp,int ch)
{	register int si;
	FaStat *nfsp,*xfsp;

	fa_backed = 0;
	if( nfsp = next1(fsp,ch) )
		return nfsp;

	if( nfsp = fsp->other ){
		if( xfsp = next1(nfsp,ch) ){
			fa_backed = 1;
			return xfsp;
		}
		if( nfsp != fsp )
			fa_backed = 1;
	}
	return nfsp;
}
static void fa_stvec_alloc(FaStat *fsp);
static void SETNEXT(FaStat *fsp,int ch,FaStat *nfsp)
{	register int si;

	if( fsp->nnexts < FA_SMALL ){
		fsp->in_ch[fsp->nnexts] = ch;
		fsp->nstat[fsp->nnexts] = nfsp;
	}else{
		if( fsp->Nstat == 0 ){
			fa_stvec_alloc(fsp);
			for( si = 0 ; si < FA_SMALL; si++ )
				SETNEXT(fsp,fsp->in_ch[si],fsp->nstat[si]);
		}
		fsp->Nstat->nvec[ch] = nfsp;
	}
	fsp->nnexts++;
}

#define NONEXT(fsp) (fsp->nnexts == 0)

typedef struct {
	FaStat *Fa_root;	/* Start Status		*/
	FaStat *Fa_last;	/* Last Created Status	*/
	int	 Fa_stid;	/* Last Created stid	*/
	int	 Fa_metachar;	/* Meta character enable*/
} FA;
static FA DefaultFA;
static FA *CurrentFA = &DefaultFA;
#define fa_root		(CurrentFA->Fa_root)
#define fa_last		(CurrentFA->Fa_last)
#define fa_stid		(CurrentFA->Fa_stid)
#define fa_metachar	(CurrentFA->Fa_metachar)

static FaVect *allocFaVect(){
	return (FaVect*)calloc(1,sizeof(FaVect)+256);
}
static FaStat *allocFaStat(){
	return (FaStat*)calloc(1,sizeof(FaStat));
}

/*##############################*
 *	CONSTRUCT FUNCTIONS	*
 *##############################*/
static FaStat *fa_init(FaStat *fsp)
{
	if(fsp)	fa_root = fsp;
	else{
		fa_root = allocFaStat();
		fa_last = 0;
		fa_stid = 0;
	}
	return(fa_root);
}

static void fa_free(FaStat *fsp)
{	FaStat *fsp1,*nfsp;

	for( fsp1 = fsp->alink; fsp1; fsp1 = nfsp ){
		nfsp = fsp1->alink;
/*
		syslog_DEBUG("#%d freed %x\n",fsp1->stid,fsp1->Nstat);
*/
		if( fsp1->Nstat ) free(fsp1->Nstat);
		free(fsp1);
	}
/*
	syslog_DEBUG("#%d freed %x\n",fsp->stid,fsp->Nstat);
*/
	if( fsp->Nstat ) free(fsp->Nstat);
	free(fsp);
	if( fa_root = fsp )
		fa_root = NULL;
}

static FaStat *fa_stnew(FaStat *ofsp)
{	FaStat *fsp;

	fsp = allocFaStat();
	fsp->alink = ofsp->alink;
	ofsp->alink = fsp;

	fsp->stid = ++fa_stid;
	if(fa_last)
		PREV(fsp) = fa_last;
	else	PREV(fsp) = fa_root;
	fa_last = fsp;
	return(fsp);
}

/*##############################*
 *	OBSERVATION FUNCTIONS	*
 *##############################*/
static void fa_dump(FaStat *fsp)
{	register int i,j,k;
	CStr(buf1,10);
	CStr(buf2,10);

	syslog_DEBUG("#%-2d:[%2x-%2x](%d)",fsp->stid,fsp->lower,fsp->upper,
		fsp->nnexts);
	if( fsp->other )
		syslog_DEBUG(" %3d<=* ",fsp->other->stid);
	if(fsp->xclass)
		syslog_DEBUG(":%3d",fsp->xclass);
	syslog_DEBUG("\n");
	if(NONEXT(fsp))
		return;

	if( fsp->nnexts < FA_SMALL ){
		for( j = 0; j < fsp->nnexts; j++ ){
			int ch,stid;
			ch = fsp->in_ch[j];
			stid = fsp->nstat[j]->stid;
			syslog_DEBUG("    -------    #%-2d <- ",stid);
			syslog_DEBUG("[%s]\n",ctos(ch,AVStr(buf1)));
		}
		return;
	}

	for(i = 0; i <= fa_stid; i++)
	for(j = fsp->lower; j < fsp->upper; j++){
	    if(NEXT(fsp,j) && (NEXT(fsp,j)->stid == i)){
		syslog_DEBUG("    -------    #%-2d <- ",i);

		for(k = j; ((k+1) < fsp->upper) && NEXT(fsp,k+1); k++)
			if(NEXT(fsp,k+1)->stid != i)
				break;

		if(j < k)
			syslog_DEBUG("[%s-%s]\n",ctos(j,AVStr(buf1)),ctos(k,AVStr(buf2)));
		else	syslog_DEBUG("%s\n",ctos(j,AVStr(buf1)));
		j = k;
	    }
	}
}
static void fa_list(FaStat *fsp)
{
	if(fsp){
		fa_list(PREV(fsp));
		fa_dump(fsp);
	}
}
static void fa_ls(){ fa_list(fa_last); }

/*##############################*
 *	FA SCANNER		*
 *##############################*/

typedef struct {
	FaStat		*m_fsp;
  const	unsigned char	*m_top;
  const	unsigned char	*m_next;
} Match;

static int fa_scanX(FaStat *fsp,unsigned char *input,const unsigned char **start,const unsigned char **tail,int shortest)
{	const unsigned char *ss;
	unsigned char cc;
	register FaStat *nfsp;
	FaStat *asp;
	const unsigned char *lsp; /* the first non-wildcard match point */
	Match lastmatch;

	if( fsp == NULL )
		fsp = fa_root;

	/* asp = the entry state for preamble wildcard if exists */
	if( fsp->other == fsp )
		asp = fsp->other;
	else	asp = 0;

	if( start ){
		if( asp == 0 || fsp->xclass || fsp->eclass )
			lsp = input;
		else	lsp = 0;
	}

	lastmatch.m_fsp = 0;
	for( ss = input; cc = *ss; ss++ ){
		if( fsp->xclass ){
			if( shortest )
				break;
			lastmatch.m_fsp = fsp;
			lastmatch.m_top = (unsigned char*)lsp;
			lastmatch.m_next = (unsigned char*)ss;
		}

		nfsp = next(fsp,cc);
		if( nfsp == NULL || fa_backed ){
			if( lastmatch.m_fsp )
				break;
		}
		if( fa_backed )
			lsp = 0;

#ifdef DEBUG
printf("#### %X %X[%d] %8X %X %s\n",fsp,nfsp,fa_backed,lsp,ss,ss);
#endif

		if( nfsp == NULL ){
			if( NONEXT(fsp) && tail && fsp->other )
				while(*ss) ss++;
			break;
		}
		fsp = nfsp;
		if( start && asp != 0 ){
			if( lsp == 0 ){
				if( fsp != asp ) lsp = ss;
			}else{
				if( fsp == asp ) lsp = 0;
			}

		}
	}
	if( fsp->xclass == 0 && !(*ss == 0 && fsp->eclass) ){
		if( lastmatch.m_fsp ){
			fsp = lastmatch.m_fsp;
			lsp = lastmatch.m_top;
			ss = lastmatch.m_next;
		}
	}

	if( start ){
		if( lsp == 0 && *ss == 0 && fsp->eclass )
			lsp = ss;
		*start = lsp;
	}
	if( tail )
		*tail = ss;

	if( *ss == 0 && fsp->eclass )
		return fsp->eclass;

	return fsp->xclass;
}
static int fa_scan(FaStat *fsp,unsigned char *input,const unsigned char **tail)
{
	return fa_scanX(fsp,input,NULL,tail,0);
}

/*##############################*
 *   FA GENERATOR/INTERPRETER	*
 *##############################*/
static void fa_stcopy(FaStat *fsfrom,FaStat *fsto)
{
	fsto->lower = fsfrom->lower;
	fsto->upper = fsfrom->upper;
	fsto->Nstat = allocFaVect();
	if( fsto->Nstat && fsfrom->Nstat )
	*(fsto->Nstat) = *(fsfrom->Nstat);
}
static void fa_stvec_alloc(FaStat *fsp)
{
	fsp->lower = 0;
	fsp->upper = CHARSETSIZE;
	fsp->Nstat = allocFaVect();
}

static FaStat *fa_stins(FaStat *ofsp,FaStat *fsp,FaStat *nfsp,unsigned char in)
{	FaStat *cfsp;

	if(NEXT(fsp,in)){
		if(nfsp){
			if(NEXT(fsp,in) != nfsp){
			syslog_DEBUG("FA_stins: NON-DETERMINISTIC [%d]%c->?\n",
				fsp->stid,in);
			}
		}else{
			if(NEXT(fsp,in) == fsp){
				cfsp = fa_stnew(ofsp);
				SETNEXT(fsp,in, cfsp);
				fa_stcopy(fsp,cfsp);
			}
		}
	}else{
		if(nfsp == 0){
			cfsp = fa_stnew(ofsp);
			SETNEXT(fsp,in, cfsp);
		}else	SETNEXT(fsp,in, nfsp);
	}
	return NEXT(fsp,in);
}

/*##############################*
 *	FA GENERATOR		*
 *##############################*/
static long int fa_rexp(FaStat *ofsp,unsigned char *regexp,int xclass);
static long int fa_gen(unsigned char *regexp,int xclass)
{
	return fa_rexp(fa_root,regexp,xclass);
}

static unsigned char *
fa_macro_exp(unsigned char *regexp,unsigned char *regexpb,int inmeta)
{	const unsigned char *sp;
	const unsigned char *tp;
	CStr(id,1000);
	const char *rstr;

	if( (regexp[0] == '$') && (regexp[1] == '<') ){
		sp = regexp + 2;
		if( tp = (unsigned char*)strchr((char*)sp,'>') ){
			strncpy(id,(char*)sp,tp-sp); setVStrEnd(id,tp-sp);
/*
			rstr = (unsigned char*)tcap_s(id);
			if( *rstr ){
				unsigned char pat[1000]; //NL
				char temp[1000]; //NL
				SPRINTF(pat,"$<%s>",id);
				strsubs(regexp,temp,pat,rstr);
				if( inmeta )
					SPRINTF(regexpb,"$%s$",temp);
				else	STRCPY(regexpb,temp);
				return regexpb;
			}
*/
		}
	}
	return regexp;
}

static int expset(const unsigned char *lrep,const unsigned char *rrep,unsigned char *set)
{	int negate,setx;
	CStr(bset,512);
	int ch1,ch2,ch;

	if( *lrep == '^' ){
		lrep++;
		negate = 1;
	}else	negate = 0;

	for( ch = 0; ch < 256; ch++ )
		bset[ch] = negate ? 1 : 0;

	for(; lrep < rrep; lrep++ ){
		ch1 = lrep[0];
		if( lrep[1] == '-' ){
			ch2 = lrep[2];
			lrep += 2;
			if( ch2 < ch1 )
				continue;
		}else	ch2 = ch1;

		for( ch = ch1; ch <= ch2; ch++ )
			bset[ch] = negate ? 0 : 1;
	}

	setx = 0;
	for( ch = 0; ch < 0x80; ch++ ){
		if( bset[ch] )
			set[setx++] = ch;
	}
	set[setx] = 0;
	return setx;
}

static int fa_nosetrep;
static long int fa_rexp(FaStat *ofsp,unsigned char *regexp,int xclass)
{	const unsigned char *rep;
	const unsigned char *lrep;
	CStr(set,512);
	char setx,ch;
	FaStat *fsp,*fsps;
	int metachar_on = fa_metachar;
	CStr(regexpb,2000);
	FaStat *lastany;

	lastany = 0;
	fsp = ofsp;
	for(rep = regexp; *rep; rep++){
	  if( 2 < LOGLEVEL )
		syslog_ERROR("-- fa_rexp: %s\n",rep);

#ifdef DEBUG
printf("#### %X %X %s\n",ofsp,fsp,rep);
#endif

	  if(*rep == '$' && rep[1] == 0 ){
		fsp->eclass = xclass;
		return (long int)fsp;
	  }
/*
	  if(*rep == '$')
		rep = fa_macro_exp(rep,regexpb,metachar_on);
*/

	  if(*rep == '$'){
		if((rep[1] == '$')||(rep[1] == 0))
			fsp = fa_stins(ofsp,fsp,0,*rep);
		else	metachar_on = !metachar_on;

	  }else if( !metachar_on )
		fsp = fa_stins(ofsp,fsp, 0 ,*rep);

	  else switch(*rep){
		case '*':
			if( rep[1] == '*' ){
				fsp->other = fsp;
				lastany = fsp;
				rep++;
			}
			break;

		case '[':
			lrep = ++rep;
			for(rep++; *rep; rep++)
				if(*rep == ']')
					break;

			if( lrep[0] == ']' ){
				fsps = fa_stnew(ofsp);
				fsp->other = fsps;
				fsp = fsps;
				break;
			}

			setx = expset(lrep,rep,(unsigned char*)set);

			if(rep[1] == '*' && !fa_nosetrep)
				fsps = fa_stins(ofsp,fsp,fsp,set[0]);
			else	fsps = fa_stins(ofsp,fsp,  0,set[0]);

			for( ch = 1; ch < setx; ch++ )
				fsps = fa_stins(ofsp,fsp,fsps,set[ch]);

			fsp = fsps;
			break;

		case '.':
		default:
			if(rep[1] == '*'&& rep[2] != '*' )
				fsp = fa_stins(ofsp,fsp,fsp,*rep);
			else	fsp = fa_stins(ofsp,fsp, 0 ,*rep);
			if( fsp == 0 ){
				syslog_ERROR("fa_rexp: %X[%s] -> NULL [%s]\n",
					p2i(ofsp),rep,regexp);
				return 0;
			}
			fsp->other = lastany;
	    }
	}
	fsp->xclass = xclass;
/*
fa_ls();
*/
	return (long int)fsp;
}

FaStat *frex_append(FaStat *fsp,PCStr(rexp))
{	char ch;
	const char *sp;
	CStr(rexpb,1024);
	refQStr(rp,rexpb); /**/
	const char *xp;

	xp = rexpb + sizeof(rexpb) -1;
	for( sp = rexp; ch = *sp; sp++ ){
		if( xp <= rp ){
			syslog_ERROR("frex_append: overflow: %s\n",rexp);
			break;
		}
		switch( ch ){
		case '*': setVStrPtrInc(rp,'*'); setVStrPtrInc(rp,'*'); break;
		case '?': setVStrPtrInc(rp,'['); setVStrPtrInc(rp,']'); break;
		default:  setVStrPtrInc(rp,ch);  break;
		}
	}
	setVStrEnd(rp,0);

	if( fsp == NULL )
		fsp = fa_init(NULL);
	fa_metachar = 1;
	fa_nosetrep = 1;
	fa_rexp(fsp,(unsigned char*)rexpb,'F');
	fa_nosetrep = 0;
	fa_metachar = 0;

	syslog_DEBUG("frex_append(%s) = %X\n",rexpb,p2i(fsp));
	return fsp;
}
FaStat *frex_create(PCStr(rexp))
{
	return frex_append((FaStat*)0,rexp);
}
char *frex_matchX(FaStat *fsp,PCStr(str),const char **start)
{	const char *tail;
	int xclass;

	xclass = fa_scanX(fsp,(unsigned char*)str,(const unsigned char**)start,(const unsigned char**)&tail,0);
	if( xclass == 'F' )
		return (char*)tail;
	else	return NULL;
}
char *frex_match(FaStat *fsp,PCStr(str))
{
	return frex_matchX(fsp,str,NULL);
}
void frex_free(FaStat *fsp)
{
	fa_free(fsp);
}



/*######################*
 *	TEST & Usage	*
 *######################*/
#ifdef MAIN
fa_test(){
	int i;
	char xclass;
	const char *tail;
	const char *next;
	CStr(line,1024);
	CStr(word,32);
	FaStat *fsp;

	static struct {
	  const	char	*rexp;
	  const	char	class;
	} rexps[] = {
		"[_a-zA-Z][_a-zA-Z0-9]*",'I',
		"[1-9][0-9]*.[0-9]*",	'R',
		"0.[0-9]*",		'R',
		".[0-9]*",		'R',
		"0",			'D',
		"[1-9][0-9]*",		'D',
		"0[0-7][0-7]*",		'O',
		"0[xX][0-9a-fA-F]*",	'X',
		"-abcd",		'D',
		"-abCD",		'D',
		0
	};
	static const char *syms[] = {
		"___1___",
		"_ab12XY",
		"123456.",
		"123.456",
		"0.12345",
		".123456",
		"0",
		"1234567",
		"0123456",
		"0x",
		"0x12abc",
		"0X12abc",
		"0X12abc+postfix",
		0
	};
	static struct {
	  const	char	*rexp;
		char	class;
	} romkan[] = {
		" ",				'1',
		"[aiueo]",			'1',
		"[kstnhmyrwgzdbv][aiueo]",	'2',
		"[ksctnhmrgzdb][hy][aiueo]",	'3',
		"j[aiueo]",			'2',
		"n[n']",			'2',
		"chi",				'3',
		"tsu",				'3',
		"xtu",				'3',
		"xtsu",				'3',
		"x[aiueo]",			'2',
		"xy[aiueo]",			'3',
		0
	};
	static const char *fsyms[] = {
		"abc123def456ghi",
		"xxabcxxdefxxghixx",
		"xxabcxxdefxxghi",
		"xxabcxxdefghi",
		"xxabcdefghi",
		"axxbcdefghi",
		"abxxcdefghi",
		"abcxxdefghi",
		"abcdxxefghi",
		"abcdexxfghi",
		"abcdefxxghi",
		"abcdefgxxhi",
		"abcdefghxxi",
		"abcdefghixx",
		"abcdefghi",
		"abcdefgh",
		0
	};

	fa_metachar = 1;

	fsp = frex_create("w*o");
	fa_ls();
	tail = frex_match(fsp,"windows.o");
	syslog_DEBUG("%s %x [%s]\n","windows.o",tail,tail?tail:"");
	tail = frex_match(fsp,"winserv.o");
	syslog_DEBUG("%s %x [%s]\n","winserv.o",tail,tail?tail:"");
	tail = frex_match(fsp,"windows.c");
	syslog_DEBUG("%s %x\n","windows.c",tail,tail);
	frex_free(fsp);
	getchar();

	fsp = frex_create("*abc*def*ghi*");
	fa_ls();
	for( i = 0; fsyms[i]; i++ ){
		tail = frex_match(fsp,fsyms[i]);
		syslog_DEBUG("(%2d/%2d): %s [%x]\n",
			tail?tail-fsyms[i]:0,strlen(fsyms[i]),
			fsyms[i],tail?*tail:-1);
	}
	frex_free(fsp);
	getchar();

	fsp = fa_init(NULL);
	syslog_DEBUG("#### GENERATE ####\n");
	for( i = 0; rexps[i].rexp; i++ ){
		syslog_DEBUG("%c : %-30s\n",rexps[i].class,rexps[i].rexp);
		fa_rexp(fsp,rexps[i].rexp,rexps[i].class);
	}

	syslog_DEBUG("#### STATUS ######\n");
	fa_ls();

	syslog_DEBUG("#### SCAN ########\n");
	for( i = 0; syms[i]; i++ ){
		class = fa_scan(fsp,syms[i],&tail);
		syslog_DEBUG("%c (%2d): %s\n",class, tail-syms[i], syms[i]);
	}
	fa_free(fsp);

	fsp = fa_init(NULL);
	for( i = 0; romkan[i].rexp; i++ )
		fa_rexp(fsp,romkan[i].rexp,romkan[i].class);

	for(;;){
		printf("ROMKAN>\n");
		if( gets(line) == 0 || line[0] == 0 )
			break;
		if( line[0] == 0 )
			break;
		for( next=line; 0 < (class=fa_scan(fsp,next,&tail)); next=tail ){
			strcpy(word,next);
			word[tail-next] = 0;
			printf("%c (%d) [%-3s] %s\n",class,tail-next,word,next);
		}
	}
	fa_free(fsp);
	fa_metachar = 0;
}
#endif
