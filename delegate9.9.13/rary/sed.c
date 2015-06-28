/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2000 Yutaka Sato
Copyright (c) 2000 Electrotechnical Laboratry (ETL), AIST, MITI

Permission to use, copy, and distribute this material for any purpose
and without fee is hereby granted, provided that the above copyright
notice and this permission notice appear in all copies.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	sed.c (small subset of sed)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	000607	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include "ystring.h"
#include "fpoll.h"

#define PATSIZE	128
#define LNSIZE	8*1024
#define SC_ECHO		0x1000
#define SC_GLOB		0x8000
#define SC_MATCH	0x0001
#define SC_PRINT	0x0010
#define SC_SUBST	0x0020
#define SC_DELETE	0x0040
#define ISBLANKLN(line)	(*line=='\r' || *line=='\n')

typedef struct _SedCom {
	int	 c_com;
	MStr(	 c_matchpat,PATSIZE);
	int	 c_matchtotail;
 struct fa_stat	*c_matchrex;
	MStr(	 c_srcpat,PATSIZE);
 struct fa_stat	*c_srcrex;
	MStr(	 c_outpat,PATSIZE);
struct _SedCom	*c_next;
} SedCom;
typedef struct sed_env {
	int	 s_noecho;
	int	 s_putlnum;	/* line number (cat -n) */
	int	 s_unbuff;	/* unbuffered output (cat -u) */
	int	 s_visual;	/* visualize non-printing char (cat -v) */
	int	 s_sbline;	/* to a single blank line (more -s) */
	int	 s_uniqln;	/* (uniq) */
	MStr(	 s_prevline,LNSIZE);
	SedCom	*s_com1;
	SedCom	*s_come;
} SedEnv;

SedEnv *sed_new()
{	SedEnv *se;

	se = (SedEnv*)calloc(1,sizeof(SedEnv));
	return se;
}
void sed_free(SedEnv *se)
{
}
static char *scan_pat(PCStr(str),int delch,PVStr(pat),int rexp,int skip)
{	const char *sp;
	char sc;
	refQStr(op,pat); /**/

	sp = str;
	if( rexp ){
		if( *sp == '^' ){
			sp++;
		}else{
			/**op++ = '.';*/
			setVStrPtrInc(op,'*');
		}
	}
	for(; sc = *sp; sp++ ){
		assertVStr(pat,op+1);
		if( sc == delch ){
			if( skip )
				sp++;
			break;
		}
		setVStrPtrInc(op,sc);
	}
	XsetVStrEnd(QVStr(op,pat),0);
	return (char*)sp;
}
static int scan_attail(char str[])
{	char sc;
	const char *sp;

	for( sp = (char*)str; sc = *sp; sp++ ){
		if( sc == '$' && sp[1] == 0 ){
			truncVStr(sp);
			return 1;
		}
	}
	return 0;
}
int sed_compile(SedEnv *se,PCStr(command))
{	const char *com;
	SedCom *sc;
	char delch;

	sc = (SedCom*)calloc(1,sizeof(SedCom));
	com = command;
	if( *com == '/' ){
		com = scan_pat(com+1,'/',AVStr(sc->c_matchpat),1,1);
		sc->c_matchtotail = scan_attail(sc->c_matchpat);
		sc->c_matchrex = frex_create(sc->c_matchpat);
	}
	switch( *com ){
	case 's':
		sc->c_com |= SC_SUBST;
		delch = com[1];
		com = scan_pat(com+2,delch,AVStr(sc->c_srcpat),1,0);
		sc->c_srcrex = frex_create(sc->c_srcpat);
		if( *com != delch ){
		}else{
			com = scan_pat(com+1,delch,AVStr(sc->c_outpat),0,0);
		}
		break;
	}
	for(; *com; com++ ){
		switch( *com ){
		case 'd': sc->c_com |= SC_DELETE; break;
		case 'g': sc->c_com |= SC_GLOB; break;
		case 'p': sc->c_com |= SC_PRINT; break;
		}
	}
	if( se->s_com1 == 0 )
		se->s_com1 = sc;
	if( se->s_come )
		se->s_come->c_next = sc;
	se->s_come = sc;
	return 0;
ERRORx:
	free(sc);
	return -1;
}
static char *sed_fmt(SedCom *sc,xPVStr(op),PCStr(spat),int len)
{	char fc;
	const char *fp;

	for( fp = sc->c_outpat; fc = *fp; fp++ ){
		assertVStr(op,op+1);
		if( fc == '&' ){
			memmove(op,spat,len);
			op += len;
		}else	setVStrPtrInc(op,fc);
	}
	setVStrEnd(op,0);
	return (char*)op;
}
static int apply_commands(SedEnv *se,PCStr(iline),PVStr(oline))
{	SedCom *sc;
	const char *start;
	const char *next;
	const char *ip;
	int len;
	int match = 0;
	CStr(lineb,LNSIZE);

	for( sc = se->s_com1; sc; sc = sc->c_next ){
		if( se->s_noecho && (sc->c_com & SC_PRINT) == 0 ){
			continue;
		}
		if( sc->c_matchrex ){
			if( next = frex_matchX(sc->c_matchrex,iline,&start) )
			{
				if( sc->c_matchtotail && *next != 0 )
					continue;
				match |= SC_MATCH;
			}
			else	continue;
		}
		if( sc->c_com & SC_DELETE ){
			match |= SC_DELETE;
			setVStrEnd(oline,0);
			lineb[0] = 0;
			iline = lineb;
			continue;
		}

		if( sc->c_srcrex ){
			refQStr(op,oline); /**/
			ip = iline;
			while( next = frex_matchX(sc->c_srcrex,ip,&start) ){
				assertVStr(oline,op+1);
				match |= SC_SUBST;
				len = start - ip;
				Xmemmove(QVStr(op,oline),ip,len);
				op += len;
				op = sed_fmt(sc,QVStr(op,oline),start,next-start);
				ip = next;
				if( (sc->c_com & SC_GLOB) == 0 )
					break;
			}
			strcpy(op,ip);
			strcpy(lineb,oline);
			iline = lineb;
		}
	}
	return match;
}
void sed_execute1(SedEnv *se,PCStr(in),PVStr(out),int err)
{
	apply_commands(se,in,AVStr(out));
}
void sed_execute(SedEnv *se,FILE *in,FILE *out,FILE *err)
{	CStr(iline,LNSIZE);
	CStr(oline,LNSIZE);
	CStr(vline,LNSIZE);
	int match,match1;
	SedCom *sc;
	const char *crp;
	CStr(crlfb,4);

	while( fgets(iline,sizeof(iline),in) != NULL ){
		if( se->s_noecho )
			match = 0;
		else	match = SC_ECHO;
		if( crp = strpbrk(iline,"\r\n") ){
			strncpy(crlfb,crp,sizeof(crlfb));
			truncVStr(crp);
		}
		strcpy(oline,iline);
		if( se->s_com1 ){
			match1 = apply_commands(se,iline,AVStr(oline));
			if( oline[0] == 0 && (match1 & SC_DELETE) )
				continue;
			match |= match1;
		}
		strcat(oline,crlfb);
		if( se->s_sbline ){
			if( ISBLANKLN(oline) )
			if( ISBLANKLN(se->s_prevline) )
				match = 0;
		}
		if( se->s_uniqln ){
			if( strcmp(oline,se->s_prevline) == 0 )
				match = 0;
		}
		if( match == 0 )
			continue;

		if( se->s_putlnum ){
			fprintf(out,"%6d\t",se->s_putlnum);
			se->s_putlnum++;
		}
		if( se->s_visual ){
			Str2vstr(oline,strlen(oline),AVStr(vline),sizeof(vline));
			fputs(vline,out);
		}else{
			fputs(oline,out);
		}
		if( se->s_unbuff && ready_cc(in) <= 0 )
			fflush(out);
		strcpy(se->s_prevline,oline);
	}
}

static FILE *fin,*fout;
int sed_main(int ac,const char *av[])
{	int ai;
	const char *arg;
	const char *ap;
	FILE *in,*out,*err;
	SedEnv *se;
	const char *com;
	int ifiles;

	if( ac <= 1 ){
		fprintf(stderr,"Usage: %s [-nsuNU] command [files]\n",av[0]);
		return -1;
	}

	se = sed_new();
	if( fout )
		out = fout;
	else	out = stdout;
	if( fin )
		in = fin;
	else	in = stdin;
	err = stderr;
	ifiles = 0;
	com = 0;
	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		if( strcmp(arg,"-e") == 0 ){
			arg = av[++ai];
			if( ai < ac ){
				com = arg;
				sed_compile(se,arg);
			}
		}else
		if( strcmp(arg,"-f") == 0 ){
		}else
		if( *arg == '-' ){
			for( ap = arg+1; *ap; ap++ ){
				switch( *ap ){
				case 'n': se->s_noecho = 1; break;
				case 's': se->s_sbline = 1; break;
				case 'u': se->s_unbuff = 1; break;
				case 'v': se->s_visual = 1; break;
				case 'N': se->s_putlnum = 1; break;
				case 'U': se->s_uniqln = 1; break;
				}
			}
		}else
		if( com == 0 ){
			com = arg;
			sed_compile(se,arg);
		}else{
			ifiles++;
			in = fopen(arg,"r");
			if( in == NULL ){
				fprintf(stderr,"%s: cannot open\r\n",arg);
				return -1;
			}
			sed_execute(se,in,out,err);
		}
	}
	if( ifiles == 0 ){
		sed_execute(se,in,out,err);
	}
	return 0;
}
void sedFilter(FILE *in,FILE *out,PCStr(comline),PCStr(args))
{	const char *av[128]; /**/
	CStr(argb,2048);
	int ac;

	ac = decomp_args(av,elnumof(av),comline,AVStr(argb));
	fin = in;
	fout = out;
	sed_main(ac,av);
}
