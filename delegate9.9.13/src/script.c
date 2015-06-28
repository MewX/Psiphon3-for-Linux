/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1995-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	script.c (DeleGate Script)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
	"..."		... is literal
	'...'		... is literal
	\c		c is litelal
	#...		... is comment
	CASE case	included when in the case
	ESAC [case]	end the case
	+=URL[#case-list]
History:
	950615	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "ystring.h"
#include "dglib.h"
#include "file.h"
#include "log.h"
#include "config.h"
#include "param.h" /* ArgComp */

FILE* fopenLIB(PCStr(file),PCStr(mode),PVStr(xpath));

#define SELF	"_SELF_"
int SCRIPT_ASIS;

#define RELATIVEx "+"

typedef struct {
  const	char	*sf_furl;
  const	char	*sf_aurl;
	FILE	*sf_sfp;
	int	 sf_off;
} ScriptFile;
typedef struct {
  const	char *se_pathv[32]; /**/
	int   se_pathx;
   ScriptFile se_scripts[32]; /**/
	char  se_scriptx;
} ScriptEnv;
static ScriptEnv *scriptEnv;
#define pathv		scriptEnv->se_pathv
#define pathx		scriptEnv->se_pathx
#define scripts		scriptEnv->se_scripts
#define scriptx		scriptEnv->se_scriptx
void minit_script()
{
	if( scriptEnv == 0 )
		scriptEnv = NewStruct(ScriptEnv);
}

static scanListFunc inspath(PCStr(path1))
{
	int pi;
	for( pi = 0; pi < pathx; pi++ ){
		if( streq(pathv[pi],path1) ){
			return 0;
		}
	}
	if( elnumof(pathv) <= pathx ){
		return -1;
	}
	pathv[pathx++] = (char*)path1;
	return 0;
}
extern const char *DELEGATE_DGPATH;
void scan_DGPATH(PCStr(path))
{	CStr(home,1024);
	CStr(xpath,2048);

	getHOME(getuid(),AVStr(home));
	strcpy(xpath,path);
	strsubst(AVStr(xpath),"${HOME}",home);
/*
	DELEGATE_substfile(AVStr(xpath),"",VStrNULL,VStrNULL,VStrNULL);
*/
	DELEGATE_substPath("DGPATH",':',xpath,AVStr(xpath));
	scan_List(xpath,':',1,scanListCall inspath);
}

static void eval_line(PCStr(file),PCStr(base),PCStr(line),PVStr(xline))
{	char ch;
	const char *sp;
	const char *dp;
	refQStr(command,xline); /**/
	FILE *fp;
	char lit = 0;
	refQStr(xp,xline); /**/
	const char *fix = xline;

	for( sp = line; ch = *sp; sp++ )
		if( ch != ' ' && ch != '\t' && ch != '\r' )
			break;

	while( ch = *sp ){
		assertVStr(xline,xp+1);
		if( ch == '\\' && sp[1] != 0  && lit == 0 ){
			setVStrPtrInc(xp,sp[1]);
			fix = xp;
			sp += 2;
		}else
		if( (ch == '"' || ch == '\'') && lit == 0 ){
			lit = ch;
			sp++;
		}else
		if( (ch == '"' || ch == '\'') && lit == ch ){
			lit = 0;
			sp++;
			fix = xp;
		}else
		if( ch == '`' && lit == 0 ){
			lit = ch;
			sp++;
			command = xp;
		}else
		if( ch == '`' && lit == ch ){
			lit = 0;
			sp++;
			setVStrEnd(xp,0);

			if( fp = popen(command,"r") ){
				fgets(command,256,fp);
				pclose(fp);
				if( dp = strpbrk(command,"\r\n") )
					truncVStr(dp);
				xp = command+strlen(command);
				fix = xp;
			}
		}else
		if( ch == '#' && lit == 0 ){
			break;
		}else{
			setVStrPtrInc(xp,*sp++);
			if( ch != ' ' && ch != '\t' && ch != '\r' )
				fix = xp;
		}
	}
	truncVStr(fix);
	if( lit != 0 )
		fprintf(stderr,"%s: unmatched (%c): %s\n",file,lit,line);
}
void conf_eval_line(PCStr(line),PVStr(xline)){
	eval_line("","",line,BVStr(xline));
}

static scanListFunc case_match(PCStr(ccase),PCStr(tcase))
{
	return strcmp(ccase,tcase) == 0;
}
static int in_case(PCStr(cases),PCStr(case1))
{	int match;

	match = scan_List(cases,'+',0,scanListCall case_match,case1);
	return match;
}

int getFoldedEnc(FILE *sfp,PVStr(enc),PCStr(encx));

int (*evalarg_func)(const char*,const char*);
void CTX_eval_script(DGC*Conn,FILE *sfp,PCStr(name),PCStr(base),PCStr(url),PCStr(cases),int encrypted,ArgComp *Acmp)
{	CStr(argb,0x4000);
	refQStr(argp,argb);
	refQStr(vp,argb); /**/
	CStr(valueb,4096);
	const char *dp;
	CStr(com,1024);
	ACStr(blocks,8,32);
	CStr(actives,8);
	CStr(block1,32);
	int blockx,bi;
	int nline;
	int active;
	int ign = 0;

	if( lFG() && !lQUIET() ){ /* with -f and without -vq */
		sprintf(argb,"#### loading conf: %s -> %s",base?base:"",url);
		fprintf(stderr,"%s\n",argb);
	}

	if( name ){
		sprintf(argb,"%s",name);
		argp = argb + strlen(argb);
	}else	argp = argb;

	vp = (char*)argp;
	blockx = 0;

	active = !in_case(cases,SELF);

/*
if( active )
 fprintf(stderr,"%d %s\n",active,url);
*/

	/*
	for( nline = 1; fgets(valueb,sizeof(valueb),sfp) != NULL; nline++ ){
	*/
	for( nline = 1; ; nline++ ){
		if( str_fgets(AVStr(valueb),sizeof(valueb),sfp) == NULL ){
			break;
		}
		if( strneq(valueb,"+=enc:",6) ){
			/* short-cut bypassing tmpfile for URLget(enc:) */
			CStr(ext,64*1024);
			strcpy(ext,valueb+6);
			getFoldedEnc(sfp,AVStr(ext),&ext[sizeof(ext)-1]);
			CTX_load_encrypted(Conn,name,base,ext);
			continue;
		}

		if( lARGDUMP() )
			fprintf(stderr,"%s: %s",url,valueb);
		if( dp = strpbrk(valueb,"\r\n") )
			truncVStr(dp);

		if( SCRIPT_ASIS )
			strcpy(vp,valueb);
		else	eval_line(url,base,valueb,AVStr(vp));

		wordScan(vp,com);
		if( Acmp && scanArgComp(AVStr(com),vp) ){
			if( ArgCompArg){
				strcpy(argp,ArgCompArg);
				free((char*)ArgCompArg);
				ArgCompArg = 0;
				scan_arg1(Conn,url,argb);
			}
			continue;
		}
		if( strcmp(com,"END") == 0 ){
			break;
		}
		if( strcmp(com,"IGN++") == 0 ){
			ign++;
		}else
		if( strcmp(com,"IGN--") == 0 ){
			ign--;
		}
		if( 0 < ign ){
			continue;
		}

		if( strcmp(com,"CASE") == 0 ){
			if( elnumof(actives) <= blockx ){
				break;
			}
			setVStrElem(actives,blockx,active); /**/
			Xsscanf(vp,"%*s %s",EVStr(blocks[blockx]));
			active = in_case(cases,blocks[blockx]);
			if( 0 < blockx )
				active &= actives[blockx];
			blockx++;
/*
if( active )
 fprintf(stderr,"%d [%d] %s\n",active,blockx,vp);
*/
		}else
		if( strcmp(com,"ESAC") == 0 ){
			block1[0] = 0;
			Xsscanf(vp,"%*s %s",AVStr(block1));
			if( block1[0] ){
			    for( bi = blockx - 1; 0 <= bi; bi-- ){
				if( strcmp(block1,blocks[bi]) == 0 ){
					blockx = bi;
					break;
				}
			    }
			    if( bi < 0 ){
				fprintf(stderr,"\"%s\":%d unmatched ESAC %s\n",
					url,nline,block1);
				break;
			    }
			}else	blockx--;
			active = actives[blockx];
/*
 fprintf(stderr,"%d [%d] %s\n",active,blockx,vp);
*/
		}else
		if( active ){
			if( *argp )
			{
				if( lSECUREEXT() && !encrypted ){
		fprintf(stderr,"---- Not encrypted: %s: %s\n",url,argb);
					Finish(-1);
				}else
				if( evalarg_func )
					(*evalarg_func)(url,argb);
				else
				scan_arg1(Conn,url,argb);
			}
		}
	}
	if( Acmp ){
		flushArgComp();
		if( ArgCompArg ){
			strcpy(argp,ArgCompArg);
			free((char*)ArgCompArg);
			ArgCompArg = 0;
			scan_arg1(Conn,url,argb);
		}
		freeArgComp();
	}
}

#include "auth.h"
extern char DGAUTHadmdom[];
extern char DGAUTHdom[];
int credhy_main(int ac,const char *av[]);
int encrypted_script(PCStr(name)){
	if( strtailstr(name,".gpg") )
		return 1;
	if( strtailstr(name,".cdh") )
		return 1;
	return 0;
}
int CredhyFile(int com,PCStr(p1),PCStr(p2),PCStr(px),FILE *in,FILE *out);
static FILE *decrypt_script(PCStr(aurl),FILE *sfp){
	CStr(gpg,128);
	CStr(in,128);
	CStr(pass,128);
	FILE *dec;
	int sfd;
	int dfd;
	int elen;

	if( !encrypted_script(aurl) )
		return sfp;

	elen = getDigestPass(DGAUTHadmdom,"config",AVStr(pass));
	if( elen == 0 )
	elen = getDigestPass(DGAUTHdom,"config",AVStr(pass));

	sfd = dup(fileno(stdin));
	dup2(fileno(sfp),fileno(stdin));

	if( strtailstr(aurl,".cdh") ){
		FILE *tmp;
		tmp = TMPFILE("decrypt_script");
		if( 0 < elen ){
/*
			const char *av[4];
			av[0] = "credhy";
			av[1] = pass;
			av[2] = "-d";
			av[3] = 0;
			dfd = dup(fileno(stdout));
			dup2(fileno(tmp),fileno(stdout));
			credhy_main(3,av);
			fflush(stdout);
			fseek(tmp,0,0);
			dup2(dfd,fileno(stdout));
			dup2(sfd,fileno(stdin));
*/
			CredhyFile(0,pass,NULL,NULL,sfp,tmp);
			bzero(pass,sizeof(pass));
			fflush(tmp);
			fseek(tmp,0,0);
			dup2(sfd,0);
			return tmp;
		}
		fprintf(stderr,"**** ignored: cannot decrypt %s\n",aurl);
		dup2(sfd,0);
		return tmp;
	}

	if( 0 < elen ){
		int pp[2];
		IGNRETZ pipe(pp);
		IGNRETP write(pp[1],pass,strlen(pass));
		bzero(pass,sizeof(pass));
		sprintf(gpg,"gpg --passphrase-fd %d --no-tty --decrypt",pp[0]);
		close(pp[1]);
	}else{
		sprintf(gpg,"gpg --decrypt --no-tty");
	}
	fprintf(stderr,"**** %s [%s]\n",gpg,aurl);
	dec = popen(gpg,"r");
	dup2(sfd,0);
	return dec;
}

FILE *openPurl(PCStr(base),PCStr(purl),PVStr(aurl))
{
	FILE *sfp,*psfp;
	int sfd;
	int ii;
	CStr(line,1024);

	if( purl[0] == 0 )
		strcpy(aurl,base);
	else
	if( base == NULL || purl[0] == '/' || isLoadableURL(purl) )
		strcpy(aurl,purl);
	else{
		strcpy(aurl,base);
		strcat(aurl,"/");
		strcat(aurl,purl);
	}
	StrSubstDate(AVStr(aurl));

	sfp = NULL;
	for( ii = 0; ii < scriptx; ii++ ){
	    if( strcmp(aurl,scripts[ii].sf_aurl) == 0 ){
		if( psfp = scripts[ii].sf_sfp ){
			sfd = dup(fileno(psfp));
			sfp = fdopen(sfd,"r");
			fseek(sfp,scripts[ii].sf_off,0);
		}
	    }
	}
	if( sfp == NULL ){
		if( isLoadableURL(aurl) ){
			sfp = TMPFILE("openPurl");
			URLget(aurl,1,sfp);
		}else	sfp = fopenLIB(aurl,"r",AVStr(aurl));
	}
	return sfp;
}
int set_svtrace(int code);
int getConfig(PCStr(name),PVStr(path));
extern int ERROR_RESTART;
int SCRIPT_UNKNOWN;
int config_FD = -1;
int set_svname(PCStr(name));

int CTX_load_script(DGC*Conn,PCStr(name),PCStr(base),PCStr(purl))
{	FILE *sfp;
	const char *path1;
	CStr(purlb,1024);
	CStr(aurl,1024);
	CStr(furl,1024);
	const char *furl1;
	CStr(dir1,1024);
	CStr(cases,1024);
	const char *dp;
	int pi,ii,jj;
	int rewind = -1;
	int lockfd = -1;
	int rstat;

	IStr(xpurl,1024);
	defineArgComp;
	initArgComp();
	if( *purl == '{' ){
		dp = wordScanY(purl+1,xpurl,"^}");
		purl = xpurl;
		if( *dp == '}' ){
			ArgCompRem = dp+1;
		}
	}
	if( *purl == '[' ){
		IStr(opts,128);
		dp = wordScanY(purl+1,opts,"^]");
		if( *dp == ']' ){
			purl = dp+1;
			if( isinListX(opts,"L","") ){
				ArgCompMode |= AC_LIST;
			}
		}
	}

	if( strchr(purl,'?') ){
		strcpy(purlb,purl);
		purl = purlb;
		dp = strchr(purlb,'?');
		strcpy(cases,dp+1);
		truncVStr(dp);
	}else	cases[0] = 0;

	sfp = NULL;
	if( strneq(purl,"fd:",3) ){
		int fd = -1;
		int sfd = -1;
		sscanf(purl+3,"%d",&fd);
		if( 0 <= fd ){
			sfd = dup(fd);
			sfp = fdopen(sfd,"r");
		}
		if( sfp == NULL ){
		fprintf(stderr,"### [%d] Cannot open +=%s\n",getpid(),purl);
			if( lSTRICT() ){
				set_svtrace(-1);
				Finish(-1);
			}
			return -1;
		}
		if( 1 ){
			if( isWindows() ){
				/* locking the config seems to stop reading
				 * it from other process...
				 */
			}else{
				rstat = lock_sharedNB(fd);
			}
			if( config_FD < 0 ){
				config_FD = fd;
			}
			lockfd = fd;
			rewind = fd;

/*
fprintf(stderr,"### OPENED[%d] +=%s, set config_FD=%d OFF=%d/%d\n",
getpid(),purl,fd,ftell(sfp),file_size(sfd));
fprintf(stderr,"### lockfd=%d shlock=%d, config_FD=%d\n",lockfd,rstat,config_FD);
*/
		}
	}
	clearVStr(aurl);
	if( name == NULL && base == NULL && isFullpath(purl) ){
		sfp = fopen(purl,"r");
		if( sfp != NULL ){
			/* 9.8.2 to cope with "+=C:/path" or so on Win */
			sprintf(aurl,"file:%s",purl);
		}
	}
	if( sfp == NULL ){
		CStr(path,1024);
		if( getConfig(purl,AVStr(path)) ){
			sfp = fopen(path,"r");
			if( sfp != NULL ){
				lockfd = dup(fileno(sfp));
				if( isWindows() ){
				}else{
					rstat = lock_sharedNB(lockfd);
				}
				rewind = lockfd;
				set_svname(purl);
/*
fprintf(stderr,"----script lock_shared=%d %d %s\n",rstat,lockfd,purl);
*/
			}else{
			}
		}else{
		}
	}
	if( sfp == NULL )
	for( pi = 0; path1 = pathv[pi]; pi++ ){
		if( strcmp(path1,"+") == 0 ){
			if( base == NULL )
				continue;
			if( purl[0] == 0 )
				path1 = base;
			else
			if( strrchr(base,'/') ){
				strcpy(dir1,base);
				*strrchr(dir1,'/') = 0;
				path1 = dir1;
			}else	path1 = "";
		}
		if( (sfp = openPurl(path1,purl,AVStr(aurl))) != NULL )
			break;
	}
/*
	if( sfp == NULL ){
*/
	if( sfp == NULL || feof(sfp) ){
		SCRIPT_UNKNOWN++;
		/*
		fprintf(stderr,"load_script: Cannot open [%s]'%s'\n",purl,aurl);
		*/
		fprintf(stderr,"load_script: Cannot open [%s]'%s' DGPATH=%s\n",
			purl,aurl,DELEGATE_DGPATH);
		iLog("--E load_script: Cannot open [%s]'%s'",purl,aurl);
		return -1;
	}
	if( cases[0] )
		sprintf(furl,"%s#%s",aurl,cases);
	else	sprintf(furl,"%s",aurl);

	for( ii = 0; ii < scriptx; ii++ ){
		furl1 = scripts[ii].sf_furl;
		if( strcmp(furl1,furl) == 0 ){
			fprintf(stderr,
				"DeleGate ERROR: loop in script: %s -> %s\n",
				base,purl);
			for( jj = 0; jj < scriptx; jj++ )
				fprintf(stderr,"[%d] %s\n",jj,scripts[jj].sf_furl);
			fprintf(stderr,"[%d] %s\n",jj,furl);
			return -1;
		}
	}

	if( elnumof(scripts) <= scriptx ){
		fprintf(stderr,"ERROR: scripts nest too deep: %s -> %s\n",
			base,purl);
		return -1;
	}

	if( base != NULL && strcmp(aurl,base) == 0 ){
		if( cases[0] != 0 )
			strcat(cases,"+");
		strcat(cases,SELF);
	}
	scripts[scriptx].sf_aurl = aurl;
	scripts[scriptx].sf_furl = furl;
	scripts[scriptx].sf_sfp = sfp;
	scripts[scriptx].sf_off = ftell(sfp);

	scriptx++;

	sfp = decrypt_script(aurl,sfp);
	CTX_eval_script(Conn,sfp,name,base,aurl,cases,encrypted_script(aurl),
		Acmp);
	scriptx--;

	if( file_isfifo(fileno(sfp)) ){
		pclose(sfp);
	}else
	fclose(sfp);

	if( 0 <= rewind ){
		Lseek(rewind,0,0);
	}
	return 0;
}

FILE *loadIntoFile(PCStr(url),xPVStr(aurl)){
	FILE *fp;
	IStr(xurl,1024);

	if( aurl == 0 )
		setQStr(aurl,xurl,sizeof(xurl));
	if( isLoadableURL(url) ){
		fp = TMPFILE("loadIntoFile");
		URLget(url,1,fp);
	}else   fp = fopenLIB(url,"r",AVStr(aurl));
	return fp;
}
char *loadListFile(PCStr(url)){
	FILE *fp;
	int fsize,bsize;
	char *bp;
	defQStr(dp);
	IStr(line,1024);
	int li;

	fp = loadIntoFile(url,VStrNULL);
	if( fp == 0 ){
		return 0;
	}
	fsize = file_size(fileno(fp)) - ftell(fp);
	bsize = fsize * 2 + 1;
	bp = (char*)malloc(bsize);
	setQStr(dp,bp,bsize);

	for( li = 0; ; li++ ){
		if( Fgets(AVStr(line),sizeof(line),fp) == NULL )
			break;
		Rsprintf(dp,"%s%s",0<li?",":"",line);
	} 
	fclose(fp);
	return bp;
}
char *substListFile(PCStr(baseurl),PCStr(str),PCStr(bpat),PCStr(epat)){
	const char *sp;
	const char *np;
	char *lp;
	IStr(xstr,8*1024);
	refQStr(dp,xstr);
	IStr(url,1024);
	int nexp = 0;
	int plen = strlen(bpat);
	IStr(xepat,32);

	sprintf(xepat,"^%s",epat);
	for( sp = str; *sp; sp++ ){
		if( *sp == *bpat && strneq(sp,bpat,plen) ){
			np = wordScanY(sp+plen,url,xepat);
			if( *np && strchr(epat,*np) ){
				sp = np + 1;
				if( lp = loadListFile(url) ){
					nexp++;
					Rsprintf(dp,"%s",lp);
					free(lp);
				}
			}else{
			}
		}else{
			setVStrPtrInc(dp,*sp);
		}
	}
	if( nexp ){
		return stralloc(xstr);
	}
	return 0;
}

int _initArgComp(ArgComp *Acmp){
	bzero(Acmp,sizeof(ArgComp));
	ArgCompAn = MAX_ARGC;
	ArgCompAv = (char**)malloc(sizeof(char*)*ArgCompAn);
	return 0;
}
int _freeArgComp(ArgComp *Acmp){
	if( ArgCompArg ){
		free((char*)ArgCompArg);
	}
	free((char*)ArgCompAv);
	return 0;
}
int _inArgComp(ArgComp *Acmp,PCStr(arg)){
	if( strtailstr(arg,INC_SYM) ){
		ArgCompMode |= AC_INC;
		return 1;
	}
	if( streq(arg,ACAT_IN) ){
		ArgCompMode |= AC_CAT;
		return 1;
	}
	if( streq(arg,ALIST_IN) ){
		ArgCompMode |= AC_LIST;
		return 1;
	}
	return 0;
}
int _outArgComp(ArgComp *Acmp,PCStr(arg)){
	if( streq(arg,ACAT_OUT) ){
		return 1;
	}
	if( streq(arg,ALIST_OUT) ){
		return 1;
	}
	if( streq(arg,"}") ){
		return 1;
	}
	if( streq(arg,".") ){
		return 1;
	}
	return 0;
}
int _isinArgComp(ArgComp *Acmp,PCStr(arg)){
	if( streq(arg,ACAT_OUT) ){
		return 0;
	}
	if( streq(arg,ALIST_OUT) ){
		return 0;
	}
	if( streq(arg,"}") ){
		return 0;
	}
	if( streq(arg,".") ){
		return 0;
	}
	if( ArgCompMode ){
		return 1;
	}
	return 0;
}
char *_catArgComp(ArgComp *Acmp){
	int ac = ArgCompAc;
	int ai;
	int len;
	defQStr(ap);
	const char *arg;

	len = 0;
	if( ArgCompAn <= ac ){
		fprintf(stderr,"--- catArg overflow %d/%d\n",ac,ArgCompAn);
		ac = ArgCompAn;
	}
	for( ai = 0; ai < ac; ai++ ){
		len += strlen(ArgCompAv[ai]) + 1;
	}
	if( ArgCompRem ){
		len += strlen(ArgCompRem) + 1;
	}
	setQStr(ap,(char*)malloc(len),len);
	arg = ap;
	for( ai = 0; ai < ac; ai++ ){
		if( ArgCompMode & AC_LIST ){
			if( ArgCompMode & AC_INC ){
				if( 1 < ai ){
					Rsprintf(ap,"%s",",");
				}
			}else{
				if( 0 < ai ){
					Rsprintf(ap,"%s",",");
				}
			}
		}
		Rsprintf(ap,"%s",ArgCompAv[ai]);
	}
	if( ArgCompRem ){
		Rsprintf(ap,"%s",ArgCompRem);
	}
	if( ArgCompMode & AC_CAT ){
		ArgCompMode &= ~AC_CAT;
	}
	if( ArgCompMode & AC_LIST ){
		ArgCompMode &= ~AC_LIST;
	}
	if( ArgCompMode == AC_INC ){
		ArgCompMode = 0;
	}
	/*
	fprintf(stderr,"++CompArg: %s\n",arg);
	*/
	return (char*)arg;
}
int _flushArgComp(ArgComp *Acmp){
	if( 0 < ArgCompAc ){
		ArgCompArg = _catArgComp(Acmp);
		ArgCompAc = 0;
		return 1;
	}
	return 0;
}
int _scanArgComp(ArgComp *Acmp,PVStr(com),PCStr(line)){
	if( _inArgComp(Acmp,com) ){
		if( ArgCompMode == AC_INC ){
			refQStr(cp,com);
			if( cp = strstr(com,INC_SYM) ){
				clearVStr(cp);
			}
			ArgCompAc = 0;
			ArgCompAv[ArgCompAc++] = stralloc(com);
		}else
		if( (ArgCompMode & AC_INC) == 0 ){
			ArgCompAc = 0;
		}
		return 1;
	}
	if( _outArgComp(Acmp,com) ){
		ArgCompArg = _catArgComp(Acmp);
		ArgCompAc = 0;
		return 1;
	}
	if( _isinArgComp(Acmp,com) ){
		if( *com == 0 || *com == '#' ){
		}else
		if( ArgCompAn <= ArgCompAc ){
			ArgCompAc++;
			fprintf(stderr,"--- scanArg overflow [%d/%d] %s\n",
				ArgCompAc,ArgCompAn,line);
		}else{
			if( com[0] == '.' && com[1] == '.' )
				ArgCompAv[ArgCompAc++] = stralloc(com+1);
			else	ArgCompAv[ArgCompAc++] = stralloc(com);
		}
		return 1;
	}
	return 0;
}
