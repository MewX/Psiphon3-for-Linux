/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1997-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2009 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	mkmake.c (Makefile preprocessor)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970105	created
//////////////////////////////////////////////////////////////////////#*/
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#define elnumof(a)      (sizeof(a)/sizeof(a[0]))

#define MaxARGV	256
#define MaxARGB	4*1024

#define MKMKMK_EXE "mkmkmk.exe"
#define SRCFILE_LIST	"srcfiles"

#include <fcntl.h>
#ifdef O_BINARY
int _fmode;
static void setBinaryIO(){ _fmode = O_BINARY; }
#else
static void setBinaryIO(){ }
#endif

#include <sys/types.h>
#include <sys/stat.h>
#ifdef S_ISUID /* set UID on execution */
#define MaybeOnUnix	1
#else
#define MaybeOnUnix	0
#endif

#ifdef _MSC_VER
/*########################################### MSWIN ############*/
#define SYST		"MSWIN"
#define BESILENT	"-s -nologo"
#define CCOUT		"/Fo"
#include <process.h>
#define pipe(sv)	_pipe(sv,0x4000,O_BINARY)
#define popen(com,mod)	_popen(com,mod)
#define pclose(fp)	_pclose(fp)
#define sleep(s)	_sleep(s*1000)
#define QUOTE_ARG
#define RETRY_RENAME
#define WITH_SPAWN
#include <direct.h>

#else /* !_MSC_VER */
#ifdef __EMX__
/*########################################### OS2EMX ###########*/
#define SYST		"OS2EMX"
#define BESILENT	"-s"
#define CCOUT		"-o "
#include <process.h>
#define WITH_SPAWN

#else /* !__EMX__ */
/*########################################### UNIX #############*/
#include <unistd.h>
#define SYST		"UNIX"
#define BESILENT	"-s"
#define CCOUT		"-o "
#include <sys/wait.h>
#ifndef WEXITSTATUS
#define WEXITSTATUS(status)	((status >> 8) & 0xFF)
#endif

#endif /* __EMX__ */
#endif /* _MSC_VER */

static char *GETCWD(char *cwd,int size)
{
#ifdef MKMKMK
	fprintf(stderr,"#### getcwd() is not available in mkmkmk.\n");
	return NULL;
#else
	return getcwd(cwd,size);
#endif
}

static const char *STRSTR(const char *s1,const char *s2)
{	int len;

	len = strlen(s2);
	for(; *s1; s1++ )
		if( *s1 == *s2 && strncmp(s1,s2,len) == 0 )
			return s1;
	return NULL;
}

static const char *_pathsep;
static const char *_PATHSEP(){
	char cwd[1024]; /**/
	if( _pathsep == NULL ){
		GETCWD(cwd,sizeof(cwd));
		if( strchr(cwd,'\\') )
			_pathsep = "\\";
		else	_pathsep = "/";
	}
	return _pathsep;
}
#define PATHSEP _PATHSEP()

static const char *_exeext;
static const char *_EXEEXT(){
	return 0;
}

static int p2i(const void *p){
	union {
		const void *p;
		int i;
	} u;
	u.p = p;
	return u.i;
}
static int z2i(unsigned long z){
	return (int)z;
}

int which(const char *command,char *path,int size);
char *addArg(char **pp,const char *name,const char *value);
int _available(FILE *errlog,const char *sym,const char *cc,const char *flags,const char *libs);
int e_available(FILE *errlog,const char *sym,const char *cc,const char *flags,const char *libs);
void cklibs(FILE *out,const char *make);
int cksum(const char *file);
int EXECVPR(const char *path,const char *av[]);
void EXECVP(const char *path,const char *av[]);
int mksubst(int ac,const char *av[]);
int _mksubst(const char *files,int mac,const char *filev[]);
int manifest_make(const char *files);
int manifest_check(const char *files);
int lnconf(int ac,const char *av[]);
int ckconf(int ac,const char *av[]);
int makeat(int ac,const char *av[]);
int makeit(int ac,const char *av[]);
int lkfile(int ac,const char *av[]);
int mkmake(int ac,const char *av[]);
int libmake(const char *files,const char *target,const char *listname);
int randtext(int ac,const char *av[]);
int check_env();
int execMake(const char *what,const char *aav[],int spawn);
int renames(const char *old,const char *xnew);
int msystem(int erralso,char res[],int size,const char *command);
int cpyfile(const char *out,const char *mode,const char *in,const char *from,const char *to,int useifdef);
int putfile(const char *out,const char *mode,const char *str);
int matchList(const char *list,const char *word);
int sysgethostname(char *hostname,int size);

typedef int substFunc(const char *file,const char *filev[],int *filecp);
int foreach_word(const char *list,substFunc func,const char *fv[],int *fcp);
int callMake(const char *what,const char *aav[]);
int Execvp(const char *path,const char *argv[]);
int waitPid(int pid);
void setSIGINT(const char *what);

FILE *ERRLOG;

#if defined(NONCPLUS)
#define NonCPlus 1 /* cc without c++ */
#else
#define NonCPlus 0
#endif

#ifdef __cplusplus
int CPP = 1;
#else
int CPP = 0;
#endif

#if defined(QSC)
int _QSC = 1;
#else
int _QSC = 0;
#endif

#ifdef NONC99
int _NONC99 = 1;
#else
int _NONC99 = 0;
#endif

#ifdef NONAZ0
int _NONAZ0 = 1;
#else
int _NONAZ0 = 0;
#endif

#define C99TEST "#define M(x,...) B(x,##__VA_ARGS__)\nint M(int,int);"
#define C99TEST2 "struct _S{char A[0]; char B[1];}S;"
#define C99TEST3 "struct _S{char A[]; char B[1];}S;"
#define C99TEST4 "struct _S{char A[1]; char B[0];}S;"
static FILE *erronly;
void checkC99(const char *Cc,const char *Cflags,const char *Cflagsplus){
	char cflags[1024];
	char hostname[128];

	sprintf(cflags,"-c %s %s",(Cflags!=0)?Cflags:"",Cflagsplus);
	if( strstr(Cc,"g++")
	 || strstr(cflags,"-x c++")
	 || strstr(cflags,"-TP")
	){
		CPP++;
	}
#ifndef _MSC_VER
	erronly = fdopen(dup(fileno(stderr)),"a");
	fprintf(stderr,"      ---- testing CC capability [%s][%s][%s] ...\n",
		Cc,Cflags,Cflagsplus);
	if( _NONC99 == 0 ){
		if( strstr(cflags,"-DNONC99") != 0 )
			_NONC99 = 2;
		else
		if( _available(erronly,C99TEST,Cc,cflags,"") == 0 )
			_NONC99 = 3;
		else
		if( _available(erronly,C99TEST2,Cc,cflags,"") == 0 )
		if( _available(erronly,C99TEST3,Cc,cflags,"") )
			_NONC99 = 4;
		else
		if( _available(erronly,C99TEST4,Cc,cflags,"") )
			_NONC99 = 5;
		else	_NONC99 = 6;
	}
	if( _NONAZ0 == 0 ){
		if( _available(erronly,C99TEST2,Cc,cflags,"") == 0 )
		if( _available(erronly,C99TEST3,Cc,cflags,"") )
			_NONAZ0 = 4;
		else
		if( _available(erronly,C99TEST4,Cc,cflags,"") )
			_NONC99 = 5;
		else	_NONAZ0 = 6;
	}
	sysgethostname(hostname,sizeof(hostname));
	printf("\t[%s -c %s %s] NONC99=%d, NONAZ0=%d @%s\n",
		Cc,Cflags,Cflagsplus,_NONC99,_NONAZ0,hostname);
	if( erronly ){
		fclose(erronly);
		erronly = 0;
	}
#endif
}

static char *MAKEenv(const char *oenv,char *nenv,int size)
{	const char *rpath;
	char apath[1024];

	if( strncmp(oenv,"MAKE=",5) != 0 )
		return (char*)oenv;
	rpath = &oenv[5];
	if( *rpath == 0 )
		rpath = "make";
	if( which(rpath,apath,sizeof(apath)) && apath[0] == PATHSEP[0] )
		sprintf(nenv,"MAKE=%s",apath);
	else	sprintf(nenv,"MAKE=%s",rpath);
	return nenv;
}

#ifndef DEFCC
#define DEFCC "cc"
#endif

int mkmkmk(int ac,const char *av[])
{	FILE *tmp;
	const char *arg;
	const char *nav[MaxARGV]; /**/
	char libdir[2048];
	char hdrdir[2048];
	int ai,nac;

	if( ac < 4 || strcmp(av[1],"-mkmkmk") != 0 ){
		for( ai = 2; ai < ac; ai++ )
			printf("[%d] %s\n",ai,av[ai]);
		fprintf(stderr,"Usage: %s -mkmkmk CC mkmake.c\n",av[0]);
		exit(-1);
	}

	nac = 0;
	libdir[0] = 0;
	for( ai = 2; ai < ac; ai++ ){
		if( elnumof(nav)-2 <= nac ){
			break;
		}
		arg = nav[nac++] = av[ai];
		if( strncmp(arg,"-L",2) == 0 || strncmp(arg,"-l",2) == 0 )
			sprintf(libdir+strlen(libdir),"%s ",arg);
		else
		if( strncmp(arg,"-I",2) == 0 )
			sprintf(hdrdir+strlen(hdrdir),"%s ",arg);
	}

	tmp = tmpfile();
/*
	if( !_available(tmp,"getcwd",DEFCC,hdrdir,libdir) )
		nav[nac++] = "-Dgetcwd=getwd";
*/
	fclose(tmp);

	nav[nac] = NULL;

	EXECVP(nav[0],nav);
	return -1;
}

char *to_fullpath(const char *path,char *fullpath,int size)
{	const char *dp;
	char dc;
	const char *path1;
	char cwd[1024];

	GETCWD(fullpath,1024);
	if( (dp = strrchr(path,'/'))
	 || (dp = strrchr(path,'\\')) ){
		/* get the real base path into fullpath */
		path1 = dp + 1;
		strcpy(cwd,fullpath);
		dc = *dp;
		*(char*)dp = 0;
		chdir(path);
		*(char*)dp = dc;
		GETCWD(fullpath,1024);
		chdir(cwd);
	}else	path1 = path;
	strcat(fullpath,PATHSEP);
	if( strncmp(path1,"./",2) == 0 || strncmp(path1,".\\",2) == 0 )
		path1 += 2;
	strcat(fullpath,path1);
	return fullpath;
}

int touch(int ac,const char *av[]){
	const char *path;
	int ai;
	struct stat st;
	FILE *fp;
	int ch;

	for( ai = 2; ai < ac; ai++ ){
		path = av[ai];
		if( stat(path,&st) != 0 ){
			continue;
		}
		if( st.st_mtime <= time(0) ){
			continue;
		}
		fprintf(stderr,"#### touch file from future: %X < %X %s\n",
			(int)time(0),(int)st.st_mtime,path);
		if( fp = fopen(path,"r+") ){
			if( (ch = getc(fp)) != EOF ){
				fseek(fp,0,0);
				putc(ch,fp);
			}
			fclose(fp);
		}
		stat(path,&st);
		fprintf(stderr,"#### touch file from future: %X < %X %s\n",
			(int)time(0),(int)st.st_mtime,path);
		sleep(1);
	}
	return 0;
}

static void baseof(const char *path,char *base,int size)
{	const char *bp;
	const char *dp;

	strcpy(base,path);
	dp = NULL;
	for( bp = base; *bp; bp++ )
		if( *bp == '/' || *bp == '\\' )
			dp = (char*)bp;
	if( dp )
		*(char*)dp = 0;
}

static int delarg1(int ac,const char *av[],int ax)
{	int ai;

	for( ai = ax; ai < ac; ai++ )
		av[ai] = av[ai+1];
	return ac - 1;
}

static const char *COM;
static int flag_NEGATE;
static int flag_REUSE;

static void scan_flags(const char *flags)
{	const char *sp;

	for( sp = flags; *sp; sp++ ){
		switch( *sp ){
			case 'n': flag_NEGATE = 1; break;
			case 'r': flag_REUSE  = 1; break;
		}
	}
}

static void putError(const char *av[],const char *com,int rcode)
{	int ai;
	FILE *err;
	char cwd[128];
	char path[1024];

	err = NULL;
	if( isatty(fileno(stdout)) )
	if( err = fopen("mkmake.err","a") ){
		GETCWD(path,sizeof(path));
		strcat(path,"/mkmake.err");
		fprintf(stderr,"mkmake: ERROR LOG is left at %s\n",path);
	}
	if( err == NULL )
		err = stdout;

	GETCWD(cwd,sizeof(cwd));
	fprintf(err,"\t*** exit(%d): %s at %s\n",rcode,com,cwd);
	for( ai = 0; av[ai]; ai++ )
		fprintf(err,"\t[%d] %s\n",ai,av[ai]);

	fprintf(err,"\n");
	if( err != stdout )
		fclose(err);
}

const char *MYPATH;
const char *MYBASE;

int main(int ac,const char *av[])
{	int rcode;
	int ai;
	char mypath[1024];
	char mybase[1024];

	if( ac < 2 ){
		fprintf(stderr,"mkmake: no arguments\n");
		return -1;
	}

	setBinaryIO();

	if( strcmp(av[1],"-noop") == 0 )
		return 0;

	if( strcmp(av[1],"-mkmkmk") == 0 )
		return mkmkmk(ac,av);

	COM = av[1];
	MYPATH = to_fullpath(av[0],mypath,sizeof(mypath));
	baseof(MYPATH,mybase,sizeof(mybase));
	MYBASE = mybase;

	if( 1 < ac && av[1][0] == '+' ){
		scan_flags(av[1]+1);
		ac = delarg1(ac,av,1);
	}

	if( strcmp(av[1],"-subst") == 0 ){
		ac = delarg1(ac,av,1);
		rcode = mksubst(ac,av);
	}else
	if( strcmp(av[1],"-lnconf") == 0 ){
		ac = delarg1(ac,av,1);
		rcode = lnconf(ac,av);
	}else
	if( strcmp(av[1],"-ckconf") == 0 ){
		ac = delarg1(ac,av,1);
		rcode = ckconf(ac,av);
	}else
	if( strcmp(av[1],"-makeat") == 0 ){
		ac = delarg1(ac,av,1);
		rcode = makeat(ac,av);
	}else
	if( strcmp(av[1],"-makeit") == 0 ){
		ac = delarg1(ac,av,1);
		rcode = makeit(ac,av);
	}else
	if( strcmp(av[1],"-lkfile") == 0 ){
		ac = delarg1(ac,av,1);
		rcode = lkfile(ac,av);
	}else
	if( strcmp(av[1],"-unlink") == 0 ){
		ac = delarg1(ac,av,1);
		if( 0 < ac )
			rcode = unlink(av[1]);
	}else
	if( strcmp(av[1],"-randtext") == 0 ){
		ac = delarg1(ac,av,1);
		if( 0 < ac )
			rcode = randtext(ac,av);
	}else
	if( strcmp(av[1],"-mkmake") == 0 ){
		ac = delarg1(ac,av,1);
		rcode = mkmake(ac,av);
	}else
	if( strcmp(av[1],"-cksum") == 0 ){
		ac = delarg1(ac,av,1);
		rcode = 0;
		for( ai = 1; ai < ac; ai++ ){
			if( cksum(av[ai]) != 0 ){
				fprintf(stderr,"ERROR: cksum: no %s\n",av[ai]);
				rcode++;
			}
		}
	}else
	if( strcmp(av[1],"-touch") == 0 ){
		rcode = touch(ac,av);
	}else{
		char cwd[1024];
		GETCWD(cwd,sizeof(cwd));
		fprintf(stderr,"ERROR: unknown usage of mkmake: %s\n",cwd);
		for( ai = 0; ai < ac; ai++ )
			fprintf(stderr," [%d] %s\n",ai,av[ai]);
		exit(-1);
	}

	if( rcode != 0 )
		putError(av,COM,rcode);

	if( flag_NEGATE ){
		if( rcode != 0 )
			rcode = 0;
		else	rcode = 1;
	}
	return rcode;
}

/*
####  lnconf -- link DELEGATE_CONF at upper directories
#### 
*/
int lnconf(int ac,const char *av[])
{	char rwd[1024];
	char cwd[1024];
	char pwd[1024];
	char dir[1024];
	char opath[1024];
	char command[1024];
	const char *CONF;
	const char *LINK;
	int fd;
	FILE *fp;

/*
	printf("\tlnconf:\n");
*/

	CONF = av[1];
	if( 0 <= (fd = open(CONF,0)) ){
		close(fd);
		return 0;
	}

	GETCWD(rwd,sizeof(rwd));
	pwd[0] = 0;

	dir[0] = 0;
	for(;;){
		GETCWD(cwd,sizeof(cwd));
		if( fopen(CONF,"r") != NULL ){
			if( dir[0] == 0 )
				return 0;
			chdir(rwd);
			sprintf(opath,"%s%s%s",dir,PATHSEP,CONF);
#ifdef S_IFLNK
			if( unlink(CONF) == 0 )
			printf("\told symlink removed\n");
			printf("\tsymlink %s %s\n",opath,CONF);
			return symlink(opath,CONF);
#else
			printf("\tcopy %s %s\n",opath,CONF);
			return cpyfile(CONF,"w",opath,"*",NULL,0);
#endif
		}
		if( strcmp(cwd,pwd) == 0 )
			break;
		strcpy(pwd,cwd);

		if( chdir("..") == 0 )
			sprintf(dir+strlen(dir),"..%s",PATHSEP);
		else	break;
		printf("\t#### looking for %s%s\n",dir,CONF);
		fflush(stdout);
	}

	/* make template */
	chdir(rwd);
	if( fp = fopen(CONF,"w") ){
		GETCWD(cwd,sizeof(cwd));
		fprintf(stderr,"\tcreated %s%s%s\n",cwd,PATHSEP,CONF);
		fprintf(fp,"#### DELEGATE CONFIGURATION FOR MAKE ####\n");
		fclose(fp);
		return 0;
	}else{
		fprintf(stderr,"cannot create %s/%s\n",rwd,CONF);
		return -1;
	}
}

/*
####  mkmake -- make Makefile.go
####  mkmake MAKE OUT CC CFLAGS CFLAGSPLUS LDFLAGS RANLIB LIBLIST LIBNAME [LIBSRCS]
*/

const char *MAKE;
const char *OUT;
const char *CC;
const char *CFLAGS;
const char *CFLAGSPLUS;
const char *LDFLAGS;
const char *RANLIB;
const char *LIBLISTs[4]; /**/
const char *LIBNAMEs[4]; /**/
int LibX = 0;
#define LIBLIST	LIBLISTs[LibX]
#define LIBNAME	LIBNAMEs[LibX]
/*
const char *LIBLIST;
const char *LIBNAME;
*/
const char *LIBSRCS;

const char *CONF = "DELEGATE_CONF";
const char *SRC = "Makefile";

#define _make	"_make"
#define _c	"_.c"
#define _out	"_.out"
#define _a	"_.a"

#define _ranlib	"ranlib"
static int find_ranlib(char *ranlib,int size,const char *make)
{ 	char command[128];
	char res[0x10000];
	int rcode;

#ifdef _MSC_VER
	strcpy(ranlib,"dir");
	return 1;
#endif

	if( which(_ranlib,ranlib,size) )
		return 1;

	unlink(_a);
	putfile(_c,"w","sub(){}\n");
	putfile(_make,"w",
"_.a:; $(CC) -c _.c\n\t$(AR) cr _.a _.o\n\t$(AR) st _.a\n\techo SUCCESS\n");
	sprintf(command,"%s -f _make",make);
	rcode = msystem(1,res,sizeof(res),command);
	unlink(_c);
	unlink(_make);
	unlink(_a);
	unlink("_.o");

	if( rcode == 0 && STRSTR(res,"SUCCESS") ){
		strcpy(ranlib,"$(AR) st");
		return 1;
	}

	return 0;
}

#define strspace(s)	strpbrk(s," \t\r\n")

static const char *noncplus(char *wh,const char *sflags,char *dflags){
	const char *sp;
	char *dp;
	dp = dflags;
	for( sp = sflags; *sp; ){
		if( strncmp(sp,"-x c++",6) == 0 ){
			sp += 6;
		}else
		if( strncmp(sp,"-DQS",4) == 0 && (sp[4]==0||sp[4]==' ')){
			sp += 4;
		}else{
			*dp++ = *sp++;
		}
	}
	*dp = 0;
	if( strcmp(sflags,dflags) != 0 )
	fprintf(stderr,"      ---- (%s) non-cplus -DQSC=%X [%s] => [%s]\n",
		wh,_QSC,sflags,dflags);
	return dflags;
}
int mkmake(int ac,const char *av[])
{	FILE *out;
	char ranlib[1024];
	int fd;
	char conf[1024];
	char cwd[1024];
	char cflags[1024];
	char cflagsplus[1024];
	char libsrcs[0x4000];
	int ai;
	const char *a1;
	static const char *IGN = "";

	printf("\tmkmake:\n");

	for(ai = 0; ai < ac; ai++){
		a1 = av[ai];
		if( strncmp(a1,"if(",3) == 0 ){
			if( matchList(a1+3,"WITHCPLUS") && NonCPlus ){
				av[ai] = IGN;
			}else
			if( matchList(a1+3,SYST) ){
				const char *dp;
				if( dp = strchr(a1+3,')') ){
					dp++;
					if( *dp == ' ' )
						dp++;
					av[ai] = dp;
				}
			}else{
				av[ai] = IGN;
			}
			fprintf(stderr,"\tav[%d] '%s' ==> '%s'\n",
				ai,a1,av[ai]);
		}
	}

	MAKE = av[1];
	OUT = av[2];
	CC = av[3];
	CFLAGS = av[4];
	CFLAGSPLUS = av[5];
	LDFLAGS = av[6];
	RANLIB = av[7];
	LIBLISTs[0] = av[8];
	LIBNAMEs[0] = av[9];
	LIBSRCS = av[10];
	if( 11 < ac ){
		LIBLISTs[1] = av[11];
		LIBNAMEs[1] = av[12];
	}

	if( flag_REUSE )
	if( 0 <= (fd = open(OUT,0)) ){
		printf("\t#### %s already made.\n",OUT);
		close(fd);
		return 0;
	}

	if( strstr(CFLAGS,"-DQSC") || strstr(CFLAGSPLUS,"-DQSC") ){
		_QSC |= 2;
	}
	if( _QSC == 0 ){
		cpyfile("_.QSC.conf","w",CONF,"1","$",1);
		/* _QSC = 4; with -DQSC in DELEGATE_CONF */
	}
	if( _QSC ){
		CFLAGS = noncplus("mkmake",CFLAGS,cflags);
		CFLAGSPLUS = noncplus("mkmake",CFLAGSPLUS,cflagsplus);
	}
	checkC99(CC,CFLAGS,CFLAGSPLUS);

	libsrcs[0] = 0;
	if( LIBSRCS ){
		char cwd[1024];
		char lscom[1024];
		const char *sp;
		const char *lp;
		const char *fp;
		char *dp;
		char name[128];
		char dir1[128];
		char files[16*1024];
		char file1[128];
		char *env;

		/* to ignore -w flag of GNUmake ... */
		if( env = getenv("MAKEFLAGS") ) *env = 0;
		if( env = getenv("MFLAGS") ) *env = 0;

		GETCWD(cwd,sizeof(cwd));
		sprintf(lscom,"%s %s %s",MAKE,BESILENT,SRCFILE_LIST);
		dp = libsrcs;
		for( sp = LIBSRCS; sp; sp = strspace(sp+1) ){
			while( *sp && strchr(" \t\r\n",*sp) )
				sp++;
			if( sscanf(sp,"%[^=]=%s",name,dir1) != 2 )
				break;
			printf("\tscanning source of %s at %s\n",name,dir1);
			sprintf(dp,"LIBSRC_%s=",name);
			dp += strlen(dp);

			if( chdir(dir1) != 0 ){
				printf("*** No Such Directory ?\n");
				exit(-1);
			}

			files[0] = 0;
			msystem(0,files,sizeof(files),lscom);
			chdir(cwd);
			printf("%s",files);
			if( strstr(files,"Makefile") == 0 ){
				printf("*** No Makefile ?\n");
				exit(-1);
			}

			for( fp = files; fp; fp = strspace(fp+1) ){
				while( *fp && strchr(" \t\r\n",*fp) )
					fp++;
				if( *fp == 0 )
					break;

				file1[0] = 0;
				sscanf(fp,"%s",file1);
			if( file1[0] == 0 )
					continue;

				if( strchr(file1,'.') == 0 )
				if( strcmp(file1,"Makefile") != 0 )
				{
					printf("#### won't use [%s]\n",file1);
					continue;
				}

				if( strcmp(file1,"\"") == 0 )
					continue; /* for Win95/98 echo */

				if( dp != libsrcs ){
					sprintf(dp," \\\n ");
					dp += strlen(dp);
				}
				sprintf(dp,"%s%s%s",dir1,PATHSEP,file1);
				dp += strlen(dp);
			}
			sprintf(dp,"\n");
			dp += strlen(dp);
		}
	}

	GETCWD(cwd,sizeof(cwd));
	printf("\t#### [%s] creating %s\n",cwd,OUT);
	out = fopen(OUT,"w");
	fprintf(out,"#### Generated from SRC=%s and CONF=%s\n",SRC,CONF);
	fflush(out);

	cpyfile(OUT,"a",SRC,"1","/#---BGN---",1);
	fseek(out,0,2);

	printf("\t[SET] MKMAKE=%s\n",MYPATH);
	fprintf(out,"MKMAKE=%s\n",MYPATH);
	fprintf(out,"MKBASE=%s\n",MYBASE);
	fprintf(out,"MKMKMK=%s%s%s\n",MYBASE,PATHSEP,MKMKMK_EXE);
	if( CFLAGS != IGN ){
		fprintf(out,"CFLAGS=%s",CFLAGS);
		if( _NONAZ0 == 4 ){
			fprintf(out," -DNONAZ0=%d",_NONAZ0);
		}
		fprintf(out,"\n");
	}
	if( CFLAGSPLUS != IGN ){
		fprintf(out,"CFLAGSPLUS=%s",CFLAGSPLUS);
		if( _NONC99 == 1 || _NONC99 == 3 )
			fprintf(out," -DNONC99=%d",_NONC99);
		fprintf(out,"\n");
	}
	if( LDFLAGS!= IGN ) fprintf(out,"LDFLAGS=%s\n",LDFLAGS);
	fprintf(out,"%s\n",libsrcs);

	if( !find_ranlib(ranlib,sizeof(ranlib),MAKE) ){
		strcpy(ranlib,RANLIB);
		if( ranlib[0] == 0 )
			strcpy(ranlib,"echo");
	}
	fprintf(out,"RANLIB=%s\n",ranlib);
	printf("\t[SET] RANLIB=%s\n",ranlib);

	fflush(out);
	/*
	cklibs(out,MAKE);
	*/
	for( LibX = 0; LibX < 4; LibX++ ){
		if( LIBLIST )
			cklibs(out,MAKE);
		else	break;
	}
	LibX = 0;

	fprintf(out,"YCFLAGS =");
	if( _NONAZ0 == 4 ){
		fprintf(out," -DNONAZ0=%d",_NONAZ0);
	}
	fprintf(out,"\n");
	fprintf(out,"#---CONF=%s\n",CONF);
	fflush(out);
	cpyfile(OUT,"a",CONF,"1","$",1);
	fseek(out,0,2);

	cpyfile(OUT,"a",SRC,"/#---END---","$",1);
	fseek(out,0,2);
	return 0;
}

/*
####  cklibs -- Pickup available libraries then print it to $OUT
####            from given library-list $LIBLIST
*/
void cklibs(FILE *out,const char *make)
{	char SLIBLIST[1024];
	char lv[256][128];
	const char *l1;
	int lc,li;
	char line[1024];
	char command[1024];
	int rcode;
	FILE *pfp;
	char res[0x10000];
	const char *libname;
	FILE *lfp;
	char name[128];
	const char *np;
	char *xp;

	putfile(_c,"w","main(){}\n");
	lc = sscanf(LIBLIST,
  "%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s ",
		lv[ 0],lv[ 1],lv[ 2],lv[ 3],lv[ 4],lv[ 5],lv[ 6],lv[ 7],
		lv[ 8],lv[ 9],lv[10],lv[11],lv[12],lv[13],lv[14],lv[15],
		lv[16],lv[17],lv[18],lv[19],lv[20],lv[21],lv[22],lv[23]
		);

	SLIBLIST[0] = 0;
	unlink("_.out");

	lfp = fopen("../gen/ccenv.h","w");

	for( li = 0; li < lc; li++ ){
		char *lp;

		l1 = lv[li];
		printf("\t- checking availability of %s [%s]\n",l1,SLIBLIST);
		if( _QSC && strcmp(l1,"-lstdc++")==0 ){
			printf("\t__QSC=%d non-cplus ign. lib [%s]\n",_QSC,l1);
		fprintf(stderr,"      ---- __QSC=%d non-cplus ign. [%s]\n",_QSC,l1);
			continue;
		}
		lp = &SLIBLIST[strlen(SLIBLIST)];
		if( lp == SLIBLIST )
			strcpy(lp,l1);
		else	sprintf(lp," %s",l1);

		unlink(_make);
		cpyfile(_make,"w",CONF,"1","$",1);
		sprintf(line,"\n_.out:; $(CC) %s%s %s %s\n\techo SUCCESS\n",
			CCOUT,_out,_c,SLIBLIST);
		putfile(_make,"a",line);

		sprintf(command,"%s -f _make",make);
		rcode = msystem(1,res,sizeof(res),command);
		if( STRSTR(res,"SUCCESS") == NULL )
			rcode = -1;

if( getenv("MK_DEBUG") ){
fprintf(stderr,"---------------------------- _make for %s\n",l1);
system("cat _make");
fprintf(stderr,"---------------------------- code=%d\n%s\n",rcode,res);
fprintf(stderr,"---------------------------- end of %s detection\n",l1);
}

		if( lfp ){
			xp = name;
			np = l1;
			if( np[0] == '-' && np[1] == 'l' )
				np += 2;
			for(; *np; np++ ){
				switch( *np ){
				case '.': *xp++ = '_'; *xp++ = 'D'; break;
				case '/': *xp++ = '_'; *xp++ = 'S'; break;
				case '-': *xp++ = '_'; *xp++ = 'M'; break;
				case '+': *xp++ = '_'; *xp++ = 'P'; break;
				case '_': *xp++ = '_'; *xp++ = 'U'; break;
				default:
					if( isalnum(*np) ){
						*xp++ = *np;
					}else{
					}
					break;
				}
				*xp = 0;
			}
			if( rcode == 0 ){
				fprintf(lfp,"#define DG_LIB_%s \"%s\"\r\n",
					name,l1);
			}else{
				fprintf(lfp,"#undef DG_LIB_%s  /*%s*/\r\n",
					name,l1);
			}
		}

		if( unlink("_.out") != 0 )
			if( rcode == 0 )
				rcode = -1;
		if( rcode != 0 ){
			*lp = 0;
			printf("\t*** %s exit(%d)\n",COM,rcode);
		}
	}

	unlink("_make");
	unlink("_.c");
	unlink("_.out");

	libname = LIBNAME;
	if( *libname == '@' ){ /* don't define if empty */
		libname++;
		if( *SLIBLIST == 0 ){
			printf("\t[don't SET] %s=\n",libname);
			return;
		}
	}
	printf("\t[SET] %s=%s\n",libname,SLIBLIST);
	fprintf(out,"%s=%s\n",libname,SLIBLIST);
	/*
	printf("\t[SET] %s=%s\n",LIBNAME,SLIBLIST);
	fprintf(out,"%s=%s\n",LIBNAME,SLIBLIST);
	*/
	fflush(out);

	if( lfp != NULL ){
		fprintf(lfp,"#define DG_LIBS \"%s\"\r\n",SLIBLIST);
		fprintf(lfp,"#define BitsOfInt %d\r\n",z2i(8*sizeof(int)));
		fprintf(lfp,"#define BitsOfPtr %d\r\n",z2i(8*sizeof(int*)));
	}
	if( lfp != NULL ){
		FILE *fp;
		const char *name = "alloca";
		char file[128];
		sprintf(file,"__%s.o",name);
#ifdef _MSC_VER
		fprintf(lfp,"#define AVAIL_%s 1\r\n",name);
#else
		if( fp = fopen(file,"r") ){
			fclose(fp);
			fprintf(lfp,"#define AVAIL_%s 1\r\n",name);
		}else{
			fprintf(lfp,"#define AVAIL_%s 0\r\n",name);
		}
#endif
	}
	if( lfp != NULL ){
		if( lfp != stdout )
			fclose(lfp);
	}
}

/*
####  ckconf -- check configuration
####
*/
int ckconf(int ac,const char *av[])
{	int ai;
	const char *user;
	char hostname[256];
	char admin[256];
	char ans[256];
	const char *dp;
	char line[1024];
	FILE *conf,*okfp;
	int fd;
	FILE *tty;

	const char *MAKEFILE_OK;
	const char *MAKEFILE;
	const char *CONF;
	const char *ADMIN;
	const char *AR;

	printf("\tckconf:\n");

	if( ac < 5 ){
		fprintf(stderr,
		"Usage: %s MAKEFILE_OUT MAKEFILE ADMIN\n",
		av[0]);
		return 1;
	}

	MAKEFILE_OK = av[1];

	if( flag_REUSE )
	if( 0 <= (fd = open(MAKEFILE_OK,0)) ){
		printf("\t#### %s already made.\n",MAKEFILE_OK);
		close(fd);
		return 0;
	}

	MAKEFILE = av[2];
	CONF = av[3];
	AR = av[4];
	ADMIN = av[5];

	printf("\tADMIN = '%s'\n",ADMIN);
	if( *ADMIN == 0 || strchr(ADMIN,'@') )
		goto conf_ok;

	if( isatty(fileno(stderr)) )
		tty = stderr;
	else
	if( getenv("SSH_TTY") || getenv("SSH_CONNECTION") ){
		tty = stderr;
	}
	else{
		tty = fopen("/dev/tty","w");
		if( tty == NULL ){
			fprintf(stderr,"## can't write to tty\n");
			if( 0 <= fileno(stdin) && getenv("TERM") && getenv("SHELL") ){
				fprintf(stderr,"#### TTY ? stdio[%d %d %d] tty[%d %d %d]\n",
					fileno(stdin),fileno(stdout),fileno(stderr),
					isatty(fileno(stdin)),isatty(fileno(stdout)),
					isatty(fileno(stderr))
				);
				system("tty");
				tty = stderr;
			}else
			return 1;
		}
	}

printf("\tget ADMIN value interactively ...\n");
fprintf(tty,"!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
fprintf(tty,"!   You should have defined ADMIN as:                      !\n");
fprintf(tty,"!     ADMIN = mail-address-of-the-DeleGate-administrator   !\n");
fprintf(tty,"!   either in %s or in the Makefile.      !\n",CONF);
fprintf(tty,"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");

	sysgethostname(hostname,sizeof(hostname));
	if( (user=getenv("USER")) || (user=getenv("LOGNAME")) )
		sprintf(admin,"%s@%s",user,hostname);
	else	admin[0] = 0;

	for(;;){

fprintf(tty,"Enter your E-mail address [%s]: ",admin);
fflush(tty);

		if( fgets(ans,sizeof(ans),stdin) == NULL )
			return 1;
		if( dp = strpbrk(ans,"\r\n") )
			*(char*)dp = 0;
		if( ans[0] != 0 )
			strcpy(admin,ans);

fprintf(tty,"ADMIN = %s\n",admin);
fprintf(tty,"OK ?  [y] / n / x(abort): ");
fflush(tty);

		if( fgets(ans,sizeof(ans),stdin) == NULL )
			return 1;
		if( dp = strpbrk(ans,"\r\n") )
			*(char*)dp = 0;

		if( ans[0] == 'y' || ans[0] == 0 )
			break;

		if( ans[0] == 'n' )
			continue;

		if( ans[0] == 'x' )
			return 1;

		fprintf(tty,"Answer y / n / RETURN\n");
	}

	conf = fopen(CONF,"a");
	if( conf == NULL ){
		fprintf(tty,"\n");
		return 1;
	}
	printf("\tgot ADMIN = %s interactively\n",admin);
	fprintf(conf,"#### ADMIN value got interactively ####\n");
	fprintf(conf,"ADMIN=%s\n",admin);
	fclose(conf);

conf_ok:
	if( *AR == 0 ){
		if( conf = fopen(CONF,"a") ){
			fprintf(conf,"#### AR added automatically ####\n");
			fprintf(conf,"AR=ar\n");
			fclose(conf);
		}
	}
	if( okfp = fopen(MAKEFILE_OK,"w") ){
		fprintf(okfp,"ckconf ok: %s + %s\n",MAKEFILE,CONF);
		fclose(okfp);
		return 0;
	}
	fprintf(stderr,"ckconf: cannot create %s\n",MAKEFILE_OK);
	return 1;
}

/*
##  makeit MAKE ...
##  0      1
*/
int makeit(int ac,const char *av[])
{	char make[1024];
	char makeenv[1024];
	int ai;
	const char **nav;

	if( ac < 2 ){
		fprintf(stderr,"Usage: %s MAKE ...\n",av[0]);
		exit(1);
	}

	for( ai = 0; av[ai]; ai++ )
		if( strncmp(av[ai],"MAKE=",5) == 0 )
			av[ai] = MAKEenv(av[ai],makeenv,sizeof(makeenv));

	if( av[1][0] == 0 ){
		av[0] = "make";
		sprintf(make,"MAKE=%s",av[0]);
		av[1] = make;
		nav = &av[0];
	}else{
		sscanf(av[1],"%s",make);
		av[1] = make;
		nav = &av[1];
	}
	EXECVP(nav[0],nav);
	fprintf(stderr,"cannot call make: %s",nav[0]);
	exit(-1);
	return -1;
}


/*
##  makeat To Work Out MAKE Target Remain
##  0      1  2    3   4    5
*/

int makeat(int ac,const char *av[])
{	char copy[1024];
	char cwd[1024];
	char rwd[1024];
	char dst[1024];
	char src[1024];
	const char *pp;
	const char *cpycom;
	int rcode;
	char mkmake[1024];
	char mkbase[1024];
	char mkmkmk[1024];
	char makeenv[1024];
	int ai,nac;
	const char *nav[1024]; /**/
	char cflags[1024];
	char cflagsa[1024];
	char cflags1[1024];
	char *dp1,*dp2;
	char hostname[128];

	if( ac < 5 ){
		fprintf(stderr,"Usage: %s TARGET WHERE OUTFILE MAKE ...\n",
		av[0]);
		return 1;
	}

	strcpy(dst,av[1]);
	GETCWD(cwd,sizeof(cwd));

	if( chdir(av[2]) != 0 ){
		fprintf(stderr,"### cannot chdir to %s\n",av[2]);
		return 1;
	}
	GETCWD(rwd,sizeof(rwd));

	if( 5 < ac )
	if( strcmp(av[5],"=") == 0 )
		av[5] = av[3];

	nac = ac - 4;
	nav[0] = av[4];
	for( ai = 1; ai < nac; ai++ ){
		if( elnumof(nav)-4 <= ai ){
			break;
		}
		nav[ai] = av[ai+4];
	}
	sprintf(mkmake,"MKMAKE=%s",MYPATH);
	nav[nac++] = mkmake;
	sprintf(mkbase,"MKBASE=%s",MYBASE);
	nav[nac++] = mkbase;
	sprintf(mkmkmk,"MKMKMK=%s%s%s",MYBASE,PATHSEP,MKMKMK_EXE);
	nav[nac++] = mkmkmk;

	nav[nac] = NULL;

	if( nav[0][0] == 0 ){
		nav[0] = "make";
		nav[nac++] = MAKEenv("MAKE=make",makeenv,sizeof(makeenv));
		nav[nac] = NULL;
	}
	for( ai = 0; nav[ai]; ai++ ){
		if( strncmp(nav[ai],"CC=",3) == 0 )
			CC = nav[ai] + 3;
		if( strncmp(nav[ai],"CFLAGS=",7) == 0 ){
			CFLAGS = nav[ai] + 7;
			if( strstr(CFLAGS,"-DQSC") ){
				_QSC |= 8;
			}
			if( _QSC )
			CFLAGS = noncplus("makeat",CFLAGS,cflags1);
		}
	}
	if( CC != 0 && CFLAGS != 0 ){
		checkC99(CC,CFLAGS,"");
	}
	for( ai = 0; nav[ai]; ai++ ){
		if( strncmp(nav[ai],"MAKE=",5) == 0 )
			nav[ai] = MAKEenv(nav[ai],makeenv,sizeof(makeenv));

		if( strncmp(nav[ai],"CFLAGS=",7) == 0 ){
			cflags[0] = 0;
			if( strstr(nav[ai],"-DNONC99") == 0 )
			if( _NONC99 == 1 || _NONC99 == 3 ){
				sprintf(cflags+strlen(cflags),"-DNONC99=%d ",_NONC99);
			}
			if( strstr(nav[ai],"-DNONAZ0") == 0 )
			if( _NONAZ0 == 4 ){
				sprintf(cflags+strlen(cflags),"-DNONAZ0=%d ",_NONAZ0);
			}
			if( strstr(nav[ai],"-Dm64") == 0 )
			if( strstr(nav[ai],"-m64") || sizeof(long int) == 8 ){
				sprintf(cflags+strlen(cflags),"-Dm64 ");
			}
			if( cflags[0] ){
				sprintf(cflagsa,"%s %s",nav[ai],cflags);
				nav[ai] = cflagsa;
			}
		}
	}

	sysgethostname(hostname,sizeof(hostname));
	printf("\r\n####### %s: %s @%s\n",COM,rwd,hostname);
	fflush(stdout);

	if( rcode = EXECVPR(nav[0],nav) ){
		putError(nav,"-makeat",rcode);
		return rcode;
	}

	if( av[1][0] == 0 )
		return 0;

	if( chdir(cwd) != 0 ){
		printf("cannot chdir to: %s\n",cwd);
		return 1;
	}

	if( av[3][0] == '/' )
		strcpy(src,av[3]);
	else	sprintf(src,"%s/%s",av[2],av[3]);

	if( (rcode = renames(src,dst)) == 0 )
		cpycom = "move";
	else
	if( (rcode = cpyfile(dst,"w",src,"*",NULL,0)) == 0 )
		cpycom = "copy";
	else	cpycom = "move/copy";

	if( rcode == 0 )
		unlink(src);

	printf("**[%d] %s %s to %s\n",rcode,cpycom,src,dst);
	return rcode;
}


/*
##  lkfile
## 
*/
int lkfile(int ac,const char *av[])
{	const char *src;
	const char *dst;
	const char *dp;

	if( ac < 3 ){
		printf("\tUsage: lkfile file-existing file-newname\n");
		return 1;
	}
	src = av[1];
	dst = av[2];
	if( strcmp(dst,".") == 0 ){
		if( dp = strrchr(src,'/') ){
			dst = dp + 1;
			printf("\tlkfile %s %s\n",src,dst);
		}else{
			printf("\tlkfile: no destination file\n");
			return 1;
		}
	}
	return cpyfile(dst,"w",src,"*",NULL,0);
}

/*
####  library functions
####
*/
int cpyfile(const char *out,const char *mode,const char *in,const char *from,const char *to,int useifdef)
{	FILE *ofp,*ifp;
	char line[1024];
	const char *ls1;
	const char *ls2;
	int ln1,ln2,lnc;
	int putit;
	int nput;
	int ignore;
	int enable = 0;
	int rcode;

	if( (ifp = fopen(in,"r")) == NULL ){
		char cwd[1024];
		getcwd(cwd,sizeof(cwd));
		printf("\tcpyfile[%s]: cannot read '%s'\n",cwd,in);
		return 1;
	}

	if( (ofp = fopen(out,mode)) == NULL ){
		printf("\tcpyfile: cannot write '%s'\n",out);
		fclose(ifp);
		return 1;
	}

	rcode = -1;
	if( strcmp(from,"*") == 0 ){
		int rcc,wcc;
		char buf[1024];
		while( rcc = fread(buf,1,sizeof(buf),ifp) )
			wcc = fwrite(buf,1,rcc,ofp);
		rcode = 0;
		goto EXIT;
	}

	if( *from == '/' )
		ls1 = from+1;
	else	ls1 = NULL;

	if( *to == '/' )
		ls2 = to+1;
	else	ls2 = NULL;

	ln1 = atoi(from);
	ln2 = atoi(to);

	putit = 0;
	ignore = 0;
	nput = 0;

	printf("\tcpyfile %s[%d-%d][%x-%x] > %s\n",in,ln1,ln2,p2i(ls1),p2i(ls2),out);

	for( lnc = 1; fgets(line,sizeof(line),ifp) != NULL; lnc++ ){
		if( !putit )
		if( ln1 && ln1 <= lnc
		 || ls1 && strncmp(line,ls1,strlen(ls1)) == 0 )
			putit = 1;

		if( strncmp(line,"#IF",3) == 0 ){
			if( matchList(line+4,"NONCPLUS") && NonCPlus ){
				enable = 1;
			}
			if( matchList(line+4,"NONC99") && _NONC99 ){
				enable = 1;
			}
			if( matchList(line+4,"QSC") && _QSC ){
				enable = 1;
			}
			if( matchList(line+4,SYST) ){
				enable = 1;
			}
		}
		if( _QSC == 0 && strstr(line,"-DQSC") ){
			const char *sp;
			int st = 0;
			for( sp = line; *sp; sp++ ){
				if( *sp == '#' ) break;
				if( st == 0 && strncmp(sp,"FLAGS",5) == 0 ) st = 1;
				if( st == 1 && *sp == '=' ) st = 2;
				if( st == 2 && strncmp(sp,"-DQSC",5) == 0 ) st = 3;
			}
			if( st == 3 ){
				_QSC |= 4;
		fprintf(stderr,"      ---- __QSC=%d set non-cplus %s:%d %s",_QSC,in,lnc,line);
			}
		}

		if( !ignore && useifdef )
		if( strncmp(line,"#ifdef",6) == 0 ){
			if( matchList(line+7,"NONC99") && _NONC99 && CPP ){
			}else
			if( !matchList(line+7,SYST) )
				ignore = 1;
			else	printf("\t%s",line);
		}

		if( putit ){
			if( enable ){
				if( isspace(*line) && line[1] == '#' ){
					line[1] = ' ';
				}
			}
			if( ignore )
				fputs("## ",ofp);
			else{
				nput++;
			}
			fputs(line,ofp);
		}

		if( ignore && useifdef )
		if( strncmp(line,"#endif",6) == 0 ){
			ignore = 0;
		}
		if( strncmp(line,"#FI",3) == 0 ){
			enable = 0;
		}

		if( putit )
		if( ln2 && ln2 <= lnc
		 || ls2 && strncmp(line,ls2,strlen(ls2)) == 0 ){
			putit = 0;
			break;
		}
	}
EXIT:
	fclose(ifp);
	fclose(ofp);
	return rcode;
}
int matchList(const char *list,const char *word)
{	const char *wp;
	const char *ep;
	char ec;
	char listbuf[1024];

	strcpy(listbuf,list);
	wp = listbuf;
	for( ep = wp; ec = *ep; ep++ ){
		if( strchr(", )#\t\r\n",ec) ){
			*(char*)ep = 0;
			if( strcmp(word,wp) == 0 )
				return 1;
			wp = ep + 1;
		}
	}
	return 0;
}

int putfile(const char *out,const char *mode,const char *str)
{	FILE *ofp;

	if( (ofp = fopen(out,mode)) == NULL ){
		printf("\tputfile: cannot write '%s'\n",out);
		return 1;
	}

	fputs(str,ofp);
	fclose(ofp);
	return 0;
}

int which(const char *command,char *path,int size)
{	const char *pe;
	char PATH[4096];
	char *np;
	const char *dir;
	FILE *fp;

	if( pe = getenv("PATH") )
		strcpy(PATH,pe);
	else	PATH[0] = 0;
	strcat(PATH,":/bin:/usr/bin:/usr/ucb:/usr/local/bin");

	for( dir = PATH; dir && *dir; dir = np ){
		if( np = (char*)strchr(dir+1,':') )
			*np++ = 0;

		sprintf(path,"%s/%s",dir,command);
		if( fp = fopen(path,"r") ){
			fclose(fp);
			return 1;
		}
	}
	return 0;
}

int renames(const char *old,const char *xnew)
{	int ri,rcode;

	rcode = -1;
	unlink(xnew);

	for( ri = 0; ri < 5; ri++ ){
		if( (rcode = rename(old,xnew)) == 0 )
			break;
#ifdef RETRY_RENAME
			fprintf(stderr,"FAILED rename %s to %s, retry...\n",
				old,xnew);
			sleep(1); /* NMAKE problem ? */
#endif
	}
	if( rcode != 0 )
		fprintf(stderr,"FAILED rename(%s,%s)\n",old,xnew);
	return rcode;
}


/*
 *	970104 C program version of mksubst
 *		<ysato@etl.go.jp>
 */

#define IFEXIST "__"
#define TRY	"_-"

const char *SRCDIR = "../src";

/*
const char *MAKE;
*/
const char *MAKEFILE;
const char *HDRDIR;
/*
const char *RANLIB;
*/
const char *LIBFILE;
const char *LIBDIR;
const char *LDLIBS;

int mksubst(int ac,const char *av[])
{	const char *com;
	const char *substfiles;

	ERRLOG = fopen("errors","a+");
	if( ERRLOG == NULL )
		ERRLOG = stderr;

	if( ac < 6 ){
	fprintf(stderr,
"Usage: %s {libck|libmk|manmk} MAKE MAKEFILE CC CFLAGS HDRDIR RANLIB LIBFILE LIBDIR LDLIBS LDFLAGS files\n",
	av[0]);
	exit(1);
	}

	com = av[1];
	MAKE = av[2];  if( MAKE[0] == 0 ) MAKE = "make";
	MAKEFILE = av[3];
	CC = av[4];    if( CC[0] == 0 ) CC = "cc";
	CFLAGS = av[5];
	HDRDIR = av[6];
	RANLIB = av[7];
	LIBFILE = av[8];
	LIBDIR = av[9];
	LDLIBS = av[10];
	LDFLAGS = av[11];
	substfiles = av[12];

	checkC99(CC,CFLAGS,"");

	printf("\tMAKE=%s\n",MAKE);
	printf("\tMAKEFILE=%s\n",MAKEFILE);
	printf("\tCC=%s\n",CC);
	printf("\tCFLAGS=%s\n",CFLAGS);
	printf("\tHDRDIR=%s\n",HDRDIR);
	printf("\tRANLIB=%s\n",RANLIB);
	printf("\tLIBFILE=%s\n",LIBFILE);
	printf("\tLIBDIR=%s\n",LIBDIR);
	printf("\tLDLIBS=%s\n",LDLIBS);
	printf("\tLDFLAGS=%s\n",LDFLAGS);
	printf("\tFiles=%s\n",substfiles);

	if( strcmp(com,"libck") == 0 )
		exit(check_env());

	if( strcmp(com,"objmk") == 0 )
		exit(_mksubst(substfiles,0,NULL));

	if( strcmp(com,"libmk") == 0 )
		exit(libmake(substfiles,av[13],av[14]));

	if( strcmp(com,"manck") == 0 )
		exit(manifest_check(substfiles));

	if( strcmp(com,"manmk") == 0 )
		exit(manifest_make(substfiles));

	fprintf(stderr,"%s: unknown command\n",com);
	exit(1);
	return -1;
}

static int exist1(const char *file,char *loadit,int size)
{	FILE *fp;
	char *dp;

	if( dp = (char*)strrchr(file,'.') )
		strcpy(dp,".o");

	fp = fopen(file,"r");

	if( fp ){
		fclose(fp);
		if( loadit[0] != 0 )
			strcat(loadit," ");
		strcat(loadit,file);
	}
	return 0;
}

int libmake(const char *files,const char *target,const char *listname)
{	char loadit[MaxARGB];
	char a1[MaxARGB];
	const char *av[3]; /**/
	const char *srcv[1024]; /**/
	const char *src1;
	int si;
	int rcode;

	srcv[0] = 0;
	_mksubst(files,elnumof(srcv),srcv);
	loadit[0] = 0;
	for( si = 0; src1 = srcv[si]; si++ )
		exist1(src1,loadit,sizeof(loadit));

	sprintf(a1,"%s=%s",listname,loadit);
	av[0] = a1;
	av[1] = (char*)target;
	av[2] = NULL;
	execMake("libmk",av,0);
	return -1;
}

int manifest_check(const char *files)
{	FILE *fp;
	char omani[1024];
	char nenv[1024];
	char nmani[4096];
	char manifest[1024];
	int rcode;
	const char *av[2]; /**/

	sprintf(manifest,"mani-%s",LIBFILE);

sprintf(nenv,   "%s CC='%s' CFLAGS='%s' RANLIB='%s' LDLIBS='%s'",
MAKE,CC,CFLAGS,RANLIB,LDLIBS);
	sprintf(nmani,"%s %s",nenv,files);

	omani[0] = 0;
	if( fp = fopen(manifest,"r") ){
		fgets(omani,sizeof(omani),fp);
		fclose(fp);
		if( strcmp(omani,nmani) == 0 )
			return 0;
	}

	fprintf(stderr,"** manifest of '%s' changed:\n < %s\n > %s\n",
		LIBFILE,omani,nmani);

	unlink(LIBFILE);
	unlink(manifest);

	av[0] = LIBFILE;
	av[1] = NULL;
	execMake("manmk",av,0);
	return -1;
}
int manifest_make(const char *files)
{	FILE *fp;
	char nmani[4096];
	char manifest[1024];

	sprintf(manifest,"%s.mani",LIBFILE);

sprintf(nmani,  "%s CC='%s' CFLAGS='%s' RANLIB='%s' LDLIBS='%s' %s",
MAKE,CC,CFLAGS,RANLIB,LDLIBS,files);

	if( fp = fopen(manifest,"w") ){
		fputs(nmani,fp);
		fclose(fp);
		return 0;
	}
	fprintf(stderr,"#### CANNOT MAKE tar MANIFEST %s\n",manifest);
	return 1;
}

#define stralloc(s)	strcpy((char*)malloc(strlen(s)+1),s)

int subst1(const char *file,const char *filev[],int *filecp)
{	const char *dp;
	char symb[256];
	const char *sym;
	char filebuf[256];
	int ifavail,xtry,avail;
	char libs[1024];

#ifdef _MSC_VER
	if( strcmp(file,"dlopen.c")==0
	 || strcmp(file,"yp_match.c")==0
	 || strcmp(file,"__spawnvp.c")==0
	 || strcmp(file,"spawnvp.c")==0
	 || strcmp(file,"flockfile.c")==0
	){
		return 0;
	}
#endif

	dp = strrchr(file,'.');
	if( dp == NULL || strcmp(dp,".c") != 0 )
		return 0;

	strcpy(symb,file);
	*strrchr(symb,'.') = 0;

	sym = symb;
	ifavail = 0;
	xtry = 0;

	if( strstr(CC,"g++")
	 || strstr(CFLAGS,"-x c++")
	 || strstr(CFLAGS,"-TP")
	){
		CPP++;
	}

	if( CPP == 0
	 && strncmp(sym,IFEXIST,strlen(IFEXIST)) == 0 ){
		sym += strlen(IFEXIST);
		ifavail = 1;
	}else
	if( CPP != 0 && sym[0] == '_'
	 || strncmp(sym,TRY,strlen(TRY)) == 0 ){
		sym += strlen(TRY);
		ifavail = 1;
		xtry = 1;
	}

	sprintf(libs,"%s %s %s",LIBDIR,LDLIBS,LDFLAGS?LDFLAGS:"");
	avail = _available(ERRLOG,sym,CC,CFLAGS,libs);

	if(  ifavail ){
		if( avail )
			printf(" ** %s.c is used\n",symb);
		else
		if( xtry )
printf(" -- %s may not be in the libraries, but try to get it.\n",symb);
		else	printf(" -- %s is not in the libraries\n",symb);

		if( avail || xtry ){
			sprintf(filebuf,"%s.o",symb);
			filev[*filecp] = stralloc(filebuf);
			*filecp = *filecp + 1;
		}
	}else{
		if( !avail || (CPP && _NONC99) ){
			if( avail && (CPP && _NONC99) )
				printf(" ** %s.c might not be\n",symb);
			else	printf(" ** %s.c is substituted\n",symb);
			sprintf(filebuf,"%s.o",symb);
			filev[*filecp] = stralloc(filebuf);
			*filecp = *filecp + 1;
		}else	printf(" -- %s is in the libraries\n",symb);
	}
	fflush(stdout);
	return 0;
}

int _mksubst(const char *files,int mac,const char *filev[])
{	char cwd[1024];
	const char *filevb[MaxARGV]; /**/
	int filec;
	FILE *sfp;
	char substlist[MaxARGB];
	char listc[MaxARGB];

	strcpy(listc,LIBFILE);
	strcat(listc,".list");

	fprintf(stderr,"** mksubst **\n");
	fprintf(stderr,"  where: %s\n",SRCDIR);
	fprintf(stderr,"  compile: %s %s %s\n",CC,CFLAGS,LDLIBS);
	fprintf(stderr,"  files: %s\n",files);

	/*
	 * Goto SRCDIR because the CFLAGS,LDLIBS may be specified in
	 * relative path from the directory
	 */
	GETCWD(cwd,sizeof(cwd));
	if( chdir(SRCDIR) != 0 ){
		fprintf(stderr,"cannot chdir SRCDIR = %s\n",SRCDIR);
		return -1;
	}

	setSIGINT("mksubst");

	filec = 0;
	if( filev == NULL ){
		filev = filevb;
		mac = elnumof(filevb);
	}

	sprintf(substlist,"%s/%s",cwd,listc);
	if( sfp = fopen(substlist,"r") ){
		char buf[128];
		const char *dp;
		while( fgets(buf,sizeof(buf),sfp) != NULL ){
			if( mac-1 <= filec ){
				fprintf(stderr,"#### too many files\n");
				break;
			}
			if( dp = strpbrk(buf,"\r\n") )
				*(char*)dp = 0;
			filev[filec++] = stralloc(buf);
		}
		fclose(sfp);
		fprintf(stderr,"#### loaded from '%s' (%d)\n",substlist,filec);
	}
	if( filec == 0 ){
		foreach_word(files,subst1,filev,&filec);
		if( sfp = fopen(substlist,"w") ){
			int fi;
			for( fi = 0; fi < filec; fi++ )
				fprintf(sfp,"%s\n",filev[fi]);
			fclose(sfp);
		}
		fprintf(stderr,"#### dumped to '%s' (%d)\n",substlist,filec);
	}
	chdir(cwd);

	filev[filec] = NULL;

	if( ERRLOG ){
		int now = time(0);
		char path[1024];
		GETCWD(path,sizeof(path));
		strcat(path,"/errors");
		fprintf(stderr,"#### mksubst errors to %s: %d\n",path,now);
		fprintf(ERRLOG,"#### mksubst errors to %s: %d\n",path,now);
		dup2(fileno(ERRLOG),2);
	}
	if( filev == filevb )
		execMake("mksub",filev,0); /* no return */
	else	return callMake("mksub",filev);
	return -1;
}

void fatal(const char *fmt)
{
	fprintf(stderr,"FATAL!!!!:");
	fprintf(stderr,"%s",fmt);
	fprintf(stderr,"\n");
}

int check_env(){
	char cflags[1024];
	char libs[1024];

	fprintf(stderr,"\t -- checking CC = %s\n",CC);
	if( !e_available(ERRLOG,NULL,CC,"",LIBDIR) ){
		fatal(" Something wrong in the CC.");
/*
		return 1;
*/
	}
	sprintf(cflags,"-c %s",CFLAGS);
	fprintf(stderr,"\t -- checking CC with CFLAGS = %s %s\n",CC,cflags);
	/*
	if( !e_available(ERRLOG,NULL,CC,cflags,LIBDIR) ){
		fatal(" Something wrong in the CFLAGS.");
		return 2;
	}
	*/
	if( !e_available(ERRLOG,NULL,CC,cflags,NULL) ){
		fatal(" Something wrong in the CFLAGS.");
	}
	sprintf(libs,"%s %s %s",LIBDIR,LDLIBS,LDFLAGS);
	if( strstr(cflags,"-m64") != 0 )
		strcpy(cflags,"-m64");
	else
	if( strstr(cflags,"-m32") != 0 )
		strcpy(cflags,"-m32");
	else	cflags[0] = 0;
	fprintf(stderr,"\t -- checking LDLIBS = %s\n",LDLIBS);
	if( !e_available(ERRLOG,NULL,CC,cflags/*CFLAGS*/,libs) ){
		fatal(" Something wrong in Libraries.");
		/*
		return 3;
		*/
	}

#ifndef __cplusplus
	if( MaybeOnUnix ){
		fprintf(stderr,"\t -- checking socket library\n");
		if( !e_available(ERRLOG,"socket",CC,cflags/*CFLAGS*/,libs) ){
#ifndef __CYGWIN__
			fatal(" Socket library should be given.");
			fatal(" You may have to specify");
			fatal("     LIBS=-lnsl -lsocket");
			fatal("     LIBS=WSOCK32.LIB");
			fatal("     ...");
			fatal(" in the Makefile (or in DELEGATE_CONF)");
			/*
			return 4;
			*/
#endif
		}
	}
#endif

	fprintf(stderr,"** CC CFLAGS LIBS and socket library are OK.\n");
	return 0;
}

int foreach_word(const char *list,substFunc func,const char *fv[],int *fcp)
{	const char *np;
	char file[1024];
	int rcode;

	for( np = list; np; np = strpbrk(np," \t") ){
		while( *np == ' ' || *np == '\t' )
			np++;
		if( *np == 0 )
			break;
		sscanf(np,"%s",file);
		if( rcode = (*func)(file,fv,fcp) )
			break;
	}
	return rcode;
}

int callMake(const char *what,const char *aav[])
{	int pid;
 
#ifdef WITH_SPAWN
	return execMake(what,aav,1);
#else
	if( (pid = fork()) == 0 ){
		execMake(what,aav,0);
		exit(-1);
	}
	return waitPid(pid);
#endif
}

int execMake(const char *what,const char *aav[],int spawn)
{	const char *av[MaxARGV]; /**/
	char ab[MaxARGB];
	char *bp;
	int ac = 0, ai;
	int aac;

	ac = 0;
	bp = ab;

	av[ac++] = MAKE;
	av[ac++] = addArg(&bp,"MAKE",MAKE);
	if( MAKEFILE[0] != 0 ){
	av[ac++] = "-f";
	av[ac++] = addArg(&bp,MAKEFILE,NULL);
	}
	av[ac++] = addArg(&bp,"CC",CC);
	av[ac++] = addArg(&bp,"CFLAGS",CFLAGS);
	av[ac++] = addArg(&bp,"HDRDIR",HDRDIR);
	av[ac++] = addArg(&bp,"RANLIB",RANLIB);
	av[ac++] = addArg(&bp,"LIBFILE",LIBFILE);

	for( aac = 0; aav[aac]; aac++ ){
		if( elnumof(av)-1 <= ac )
			break;
		av[ac++] = addArg(&bp,aav[aac],NULL);
	}
	av[ac++] = NULL;

	for( ai = 0; av[ai]; ai++ )
		printf("\t%s[%d] %s\n",what,ai,av[ai]);

#ifdef WITH_SPAWN
	if( spawn ){
		int rcode;
		if( rcode = spawnvp(P_WAIT,MAKE,av) )
			printf("*** mksubst exit(%d) %s\n",av[0]);
		return rcode;
	}
#endif
	EXECVP(MAKE,av);

	fprintf(stderr,"EXECVP(%s) failed\n",MAKE);
	perror("EXECVP");
	exit(1);
	return -1;
}

/*
 *	970204 C program version of available
 *		<ysato@etl.go.jp>
 */
#include <signal.h>

#define TEST_C	"_.c"

void setSIGINT(const char *what)
{
	signal(SIGINT,SIG_DFL);
}

static int isfile(const char *path)
{	struct stat st;

	return stat(path,&st) == 0;
}

int _available(FILE *errlog,const char *sym,const char *cc,const char *flags,const char *libs)
{	FILE *fp;
	int rcode,fd;
	char command[1024];
	int rcode1;
	char command1[1024];
	char res[0x10000];

	fp = fopen(TEST_C,"w");
	/*
	if( sym != NULL && *sym == '#' ){
	*/
	if( sym != NULL && (*sym == '#' || strchr(sym,'{')) ){
		fprintf(fp,"%s\n",sym);
		fprintf(fp,"main(){ }\n");
	}else
	if( sym != NULL )
		fprintf(fp,"main(){ %s();}\n",sym);
	else{
		sym = "ANYTHING";
		fprintf(fp,"main(){ }\n");
	}
	fclose(fp);
	unlink("a.out");
	unlink("_.exe");
	unlink("a.exe");

	unlink("_.o");
#ifdef _MSC_VER
	sprintf(command,"%s -c -Fo_.o %s %s",cc,flags,TEST_C);
#else
	sprintf(command,"%s -c -o _.o %s %s",cc,flags,TEST_C);
#endif
	rcode = msystem(1,res,sizeof(res),command);
	rcode1 = rcode;
	strcpy(command1,command);
	if( libs == NULL || rcode != 0 ){
		if( errlog != NULL ){
			fprintf(errlog,"***\n%s\n%s\n",command,res);
		}
	}
	if( libs == NULL ){
		return rcode == 0;
	}

	sprintf(command,"%s _.o %s",cc,libs);

	if( strstr(flags,"-m64") != 0 && strstr(command,"-m64") == 0 )
		strcat(command," -m64");
	else
	if( strstr(flags,"-m32") != 0 && strstr(command,"-m32") == 0 )
		strcat(command," -m32");
	if( strstr(flags," -x c++") )
	{
		strcat(command," -lstdc++");
#if defined(__OpenBSD__) || defined(__NetBSD__)
		strcat(command," -lm");
#endif
	}

	rcode = msystem(1,res+strlen(res),sizeof(res)-strlen(res),command);

	if( errlog == erronly ){
	    if( rcode1 !=0 || rcode != 0 ){
		fprintf(errlog,"      ---- CC exit(%d) %s\n",rcode1,command1);
		fprintf(errlog,"      ---- LD exit(%d) %s\n",rcode,command);
		fprintf(errlog,"\n");
		fflush(errlog);
	    }
	}else
	if( errlog != NULL ){
		fprintf(errlog,"***\n%s\n",command);
		fprintf(errlog,"%s\n",res);
		fflush(errlog);
	}else	printf("%s",res);

	if( !isfile("a.out") && !isfile("_.exe") && !isfile("a.exe") ){
		if( strstr(res,"too few arguments") ){
			fprintf(stderr,"*** %s : available ?\r\n",sym);
			rcode = 0;
		}else
		if( rcode == 0 ){
			fprintf(stderr,"*** %s : unavailable ?\r\n",sym);
			rcode = -1;
		}
	}

	unlink("a.out");
	unlink("_.exe");
	unlink("a.exe");

	if( rcode == 0 )
		unlink(TEST_C);

	return rcode == 0;
}
int e_available(FILE *errlog,const char *sym,const char *cc,const char *flags,const char *libs)
{	int off,ok,rcc;
	char buf[2048];

	if( errlog != NULL ){
		fseek(errlog,0,2);
		off = ftell(errlog);
		ok = _available(errlog,sym,cc,flags,libs);
		if( !ok ){
			fseek(errlog,off,0);
			while( fgets(buf,sizeof(buf),errlog) != NULL )
				fprintf(stderr,"##ERROR## %s",buf);
			fflush(stderr);
		}
		return ok;
	}else{
		return _available(errlog,sym,cc,flags,libs);
	}
}

char *addArg(char **pp,const char *name,const char *value)
{	char *p0;
	char arg[MaxARGB];

	p0 = *pp;
	if( value == NULL )
		strcpy(arg,name);
	else	sprintf(arg,"%s=%s",name,value);

#ifdef QUOTE_ARG
	if( arg[0] != '"' )
		sprintf(p0,"\"%s\"",arg);
	else
#endif
	strcpy(p0,arg);

	*pp = p0 + strlen(p0) + 1;
	return p0;
}


int EXECVPR(const char *path,const char *av[])
{	const char *nav[MaxARGV]; /**/
	char na[4][256];
	char *nap;
	char nab[MaxARGB];
	int nac0,ai,nac;
	int status;
	int pid,rcode;

	if( strpbrk(path," \t") ){
		na[0][0] = 0;
	 	nac0 = sscanf(path,"%s %s %s %s",na[0],na[1],na[2],na[3]);
		fprintf(stderr,"#### execvp(%s) -> execpv(%s)\n",
			av[0],na[0]);
		av[0] = na[0];
		path = av[0];
/*
some make produeces MAKE="make TARGET=x\ y\ z" ...
		path = na[0];
		nac = 0;
		fprintf(stderr,"#### execvp(%s):\n",av[0]);
		for(ai = 0; ai < nac0; ai++){
			if( elnumof(nav)-1 <= nac )
				break;
			printf("\t[%d] %s\n",ai,na[ai]);
			nav[nac++] = na[ai];
		}
		for(ai = 1; av[ai]; ai++ ){
			if( elnumof(nav)-1 <= nac )
				break;
			nav[nac++] = av[ai];
		}
		nav[nac] = NULL;
		av = nav;
*/
	}

#ifdef WITH_SPAWN
	nav[0] = av[0];
	nap = nab;
	for( ai = 1; av[ai]; ai++ )
		nav[ai] = addArg(&nap,av[ai],NULL);
	nav[ai] = 0;
	rcode = spawnvp(P_WAIT,nav[0],nav);
#else
	if( (pid = fork()) == 0 ){
		rcode = Execvp(av[0],av);
		fprintf(stderr,"#### execvp(%s) = %d, failed\n",path,rcode);
		exit(-1);
	}else{
		rcode = waitPid(pid);
	}
#endif
	return rcode;
}

#ifndef WITH_SPAWN
int waitPid(int pid)
{	int xpid,status,rcode;

	rcode = -1;
	for(;;){
		xpid = wait(&status);
		if( xpid != -1 )
			rcode = WEXITSTATUS(status);
		else	rcode = -1;
		/*printf("waitPid(%d) = %d, exit(%d)\n",pid,xpid,rcode);*/
		if( xpid == -1 || xpid == pid )
			break;
	}
	return rcode;
}
#endif

void EXECVP(const char *path,const char *av[])
{
	exit(EXECVPR(path,av));
}

int msystem(int erralso,char res[],int size,const char *command)
{	int rcc,ecc;
	FILE *out,*errout;
	int outpipe[2];
	int outfd,errfd;
	int rcode;

	pipe(outpipe);
	errout = tmpfile();

	outfd = dup(1);
	dup2(outpipe[1],1);
	if( erralso ){
		errfd = dup(2);
		dup2(fileno(errout),2);
	}
	rcode = system(command);
	dup2(outfd,1);
	close(outfd);
	if( erralso ){
		dup2(errfd,2);
		close(errfd);
	}

	close(outpipe[1]);
	out = fdopen(outpipe[0],"r");
	rcc = fread(res,1,size,out);
	fclose(out);

	fseek(errout,0,0);
	ecc = fread(res+rcc,1,size,errout);
	fclose(errout);
	res[rcc+ecc] = 0;
	return rcode;
}

#ifndef HOSTNAME
#define HOSTNAME	""
#endif
#ifndef HOSTNAME_FILE
#define HOSTNAME_FILE	""
#endif
#ifndef HOSTNAME_COM
#define HOSTNAME_COM	"hostname"
#endif

int sysgethostname(char *hostname,int size)
{	FILE *fp;

	*hostname = 0;

	if( HOSTNAME && *HOSTNAME ){
		strcpy(hostname,HOSTNAME);
		return 1;
	}

	if( HOSTNAME_FILE && *HOSTNAME_FILE ){
		if( fp = fopen(HOSTNAME_FILE,"r") ){
			fscanf(fp,"%s",hostname);
			fclose(fp);
			if( *hostname )
				return 1;
		}
	}
	if( HOSTNAME_COM != NULL ){
		if( fp = popen(HOSTNAME_COM,"r") ){
			fscanf(fp,"%s",hostname);
			pclose(fp);
			if( *hostname )
				return 1;
		}
	}
	return 0;
}

#ifdef WITH_SPAWN
int Execvp(const char *path,const char *argv[])
{	int stat;

	stat = spawnvp(P_WAIT,path,argv);
	if( stat == -1 )
		return -1;
	else	exit(stat);
	return -1;
}
#else
int Execvp(const char *path,const char *argv[])
{
	return execvp(path,(char**)argv);
}
#endif

int randtext(int ac,const char *av[])
{	int rand,i;
	FILE *fp;

	if( ac < 1 )
		return -1;
	fp = NULL;
	if( 1 < ac )
		fp = fopen(av[1],"w");
	if( fp == NULL )
		return -1;

	fprintf(fp,"int randtext(int n){\n");
	fprintf(fp,"  switch(n){\n");
	rand = time(0) % 128;
	for( i = 0; i < rand; i++ ){
	fprintf(fp,"    case %d: n++;\n",i);
	}
	fprintf(fp,"  }\n");
	fprintf(fp,"  return n;\n");
	fprintf(fp,"}\n");
	if( fp != stdout )
		fclose(fp);
	return 0;
}

#define MKMAKE
#define fileIsdir(f) 0
#define gethostname(n,z) -1
#include "../rary/cksum.c"
