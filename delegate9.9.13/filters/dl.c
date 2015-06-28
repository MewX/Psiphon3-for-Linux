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
Content-Type:	program/C; charset=US-ASCII
Program:	dl.c (Dynamic Linker)
Author:		Yutaka Sato <ysato@delegate.org>
Description:

History:
	050430	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "ystring.h"
#include "log.h"
int fullpathDYLIB(PCStr(path),PCStr(mode),PVStr(xpath));

#ifdef __cplusplus
extern "C" {
#endif
void *dlopen(const char *path,int mode);
void *dlsym(void *handle,const char *symbol);
const char *dlerror(void);
int dlclose(void *handle);
/*
#define RTLD_LAZY ?
*/

#ifdef RTLD_now
#define RTLD_NOW RTLD_now
#elif defined(__OpenBSD__)
#define RTLD_NOW  0x101
#else
#define RTLD_NOW  1
#endif

#ifdef __cplusplus
}
#endif

typedef struct {
  const	char *name;
	void *addr;
  const	char *opts;
} DLMap;

int dl_main(int ac,char *av[]){
	return 0;
}

#if defined(__APPLE__)
#define LDPATHENV	"DYLD_LIBRARY_PATH"
#else
#define LDPATHENV	"LD_LIBRARY_PATH"
#endif

static const char *libpat[16] = {
#if defined(__APPLE__)
	"dglib%s.dylib",
	"lib%s.0.9.8.dylib", /* 9.2.5 for a while */
	"lib%s.dylib",
#else
#if !defined(_MSC_VER)
	"dglib%s.so",
	"lib%s.so.0.9.8",    /* 9.2.5 for a while */
	"lib%s.so",
	"lib%s.so.1.0.0",    /* 9.9.9 mod-140602e OpenSSL nowadays in 2014 */
	"lib%s.so.10", /* 9.9.10 mod-140630c for CentOS/6.5_64 */
	"lib%s.so.6", /* 9.9.5 for CentOS/5.3_64 */
	"lib%s.so.4", /* 9.9.2 for Vine4 */
	"lib%s.so.1",
	"lib%s.so.0",
	"lib%s.so.0.9.7", /* 9.2.2 for OpenSSL, for a while ... */
#endif
#endif
#if defined(__CYGWIN__)
	"cyg%s-0.9.8.dll", /* 9.9.10 fix-140704b */
	"cyg%s-1.0.0.dll", /* 9.9.10 fix-140704b */
#endif
#if defined(_MSC_VER) || defined(__CYGWIN__)
	"dglib%s.dll",
	"%s.dll",
#endif
	"%s",
	0
};

/* DYLIB="lib*.so,lib*.dylib,lib*.so.1" */
void scan_DYLIB(PCStr(conf)){
	CStr(pats,2048);
	CStr(pat1,256);
	refQStr(p1,pat1);
	const char *patv[8];
	int pc,pi;
	int px,pj;
	const char *savpat[elnumof(libpat)];

	strcpy(pats,conf);
	pc = list2vect(pats,',',8,patv);
	px = 0;
	for( pi = 0; pi < elnumof(savpat); pi++ )
		savpat[pi] = libpat[pi];
	for( pi = 0; pi < pc && pi < elnumof(libpat); pi++ ){
		if( elnumof(libpat)-1 < px )
			break;
		if( streq(patv[pi],"+") ){
			for( pj = 0; savpat[pj]; pj++ ){
				if( elnumof(libpat)-1 < px )
					break;
				libpat[px++] = savpat[pj];
			}
			continue;
		}
		strcpy(pat1,patv[pi]);
		strsubst(AVStr(pat1),"%","%%");
		if( p1 = strrchr(pat1,'*') )
			strsubst(AVStr(p1),"*","%s");
		libpat[px++] = stralloc(pat1);
		/*
		strsubst(AVStr(pat1),"*","%s");
		libpat[pi] = stralloc(pat1);
		*/
	}
	libpat[px] = 0;
	/*
	libpat[pc] = 0;
	*/

	if( lPATHFIND() ){
		CStr(path,2048);
		for( pi = 0; pi < px; pi++ ){
			strcpy(pat1,libpat[pi]);
			strsubst(AVStr(pat1),"%s","*");
			fprintf(stderr,"--- DYLIB[%d]=%s\n",pi,pat1);
			Xsprintf(TVStr(path),"%s%s",0<pi?",":"",pat1);
		}
		fprintf(stderr,"### DYLIB=\"%s\"\n",path);
	}
}

int dylib_exec(PCStr(path)){
	const char *ldpath;
	if( isWindows() ){
		return 0;
	}
	if( ldpath = getenv(LDPATHENV) ){
		return 0;
	}else{
		IStr(env,1024);
		sprintf(env,"%s=%s",LDPATHENV,path);
		if( !isWindows() ){
			strsubst(AVStr(env),";",":");
		}
		putenv(stralloc(env));
		if( lDYLIB() ){
			fprintf(stderr,"--- exported %s\n",env);
			iLog("--- exported %s",env);
		}
		return 1;
	}
}

static int stab0(){
	fprintf(stderr,"--- dynamic link stab called ---\r\n");
	return 0;
}
static int do_exit(){
	fprintf(stderr,"--- dynamic link unknown function called ---\r\n");
	_exit(0);
	return -1;
}

int dl_isstab(void *f){
	if( f == (void*)stab0 )
		return 1;
	if( f == (void*)do_exit )
		return 1;
	return 0;
}

int dl_libraryX(const char *libname,DLMap *dlmap,const char *mode);
int dl_library(const char *libname,DLMap *dlmap,const char *mode){
	int rcode;
	int omode;
	omode = LOG_type2;
	if( lDYLIB() ) LOG_type2 |= L_PATHFIND;
	rcode = dl_libraryX(libname,dlmap,mode);
	LOG_type2 = omode;
	return rcode;
}
int isFullpath(PCStr(path));
int File_is(PCStr(path));
void chdir_cwd(PVStr(cwd),PCStr(go),int userdir);
int dl_libraryX(const char *libname,DLMap *dlmap,const char *mode){
	CStr(libpath,1024);
	CStr(dlpathe,1024);
	void *handle;
	void *addr;
	int i;
	DLMap *dl;
	const char *name;
	const char *pat1;
	int unknown = 0;
	int already = 0;
	int nopts = 0;
	CStr(xpath,1024);
	const char *err;
	IStr(cwd,1024);

/*
	if( *(char**)dlmap[0].addr != 0 )
		return 0;
*/

	IGNRETS getcwd(cwd,sizeof(cwd));
	iLog("--- dl_library(%s)...",libname);
	if( lPATHFIND() ){
		CStr(name1,128);
		fprintf(stderr,"--- find dynamic library '%s' in DYLIB='",libname);
		for( i = 0; pat1 = libpat[i]; i++ ){
			if( 0 < i ) fprintf(stderr,",");
			strcpy(name1,pat1);
			strsubst(AVStr(name1),"%s","*");
			fprintf(stderr,"%s",name1);
			/*
			fprintf(stderr,"%s",pat1);
			*/
		}
		fprintf(stderr,"'\n");
	}
	handle = 0;
	truncVStr(libpath);
	sprintf(dlpathe,"DYLIB_%s",libname);
	if( pat1 = getenv(dlpathe) ){
		handle = dlopen(pat1,RTLD_NOW);
		if( handle ){
			if( lDYLIB() ){
				fprintf(stderr,"--- DYLIB_%s=%s\n",libname,pat1);
			}
			iLog("--- LOADED DYLIB_%s=%s\n",libname,pat1);
		}else{
			err = dlerror();
			fprintf(stderr,"--- FAILED DYLIB_%s=%s : %s\n",libname,pat1,
				err?err:"");
			iLog("--E FAILED [%s] DYLIB_%s=%s : %s\n",cwd,libname,
				pat1,err?err:"");
		}
	}
	if( handle == 0 )
	for( i = 0; pat1 = libpat[i]; i++ ){
		if( *pat1 == '!' || *pat1 == '-' ){
			pat1++;
			if( streq(pat1,libname) ){
				InitLog("## dont load %s\n",libname);
				return -1;
			}
		}
		if( strchr(pat1,'%') == 0 ){
			const char *dp;
			if( (dp = strstr(pat1,libname)) == 0 )
				continue;
			if( dp[strlen(libname)] != '.' )
				continue;
		}
		sprintf(libpath,pat1,libname);
		if( fullpathDYLIB(libpath,"r",AVStr(xpath)) ){
			if( File_is(xpath) && !isFullpath(xpath) ){
				/* 9.8.2 must be full-path to be consistently
				 * reloaded after exec/spawn, after becoming a
				 * server running at a different dir. (WORKDIR)
				 */
				CStr(ypath,1024);
				IGNRETS getcwd(ypath,sizeof(ypath));
				chdir_cwd(AVStr(ypath),xpath,0);
				if( File_is(ypath) ){
					strcpy(xpath,ypath);
				}
			}
			if( handle = dlopen(xpath,RTLD_NOW) ){
				InitLog("--- [%s]\n",xpath);
				if( lDYLIB() ){
					fprintf(stderr,"--- [%s]\n",xpath);
				}
				strcpy(libpath,xpath);
			}else{
				err = dlerror();
				InitLog("--- [%s] %s\n",xpath,err?err:"");
			}
		}
		if( handle == 0 )
		handle = dlopen(libpath,RTLD_NOW);
		InitLog("--- [%s] %X %s\n",libname,p2i(handle),libpath);
		iLog("--- [%s] %X %s",libname,p2i(handle),libpath);
		if( lDYLIB() || lPATHFIND() ){
			if( err = dlerror() ){
				InitLog("{l}-- [%s] %s\n",libname,err);
				iLog("{l}-- [%s] %s\n",libname,err);
			}
		}
		if( lPATHFIND() ){
			fprintf(stderr,"--- [%s] %X %s\n",libname,p2i(handle),libpath);
		}
		if( handle != NULL )
		{
			sprintf(dlpathe,"DYLIB_%s=%s",libname,libpath);
			putenv(stralloc(dlpathe));
			iLog("--- [%s] putenv(%s)\n",cwd,dlpathe);
			break;
		}
	}
	if( handle == NULL ){
		iLog("--E cannot load %s",libname);
		InitLog("## cannot load %s\n",libname);
		return -1;
	}
	dl = dlmap;
	for( i = 0; name= dl[i].name; i++ ){
		if( i == 0 && name[0] == '#' ){
			dl[0].addr = handle;
			continue;
		}
		addr = dlsym(handle,name);
		if( addr == 0
		 && *(char**)(dl[i].addr) != 0
		 && *(char**)(dl[i].addr) != (char*)do_exit
		){
			/*
			InitLog("in another module: %s\n",name);
			*/
			already++;
			continue;
		}
		if( addr == 0 && dl[i].opts && dl[i].opts[0] == '0' ){
			addr = (void*)stab0;
			InitLog("--- [%s] optional: %s\n",libname,name);
			nopts++;
		}
		if( addr == 0 ){
			unknown++;
			/*
			InitLog("## unknown [%s] %s\n",libpath,name);
			*/
			if( LOG_VERBOSE && lDYLIB() && !lISCHILD() ){
			fprintf(stderr,"## unknown [%s] %s\n",libpath,name);
			}
			*(char**)dl[i].addr = (char*)do_exit;
		}else{
			/*
			fprintf(stderr,"%X %X %s\n",dl[i].addr,addr,name);
			*/
			*(char**)dl[i].addr = (char*)addr;
		}
	}
InitLog("---- [%s] loaded %d syms, unknown=%d+%d, already=%d\n",
libname,i,unknown,nopts,already);
	if( already ){
		InitLog("---- unknown = %d+%d, already = %d / %d\n",
			unknown,nopts,already,i);
	}
	if( unknown )
		return -1;
	return 0;
}
void *dgdlsym(DLMap *dl,const char *sym){
	void *addr;
	if( dl[0].name && dl[0].name[0] == '#' && dl[0].addr ){
		addr = dlsym(dl[0].addr,sym);
		dlerror();
		return addr;
	}
	return 0;
}

int mysym_main(int ac,const char *av[]){
	void *me;
	int ai;
	const char *sym;
	const void *addr;

	me = dlopen(NULL,0);
	fprintf(stdout,"-- me: %X\n",p2i(me));
	if( me == 0 ){
		return -1;
	}
	for( ai = 1; ai < ac; ai++ ){
		sym = av[ai];
		addr = dlsym(me,sym);
		Xfprintf(stdout,"%08llX %s\n",p2llu(addr),sym);
	} 
	dlclose(me);
	return 0;
}
