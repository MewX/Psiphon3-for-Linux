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
Program:	cafe.c (Cache file expirer)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970429	created
//////////////////////////////////////////////////////////////////////#*/

/*
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
*/
#include "yarg.h"
#include "ystring.h"
#include "file.h"

int FS_withSymlink();
int lock_exclusiveTO(int fd,int timeout,int *elapsedp);
int stat_blocks(FileStat *stp);

#ifndef S_ISDIR
#define S_ISDIR(m)  (((m)&S_IFMT) == S_IFDIR)
#endif

#include "vsocket.h"

static const char *USAGE = "\
Cafe -- cache file expirer\n\
-----------------------------------------------------------------------\n\
Usage: %s [options] directories\n\
  -ic[DIR]      keep inode cache at dir for speed up\n\
  -du[OPT]      ex. -dua generates output like `du -a'\n\
  -atime N[m|h] select last accessed before than N days [min|hour]\n\
  -mtime N[m|h] select last modified before than N days [min|hour]\n\
  -asize N      total size (bytes) to be remained\n\
  -h            follow symbolic link\n\
  -m            follow mounted file system\n\
  -rm           remove selected file\n\
  -mvDIR        move slected file under DIR\n\
  -ls[OPT]      list selected file in `ls' like format (ex. -lslsu)\n\
  -print        print selected file name\n\
  -s            work silently reporting the total only (with -du)\n\
  dir           directory to be scanned\n\
Exmaple:\n\
  %s DIR -atime 12h -lslsu  -- list files not acceessed within 12 hours\n\
  %s DIR -atime 12h -rm  -- remove files not accessed within 12 hours\n\
-----------------------------------------------------------------------\n\
";
static void put_usage(FILE *out,PCStr(me))
{
	fprintf(out,USAGE,me,me,me,me);
}

static int ROOT_DEV;
static int DIRLEV;
static const char *CWD;

static int F_FOLLOW_MOUNT;
static int F_FOLLOW_SYMLINK;
static const char *ls_opts;
static int F_LSFORM;
static int F_UATIME; /* update the atime of directory after scanning */
static int F_VERBOSE;
static int F_DU;
static int F_DIR;
static int F_PRINT;
static int N_LIST;
static int F_REMOVE;
static int F_MOVE;
static int F_SUMMARY;
static int REM_SIZE;

static const char *F_TYPE;
static int F_NAME_NOT;
static const char *F_NAME;
static int A_FROM;
static int A_TILL;
static int M_FROM;
static int M_TILL;
static int NOW;
static int CNT;

static int N_DIR;
static int N_REG;
static int N_REM;
static int N_ERR;
static int N_BLK;
static int N_BLKREM;

static void loghead(FILE *out)
{	CStr(stime,128);

	StrftimeLocal(AVStr(stime),sizeof(stime),"%Y/%m/%d-%H:%M:%S",time(0),0);
	fseek(out,0,2);
	fprintf(out,"%s [%d] ",stime,getpid());
}

static FILE *LOG;
static void errlog(PCStr(fmt),...)
{	VARGS(16,fmt);
	loghead(LOG);
	fprintf(LOG,fmt,VA16);
	fflush(LOG);
}
static void summary(FILE *out,PCStr(root))
{
	loghead(out);
	fprintf(out,"%s: %d blk, %d dir, %d reg",root,N_BLK,N_DIR,N_REG);

	if( F_REMOVE )
		fprintf(out,", %d rem (%d blk), %d err",
			N_REM,N_BLKREM,N_ERR);

	fprintf(out,", %d sec\n",ll2i(time(0)-NOW));
}

typedef struct {
	int	d_top;
	FILE   *d_out;
	int	d_Rlen;
  const	char   *d_Root;
  const	char   *d_cwd;
	int	d_dev;
	int	d_ino;
	int	d_nch;
	int	d_nrm;
	int	d_lev;
	int	d_blocks;
} DA;

static void mkabspath(PVStr(path),PCStr(dir),PCStr(file))
{	const char *dp;
	char dc;
	refQStr(pp,path); /**/

	cpyQStr(pp,path);
	if( !isFullpath(file) ){
		for( dp = dir; dc = *dp; dp++ ){
			assertVStr(path,pp);
			setVStrPtrInc(pp,dc);
		}
		if( path < pp &&  pp[-1] != '/' ){
			setVStrPtrInc(pp,'/');
		}
	}
	strcpy(pp,file);
}

static void Stat(PCStr(path),FileStat *stp)
{
}

static char *filesys(PCStr(path),PVStr(root),PVStr(parent))
{	int dev;
	FileStat st;
	const char *dp;
	char dc;
	CStr(cwd,1024);
	CStr(xpath,1024);

	if( stat(path,&st) != 0 ){
		errlog("can't stat: %s\n",path);
		exit(1);
	}
	dev = st.st_dev;
	IGNRETS getcwd(cwd,sizeof(cwd));
	strcpy(xpath,path);
	if( !fileIsdir(xpath) ){
		if( dp = strrchr(xpath,'/') )
			*(char*)dp = 0;
		else	strcpy(xpath,".");
	}
	IGNRETZ chdir(xpath);
	IGNRETS getcwd(xpath,sizeof(xpath));
	strcpy(parent,xpath);

	for( dp = strchr(xpath,'/'); dp; dp = strchr(dp+1,'/') ){
		dc = dp[1];
		((char*)dp)[1] = 0;
		if( stat(xpath,&st) == 0 ){
			if( st.st_dev == dev ){
				if( dp != xpath )
					*(char*)dp = 0;
				strcpy(root,xpath);
				break;
			}
		}
		((char*)dp)[1] = dc;
	}

	IGNRETZ chdir(cwd);
	return (char*)root;
}
static int file_stats(int pdev,int pino,PVStr(path),PCStr(file),FileStat *stp,int *blocksp);
static void put_icacheR(PCStr(path))
{	const char *dp;
	char dc;
	int pdev,pino;
	FileStat st;
	CStr(xpath,1024);

	strcpy(xpath,path);
	pdev = pino = 0;

	for( dp = strchr(xpath,'/'); dp; dp = strchr(dp+1,'/') ){
		dc = dp[1];
		((char*)dp)[1] = 0;
		if( file_stats(pdev,pino,AVStr(xpath),xpath,&st,NULL) < 0 ){
			((char*)dp)[1] = dc;
			break;
		}
		((char*)dp)[1] = dc;
		pdev = st.st_dev;
		pino = st.st_ino;
	}
	file_stats(pdev,pino,AVStr(xpath),xpath,&st,NULL);
}

/*
 *	INODE CACHE
 */
typedef struct {
	int	 ic_dev;
  const char	*ic_rootpath;
	FILE	*ic_file;
} IC;
typedef struct {
  const char   *ie_icachedir;
	IC	ie_ICs[32];
	int	ie_put_force;
	int	ie_inocnt;
} ICacheEnv;
static ICacheEnv *iCacheEnv;
#define icachedir	iCacheEnv->ie_icachedir
#define ICs		iCacheEnv->ie_ICs
#define put_force	iCacheEnv->ie_put_force
#define inocnt		iCacheEnv->ie_inocnt
void minit_icache()
{
	if( iCacheEnv == 0 )
		iCacheEnv = NewStruct(ICacheEnv);
}

static FILE *fopen_rw(PCStr(path))
{	FILE *fp;

	if( (fp = fopen(path,"r+")) == NULL )
		fp = fopen(path,"w+");
	return fp;
}

static FILE *ino_cache_sort(int dev,PCStr(key))
{	CStr(path,1024);
	FILE *ics;

	sprintf(path,"%s/dev-%08x/ino-sort-by-%s",icachedir,dev,key);
	ics = fopen(path,"r+");
	if( ics == NULL )
		ics = fopen(path,"w+");
	return ics;
}
static FILE *ino_cache(xPVStr(rootpath),int dev,int *ixp)
{	CStr(icache,1024);
	CStr(path,1024);
	CStr(rootpathbuf,1024);
	CStr(parent,1024);
	CStr(tmp,1024);
	FILE *ic;
	int ix,dev1;

	if( icachedir == NULL )
		return NULL;

	for( ix = 0; dev1 = ICs[ix].ic_dev; ix++ ){
		if( dev1 == dev && ICs[ix].ic_file ){
			if( ixp ) *ixp = ix;
			if( rootpath && *rootpath == 0 )
				strcpy(rootpath,ICs[ix].ic_rootpath);
			return ICs[ix].ic_file;
		}
	}

	sprintf(icache,"%s/dev-%08x",icachedir,dev);
	if( !fileIsdir(icache) ){
		if( mkdir(icache,0755) != 0 ){
			errlog("can't make inode cache directory: %s\n",
				icache);
			exit(1);
		}
	}

	sprintf(path,"%s/rootpath",icache);
	if( rootpath && *rootpath ){
		ic = fopen_rw(path);
		if( ic == NULL ){
			errlog("can't make inode cache file: %s\n",path);
			return NULL;
		}
		rootpath = filesys(rootpath,AVStr(rootpathbuf),AVStr(parent));
		fputs(rootpath,ic);
		fclose(ic);

		if( inocnt == 0 ){
			inocnt++;
			put_force = 1;
			put_icacheR(parent);
			put_force = 0;
			inocnt--;
		}

	}else{
		ic = fopen(path,"r");
		if( ic == NULL ){
			errlog("can't open inode cache file: %s\n",path);
			return NULL;
		}
		if( rootpath == NULL )
			setPStr(rootpath,rootpathbuf,sizeof(rootpathbuf));
		fgets(tmp,sizeof(tmp),ic);
		Xsscanf(tmp,"%s",AVStr(rootpath));
		fclose(ic);
	}

	sprintf(path,"%s/ino",icache);
	ic = fopen_rw(path);
	if( ic == NULL ){
		errlog("can't make inode cache file: %s\n",path);
		exit(1);
	}

	ICs[ix].ic_dev = dev;
	ICs[ix].ic_file = ic;
	ICs[ix].ic_rootpath = stralloc(rootpath);
	if( ixp ) *ixp = ix;

	return ic;
}

typedef struct {
	int	i_ino;
	int	i_pino;
	int	i_blks;
	int	i_atime;
} INO;

static void put_inocache(int pdev,int pino,PVStr(path),FileStat *stp,int blocks)
{	FILE *ic;
	int ix;
	INO inoc;
	int dev = stp->st_dev;
	int ino = stp->st_ino;
	int atime = stp->st_atime;

	if( pino == 0 )
		return;

	if( !put_force )
	if( pdev != dev )
		return;

	if( (ic = ino_cache(AVStr(path),dev,&ix)) == NULL )
		return;

	inoc.i_ino   = ino;
	inoc.i_pino  = pino;
	inoc.i_blks  = blocks;
	inoc.i_atime = atime;
	fseek(ic,ino*sizeof(INO),0);
	fwrite(&inoc,sizeof(INO),1,ic);

	if( put_force ){
		fflush(ic);
		errlog("FLUSH: %d/%x %s\n",fileno(ic),ic,path);
	}
}

static int file_stats(int pdev,int pino,PVStr(path),PCStr(file),FileStat *stp,int *blocksp)
{       int rcode,blocks;

	if( FS_withSymlink() ){
		if( F_FOLLOW_SYMLINK )
			rcode = stat(file,stp);
		else	rcode = lstat(file,stp);
	}else{
		rcode = stat(file,stp);
	}

        if( rcode == 0 ){
		blocks = stat_blocks(stp);
		if( blocksp ) *blocksp = blocks;
		put_inocache(pdev,pino,AVStr(path),stp,blocks);
		return S_ISDIR(stp->st_mode);
        }else	return -1;
}


static int cmpino(INO **i1,INO **i2)
{	int diff;

	if( diff = (*i1)->i_atime - (*i2)->i_atime )
		return diff;
	if( diff = (*i2)->i_blks - (*i1)->i_blks )
		return diff;
	return (*i2)->i_ino - (*i1)->i_ino;
}

extern int scan_ino;
static scanDirFunc inofind1(PCStr(file),int ino,PVStr(name))
{
	if( scan_ino == ino ){
		strcpy(name,file);
		return ino;
	}
	return 0;
}
static void ino_name(PCStr(dir),int ino,PVStr(name))
{
	setVStrEnd(name,0);
	Scandir(dir,scanDirCall inofind1,ino,AVStr(name));
}

static void ino2path(int icx,PCStr(root),FILE *ic,int ino,PVStr(path))
{	int inov[256],lev,li;
	INO inob;
	refQStr(pp,path); /**/
	int cx;

	strcpy(path,root);
	for( lev = 0; lev < 256; lev++ ){
		inov[lev] = ino;
		fseek(ic,ino*sizeof(INO),0);
		IGNRETP fread(&inob,sizeof(INO),1,ic);
		if( inob.i_pino == 0 || inob.i_pino == ino )
			break;
		ino = inob.i_pino;
	}

	pp = (char*)path + strlen(path);
	for( li = lev-1; 0 <= li; li-- ){
		if( path < pp && pp[-1] != '/' )
			setVStrPtrInc(pp,'/');
		ino_name(path,inov[li],QVStr(pp,path));
		pp += strlen(pp);
	}
}

static void find_icache1(FILE *out,int dev,int nlist)
{	int imax;
	INO **inos,*inov;
	int ino,ngot,icx,ix,blks,rblks;
	FILE *ic,*ics;
	CStr(root,1024);
	CStr(path,2048);
	CStr(ctime,64);

	*root = 0;
	ic = ino_cache(AVStr(root),dev,&icx);
	if( ic == NULL )
		return;

	fflush(ic);
	fseek(ic,0,0);

	imax = file_size(fileno(ic)) / sizeof(INO);
	inos = (INO**)malloc(imax*sizeof(INO*));
	inov = (INO*)malloc(imax*sizeof(INO));

	ngot = 0;
	blks = 0;

	for( ino = 0; ino < imax && ngot < imax; ino++ ){
		if( fread(&inov[ngot],sizeof(INO),1,ic) == 0 ){
			errlog("premature EOF of inode-cache: %s\n",
				root);
			break;
		}
		if( inov[ngot].i_atime != 0 ){
			inos[ngot] = &inov[ngot];
			blks += inos[ngot]->i_blks;
			ngot++;
		}
	}

	qsort(inos,ngot,sizeof(INO*),(sortFunc)cmpino);
	ics = ino_cache_sort(dev,"atime");
	for( ix = 0; ix < ngot; ix++ )
		fwrite(inos[ix],sizeof(INO),1,ics);
	fclose(ics);

	printf("%s: %d inodes cached...\n",root,ngot);

	if( nlist == 0 )
		nlist = imax;
	rblks = 0;
	for( ix = 0; ix < ngot && ix < nlist; ix++ ){
		ino2path(icx,root,ic,inos[ix]->i_ino,AVStr(path));
		rblks += inos[ix]->i_blks;
		blks -= inos[ix]->i_blks;

		if( F_LSFORM ){
			FileStat st;
			if( stat(path,&st) == 0 ){
				printf("%8d ",(int)st.st_ino);
				ls_unix(out,ls_opts,CVStr(NULL),path,&st);
			}else{
				/* stale cache */
				/* remove it */
			}
		}else{
			rsctime(inos[ix]->i_atime,AVStr(ctime));
			printf("%8d %8d - %8d %6d %6d %s %s\n",
				rblks,blks,inos[ix]->i_blks,
				inos[ix]->i_ino,inos[ix]->i_pino,
				ctime,path);
		}

		if( REM_SIZE && REM_SIZE <= rblks )
			break;
	}

	free(inos);
	free(inov);
}

static void find_icache(FILE *out,PCStr(path),int nlist)
{	int dev;
	FileStat st;

	if( stat(path,&st) == 0 )
		find_icache1(out,st.st_dev,nlist);
	else	errlog("unknown path: %s\n",path);
}

/*
static int dir1(PCStr(cwd),PCStr(dir),PCStr(rdir),int dev,int ino,FILE *out,int *blocks);
*/
static int dir1(DA *da,PCStr(cwd),PCStr(dir),PCStr(rdir),int dev,int ino,FILE *out,int *blocks);
static scanDirFunc find1(PCStr(file),DA *da)
{	int isdir,mtime,atime,size,blocks,dev,ino;
	int cnt;
	int match,rcode,cblocks;
	CStr(path,1024);
	FILE *out = da->d_out;
	FileStat st;
	const char *ftype;

	if( !da->d_top && file[0] == '.' )
		if( file[1] == 0 || file[1] == '.' && file[2] == 0 )
			return 0;
	da->d_nch++;
	mkabspath(AVStr(path),da->d_cwd,file);

	CNT++;
	match = 0;
	rcode = 0;

	if( da->d_Root ){
	isdir = file_stats(da->d_dev,da->d_ino,AVStr(path),path,&st,&blocks);
	}else
	isdir = file_stats(da->d_dev,da->d_ino,AVStr(path),file,&st,&blocks);
	dev = st.st_dev;
	ino = st.st_ino;
	mtime = st.st_mtime;
	atime = st.st_atime;
	size = st.st_size;
	
	if( isdir < 0 ){
		errlog("can't access: %s\n",path);
		return 0;
	}

	if( !F_FOLLOW_MOUNT && dev != ROOT_DEV ){
		if( ROOT_DEV == 0 )
			ROOT_DEV = dev;
		else	return 0;
	}

	N_BLK += blocks;

	if( isdir ){
		N_DIR++;
		/*
		match = 0 < dir1(da->d_cwd,path,file,dev,ino,out,&cblocks);
		*/
		match = 0 < dir1(da,da->d_cwd,path,file,dev,ino,out,&cblocks);
		if( F_REMOVE ){
			match = match && (0 < N_REM);
		}else
		if( (A_FROM==0||A_FROM<=atime) && (A_TILL==0||atime<=A_TILL) )
		if( (M_FROM==0||M_FROM<=mtime) && (M_TILL==0||mtime<=M_TILL) )
			match = 1;
		else	match = 0;
	}else{
		N_REG++;
		if( (A_FROM==0||A_FROM<=atime) && (A_TILL==0||atime<=A_TILL) )
		if( (M_FROM==0||M_FROM<=mtime) && (M_TILL==0||mtime<=M_TILL) )
			match = 1;
	}

	if( F_TYPE ){
		switch( *F_TYPE ){
			case 'f': if(  isdir ){ match = 0; } break;
			case 'd': if( !isdir ){ match = 0; } break;
		}
	}
	if( F_NAME ){
		CStr(fnam,1024);
		const char *np;
		if( np = strrpbrk(file,"/") ){
			np++;
		}else{
			np = file;
		}
		if( rexpmatch(F_NAME,np) ){
			if(  F_NAME_NOT ) match = 0;
		}else{
			if( !F_NAME_NOT ) match = 0;
		}
	}

	if( match && F_REMOVE && !da->d_top ){
		if( isdir )
			rcode = rmdir(file);
		else	rcode = unlink(file);
		if( rcode == 0 ){
			da->d_nrm++;
			N_BLKREM += blocks;
			N_REM++;
		}else	N_ERR++;
	}
	if( match || F_DU ){
		da->d_blocks += blocks;
		if( isdir ) da->d_blocks += cblocks;
	}

	if( !match && (F_TYPE || F_NAME) ){
	}else
	if( match && (F_PRINT || F_LSFORM)
	 || da->d_top && !F_REMOVE
	 || isdir && F_DIR
	/* || isdir && match_in_child */
	){
		fseek(out,0,2);
		if( F_DU ){
			if( isdir )
				fprintf(out,"%-7d ",(blocks+cblocks)/2);
			else	fprintf(out,"%-7d ",blocks/2);
		}
		if( F_LSFORM ){
			ls_unix(out,ls_opts,CVStr(NULL),path,&st);
		}else{
			ftype = "";
			if( isdir && path[strlen(path)-1] != '/' )
				ftype = "/";
			if( da->d_Root
			 && strneq(path,da->d_Root,da->d_Rlen) ){
				fprintf(out,"%s%s\n",path+da->d_Rlen,ftype);
			}else
			fprintf(out,"%s%s\n",path,ftype);
		}
	}
	return 0;
}
/*
static void find0(FILE *out,PCStr(top))
*/
static void find0(FILE *out,PCStr(Root),PCStr(top))
{	DA dab;
	FileStat st;

	dab.d_top = 1;
	dab.d_out = out;
	dab.d_Rlen = Root?strlen(Root):0;
	dab.d_Root = Root;
	dab.d_cwd = "";
	dab.d_dev = 0;
	dab.d_ino = 0;
	dab.d_blocks = 0;
	dab.d_nch = 0;
	dab.d_nrm = 0;
	dab.d_lev = DIRLEV;
	find1(top,&dab);
}

static void ScandirNCAT(PCStr(path),PCStr(rdir),scanDirCallP func,PCStr(arg))
{	FileStat st;

	stat(path,&st);
	Scandir(rdir,func,arg);
	set_utimes(path,st.st_atime,st.st_mtime);
}

/*
static int dir1(PCStr(cwd),PCStr(dir),PCStr(rdir),int dev,int ino,FILE *out,int *blocks)
*/
static int dir1(DA *da,PCStr(cwd),PCStr(dir),PCStr(rdir),int dev,int ino,FILE *out,int *blocks)
{	DA dab;
	CStr(pcwd,1024);
	CStr(dirbuf,1024);

	*blocks = 0;
	if( chdir(rdir) != 0 ){
		errlog("can't chdir: %s\n",dir);
		return 0;
	}
	if( !isFullpath(cwd) ){
		mkabspath(AVStr(pcwd),CWD,cwd);
		cwd = pcwd;
	}

	if( da ){
		dab.d_Root = da->d_Root;
		dab.d_Rlen = da->d_Rlen;
	}
	dab.d_top = 0;
	dab.d_out = out;
	dab.d_cwd = dir;
	dab.d_dev = dev;
	dab.d_ino = ino;
	dab.d_blocks = 0;
	dab.d_nch = 0;
	dab.d_nrm = 0;
	dab.d_lev = DIRLEV;
	DIRLEV++;
	if( F_UATIME )
		Scandir(".",scanDirCall find1,&dab);
	else{
		if( !isFullpath(dir) ){
			mkabspath(AVStr(dirbuf),CWD,dir);
			dir = dirbuf;
		}
		ScandirNCAT(dir,".",scanDirCall find1,(char*)&dab);
	}
	DIRLEV--;

	if( chdir(cwd) != 0 ){
		errlog("can't return to: %s\n",cwd);
		exit(-1);
	}
	*blocks = dab.d_blocks;
	return dab.d_nch == dab.d_nrm;
}

static int get_period(PCStr(pspec))
{	int period;
	int type;

	type = pspec[0];
	if( type == '-' || type == '+' )
		pspec++;

	period = scan_period(pspec,'d',1);

	if( type == '-' )
		return -period;
	else	return  period;
}

static FILE *setlog(PCStr(path))
{	FILE *fp;

	if( path[0] == '-' )
		fp = fdopen(atoi(&path[1]),"a");
	else	fp = fopen(path,"a");

	if( fp == NULL ){
		syslog_ERROR("cannot open expire log: %s\n",path);
		exit(1);
	}
	if( lock_exclusiveTO(fileno(fp),1000,NULL) != 0 ){
		syslog_ERROR("cannot lock expire log: %s\n",path);
		exit(1);
	}
	return fp;
}
static char *catarg1(PCStr(args),xPVStr(ap),PCStr(arg))
{
	if( ap != args )
		setVStrPtrInc(ap,' ');
	strcpy(ap,arg);
	ap += strlen(ap);
	return (char*)ap;
}
int cafe_mainX(int ac,const char *av[],FILE *out,FILE *log)
{	const char *arg;
	int ai;
	int period;
	CStr(cwd,1024);
	const char *Root = 0;
	IStr(Rtop,1024);
	const char *tops[1024]; /**/
	const char *top;
	int topx,tx;
	int cacheonly = 0,wonly = 0;
	CStr(ls_optsb,128);
	CStr(args,64*1024);
	refQStr(ap,args); /**/
	const char *ax = &args[sizeof(args)-1];
	const char *pp;
	int fnot = 0;

	minit_icache();

	topx = 0;
	LOG = out;

	if( ac == 1 ){
		put_usage(LOG,av[0]);
		exit(0);
	}

	NOW = time(0);

	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		pp = ap;
		ap = catarg1(args,AVStr(ap),arg);
		if( ax <= ap ){
			break;
		}

		if( strncmp(arg,"-root=",6) == 0 ){
			Root = arg+6;
		}else
		if( strcmp(arg,"-not") == 0 ){
			fnot = ai+1;
		}else
		if( strcmp(arg,"-ign") == 0 ){
			++ai;
			ap = (char*)pp;
		}else
		if( strcmp(arg,"-log") == 0 || strcmp(arg,"-err") == 0 ){
			if( ++ai < ac ){
				LOG = setlog(av[ai]);
				ap = (char*)pp;
			}
		}else
		if( strcmp(arg,"-utime") == 0 ){
			F_UATIME = 1;
		}else
		if( strcmp(arg,"-atime") == 0 ){
			if( ++ai < ac ){
				ap = catarg1(args,AVStr(ap),av[ai]);
				period = get_period(av[ai]);
				if( period < 0 )
					A_FROM = NOW + period;
				else	A_TILL = NOW - period;
			}
		}else
		if( strcmp(arg,"-mtime") == 0 ){
			if( ++ai < ac ){
				ap = catarg1(args,AVStr(ap),av[ai]);
				period = get_period(av[ai]);
				if( period < 0 )
					M_FROM = NOW + period;
				else	M_TILL = NOW - period;
			}
		}else
		if( strcmp(arg,"-asize") == 0 ){
			if( ++ai < ac ){
				ap = catarg1(args,AVStr(ap),av[ai]);
				REM_SIZE = atoi(av[ai]);
			}
		}else
		if( strcmp(arg,"-name") == 0 ){
			if( ++ai < ac ){
				F_NAME_NOT = (fnot == ai-1);
				F_NAME = av[ai];
			}
		}else
		if( strcmp(arg,"-type") == 0 ){
			if( ++ai < ac ){
				F_TYPE = av[ai];
			}
		}else
		if( strncmp(arg,"-ls",3) == 0 ){
			F_LSFORM = 1;
			if( arg[3] == 0 )
				strcpy(ls_optsb,"dl");
			else	sprintf(ls_optsb,"d%s",&arg[3]);
			ls_opts = ls_optsb;
		}else
		if( strncmp(arg,"-du",3) == 0 ){
			F_DU = 1;
			if( strchr(&arg[3],'s') == 0 )
				F_DIR = 1;
			if( strchr(&arg[3],'a') != 0 )
				F_PRINT = 1;
		}else
		if( strcmp(arg,"-s") == 0 ){
			F_DIR = 0;
		}else
		if( strncmp(arg,"-ic",3) == 0
		 || strncmp(arg,"-iw",3) == 0
		 || strncmp(arg,"-ir",3) == 0
		){
			if( arg[3] )
				icachedir = &arg[3];
			else	icachedir = "/tmp/cafe";
			if( strncmp(arg,"-ir",3) == 0 )
				cacheonly = 1;
			if( strncmp(arg,"-iw",3) == 0 )
				wonly = 1;
		}else
		if( strncmp(arg,"-mv",3) == 0 ){
			F_MOVE = 1;
		}else
		if( strcmp(arg,"-h") == 0 ){ F_FOLLOW_SYMLINK = 1; }else
		if( strcmp(arg,"-m") == 0 ){ F_FOLLOW_MOUNT = 1; }else
		if( strcmp(arg,"-v") == 0 ){ F_VERBOSE = 1; }else
		if( strcmp(arg,"-a") == 0 ){ /* ignore */ }else
		if( strncmp(arg,"-p",2) == 0 ){ F_PRINT = 1; }else
		if( strcmp(arg,"-sum") == 0 ){ F_SUMMARY = 1; }else
		if( strcmp(arg,"-rm") == 0 ){ F_REMOVE = 1; }else
		if( arg[0] == '-' ){
			if( atoi(&arg[1]) )
				N_LIST = atoi(&arg[1]);
		}else{
			if( elnumof(tops)-2 <= topx ){
				continue;
			}
			tops[topx++] = arg;
			tops[topx] = 0;
			ap = (char*)pp;
		}
	}
	XsetVStrEnd(AVStr(ap),0);

	if( topx == 0 ){
		tops[topx++] = ".";
		tops[topx] = 0;
	}

	if( !F_PRINT && !F_LSFORM && !F_DU && !F_SUMMARY ){
		F_DU = 1;
	}

	if( icachedir != NULL && !fileIsdir(icachedir) ){
		if( mkdir(icachedir,0755) != 0 ){
			errlog("%s: can't make inode cache directory: %s\n",
				av[0],icachedir);
			exit(1);
		}
	}

	IGNRETS getcwd(cwd,sizeof(cwd));
	CWD = cwd;

	for( tx = 0; tx < topx; tx++ ){
		top = tops[tx];
		if( Root ){
			IStr(tmp,1024);
			strcpy(tmp,"");
			chdir_cwd(AVStr(tmp),top,0);
			strcpy(Rtop,Root);
			if( *tmp == '/' )
				ovstrcpy(tmp,tmp+1);
			if( *tmp ){
				if( strtailchr(Rtop) != '/' )
					strcat(Rtop,"/");
				strcat(Rtop,tmp);
			}
			top = Rtop;
		}

		if( LOG != stdout )
		if( LOG != out )
		errlog("%s %s\n",top,args);

		if( !icachedir || !cacheonly )
			find0(LOG,Root,top);
			/*
			find0(LOG,top);
			*/

		if( icachedir != NULL )
		if( !wonly )
			find_icache(LOG,top,N_LIST);

		if( F_SUMMARY )
			summary(LOG,top);
	}

	if( LOG != out )
	fclose(LOG);
	return 0;
}
int cafe_main(int ac,const char *av[]){
	cafe_mainX(ac,av,stdout,stdout);
	exit(0);
	return 0;
}
