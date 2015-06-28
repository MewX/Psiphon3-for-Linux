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
Program:	gzip.c
Author:		Yutaka Sato <ysato@delegate.org>
Description:

History:
	050501	created
//////////////////////////////////////////////////////////////////////#*/
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "ystring.h"
#include "log.h"
#include "proc.h"
#include "fpoll.h"
#include "ysignal.h"

#define GZDBG lZLIB()==0?0:fprintf

int setCloseOnFork(PCStr(wh),int fd);
int clearCloseOnFork(PCStr(wh),int fd);

#define Z_SYNC_FLUSH    2
#define Z_FULL_FLUSH    3

typedef int (*SYMADDR)(const char *sym,const void *addr,void **xaddr);
typedef void (*GZFUNCS)(void *_fdopen,void *_fread,void *_fwrite,void *_fprintf,void *_fputc,void *_fflush,void *_fclose);
static GZFUNCS _gzfuncs;

/*BEGIN_STAB(zlib)*/
typedef void *gzFile;
const char *zlibVersion();
gzFile gzopen(const char *path,const char *mode);
gzFile gzdopen(int fd,const char *mode);
int gzwrite(gzFile file,const void *buf,unsigned len);
int gzflush(gzFile file,int flush);
int gzread(gzFile file,void *buf,unsigned len);
int gzeof(gzFile);
long gztell(gzFile file);
int gzclose(gzFile file);
int gziocallback(const char *name,const void *addr);/*OPT(0)*/
const char *gzerror(gzFile file,int *errnum);
typedef unsigned char Byte;
typedef unsigned long uLong;
int compress2(Byte *dest,uLong *destLen,const Byte *source,uLong sourceLen,int lev);
int uncompress(Byte *dest,uLong *destLen,const Byte *source,uLong sourceLen);

typedef void *z_streamp;
int inflateInit_(z_streamp stream,const char *version,int stream_size);
int inflateEnd(z_streamp stream);
int inflate(z_streamp stream,int flush);
int deflateInit_(z_streamp stream,int level,const char *ver,int siz);
int deflate(z_streamp stream,int flush);
int deflateEnd(z_streamp stream);
/*END_STAB*/

typedef int (*IFUNC)();
int dl_library(const char *libname,DLMap *dlmap,const char *mode);

static int DGzlibVer;
int withDGZlib(){
	return DGzlibVer;
}

static FILE *xfdopen(int fd,const char *mode){
	FILE *fp;
	fp = fdopen(fd,mode);
	if( fp && streq(mode,"r") ){
		/*can have significant effect on parallelism */
		//setbuffer(fp,NULL,0);
	}
	//fprintf(stderr,"---- dgzlib:fdopen(%d,%s)=%X\n",fd,mode,fp);
	return fp;
}
int getthreadid();
int strCRC32(PCStr(str),int len);
int strCRC32add(int crc,PCStr(str),int len);
static int inlen;
static int xfread(char *buf,int siz,int nel,FILE *fp){
	int rel;

	fPollIn(fp,0);
	errno = 0;
	rel = fread(buf,siz,nel,fp);
	if( rel == 0 ){
		while( !feof(fp) ){
			fPollIn(fp,0);
			rel = fread(buf,siz,nel,fp);
fprintf(stderr,"----[%d] dgzlib:fread(%d)=%d RETRY\n",
getpid(),fileno(fp),rel);
			if( 0 < rel ){
				break;
			}
		}
	}

	if( rel <= 0 ){
		syslog_ERROR("[%X] xfread rcc=%d/%d +%d errno=%d\n",
			getthreadid(),rel,nel,inlen,errno);
	}

	if( 0 < rel ){
		inlen += rel;
		if( errno == EAGAIN ){
//fprintf(stderr,">>>>>>> dgzlib:fread(%d)=%d, errno=%d\n",fileno(fp),rel,errno);
			clearerr(fp);
			errno = 0;
		}
	}
	return rel;
}
static int xfwrite(const char *buf,int siz,int nel,FILE *fp){
	int wel;
	wel = fwrite(buf,siz,nel,fp);
	fflush(fp);
	return wel;
}
static int xfflush(FILE *fp){
	return fflush(fp);
}
static int xfclose(FILE *fp){
	return fclose(fp);
}
static int symaddr(const char *sym,const void *addr,void **xaddr){
	if( addr == fdopen ){ *xaddr = (void*)xfdopen; return 1; }
	if( addr == fflush ){ *xaddr = (void*)xfflush; return 1; }
	if( addr == fclose ){ *xaddr = (void*)xfclose; return 1; }
	if( addr == fread  ){ *xaddr = (void*)xfread;  return 1; }
	if( addr == fwrite ){ *xaddr = (void*)xfwrite; return 1; }
	return 0;
}

extern int inGzip;
extern const char *FL_F_Gzip;
extern int FL_L_Gzip;

#ifdef _MSC_VER
int gzipInit0(){
	int code;
	code = -1;
	if( isWindowsCE() )
		code = dl_library("dgcezlib1",dlmap_zlib,"");
	if( code != 0 )
	code = dl_library("dgzlib1",dlmap_zlib,"");
	return code;
}
void thread_yield();
int fd2handle(int fd);
int withDG_Zlib();
gzFile GZdopen(int fd,const char *mode){
	gzFile gz;
	int handle;

	thread_yield();

	inGzip++; FL_F_Gzip = "Gzdopen"; FL_L_Gzip = __LINE__;
    if( isWindows() && !withDG_Zlib() ){
	handle = 0x80000000 | fd2handle(fd);
	gz = gzdopen(handle,mode);
	if( gz == 0 ){
		syslog_ERROR("-- failed gzdopen(0x%X)\n",handle);
		gz = gzdopen(fd,mode);
	}
    }else{
	gz = gzdopen(fd,mode);
    }
	inGzip--;
	if( gz == 0 ){
		syslog_ERROR("-- failed gzdopen(%d)\n",fd);
	}
	return gz;
}
#else
int gzipInit0(){
	int code;
	code = dl_library("z",dlmap_zlib,"");
	if( code != 0 && isCYGWIN() ){
		code = dl_library("dgzlib1",dlmap_zlib,"");
	}
	return code;
}
/*
#define GZdopen(fd,mode) gzdopen(fd,mode)
*/
gzFile GZdopen(int fd,const char *mode){
	gzFile gz;
	inGzip++; FL_F_Gzip = "Gzdopen"; FL_L_Gzip = __LINE__;
	gz = gzdopen(fd,mode);
	inGzip--;
	return gz;
}
#endif
/* gztell()/malloc() should be sigblocked ... */
long GZtell(gzFile file){
	long off;
	inGzip++; FL_F_Gzip = "Gztell"; FL_L_Gzip = __LINE__;
	off = gztell(file);
	inGzip--;
	return off;
}
int GZclose(gzFile file){
	int rcode;
	inGzip++; FL_F_Gzip = "Gzclose"; FL_L_Gzip = __LINE__;
	rcode = gzclose(file);
	inGzip--;
	return rcode;
}

static void *Zmalloc(int siz){
	void *ptr;
	int nsiz;
	nsiz = ((siz+127)/128)*128;
	ptr = malloc(nsiz);
	GZDBG(stderr,"-- %4X Zmalloc(%d/%d)=%X\n",TID,siz,nsiz,p2i(ptr));
	return ptr;
}
void Zfree(void *ptr){
	free(ptr);
	GZDBG(stderr,"-- %4X Zfree(%X)\n",TID,p2i(ptr));
}

static void Znotify(const char *fmt,...){
	VARGS(8,fmt);
	fprintf(stderr,fmt,VA8);
}
static void Zclearerr(FILE *fp){
	clearerr(fp);
	GZDBG(stderr,"-- %X Zclearerr(%X)\n",TID,fileno(fp));
}
int SocketOf(int fd);
int ShutdownSocket(int fd);
int Gzip_NoFlush;
int fdebug(FILE *fp,const char *mode);
static int Zfclose(FILE *fp){
	int fd;
	int sock;
	int rcode;

	fflush(fp);
	fd = fileno(fp);
	if( sock = SocketOf(fd) ){
		ShutdownSocket(fileno(fp));
	}
	rcode = fclose(fp);
	GZDBG(stderr,"-- %X Zfclose(%X)=%d %s\n",TID,fd,rcode,
		sock?"(SOCKET)":"");

	return rcode;
}
static FILE *Zfdopen(int fd,const char *mode){
	FILE *fp;
	if( !isWindowsCE() && (fd & 0x80000000) ){
		fp = 0;
	}else
	fp = fdopen(fd,mode);
	GZDBG(stderr,"-- %X Zfdopen(%X,%s)=%X\n",TID,fd,mode,p2i(fp));
	if( fp && Gzip_NoFlush ){
		/*
		fdebug(fp,"w");
		*/
	}
	return fp;
}
static int Zfeof(FILE *fp){
	int rcode;
	rcode = feof(fp);
	GZDBG(stderr,"-- %X Zfeof(%X)=%d\n",TID,fileno(fp),rcode);
	return rcode;
}
static int Zferror(FILE *fp){
	int rcode;
	rcode = ferror(fp);
	GZDBG(stderr,"-- %X Zferror(%X)=%d\n",TID,fileno(fp),rcode);
	return rcode;
}
static int Zfflush(FILE *fp){
	int rcode;
	rcode = fflush(fp);
	GZDBG(stderr,"-- %X Zfflush(%X)=%d\n",TID,fileno(fp),rcode);
	return rcode;
}
static int Zfgetc(FILE *fp){
	int ch;
	ch = fgetc(fp);
	GZDBG(stderr,"-- %X Zfgetc(%X)=%02X\n",TID,fileno(fp),ch);
	return ch;
}
static int Zfprintf(FILE *fp,const char *fmt,...){
	int len;
	VARGS(16,fmt);
	len = fprintf(fp,fmt,VA16);
	GZDBG(stderr,"-- %X Zfprintf(%X)=%d\n",TID,fileno(fp),len);
	return len;
}
static int Zfputc(int ch,FILE *fp){
	int rcode;
	rcode = fputc(ch,fp);
	GZDBG(stderr,"-- %X Zfputc(%02X,%X)=%02X\n",TID,ch,fileno(fp),rcode);
	return rcode;
}
int fgetBuffered(PVStr(b),int n,FILE *fp);
static size_t Zfread(void *b,size_t z,size_t n,FILE *fp){
	int rcc;
	char *bp;
	/*
	if( !isWindowsCE() && z == 1 && ready_cc(fp) <= 0 ){
	*/
	if( !isWindowsCE() && z == 1 ){
		int rcc2;
		int fd = fileno(fp);
		/*
		rcc = read(fd,b,n);
		*/
		bp = (char*)b;
		rcc = fgetBuffered(ZVStr(bp,z),z,fp);
		if( 0 < rcc ){
			GZDBG(stderr,"-- %X Zfread:buff=%d\n",TID,rcc);
		}else
		if( rcc < 0 ){
			rcc = 0;
		}
		if( rcc < 32 && rcc < n ){
			rcc += read(fd,bp+rcc,n-rcc);
		}
		if( 0 < rcc && rcc < 32 && rcc < n ){
			if( 0 < PollIn(fd,30) ){
				rcc2 = read(fd,((char*)b)+rcc,n-rcc);
				if( 0 < rcc2 ){
					rcc += rcc2;
				}else{
				}
			}else{
			}
		}else{
		}
	}else{
	rcc = fread(b,z,n,fp);
	}
	GZDBG(stderr,"-- %X Zfread(%X,%d,%d)=%d\n",TID,fileno(fp),ll2i(z),ll2i(n),rcc);
	return rcc;
}
static size_t Zfwrite(const void *b,size_t z,size_t n,FILE *fp){
	int wcc;
	wcc = fwrite(b,z,n,fp);
	GZDBG(stderr,"-- %X Zfwrite(%X,%d,%d)=%d S%d\n",TID,fileno(fp),ll2i(z),ll2i(n),wcc,
		SocketOf(fileno(fp)));
	return wcc;
}
static int Zftell(FILE *fp){
	int off;
	off = ftell(fp);
	GZDBG(stderr,"-- %X Zftell(%X)=%d\n",TID,fileno(fp),off);
	return -1;
}
int Zfgzflush(FILE *fp){
	int fd;
	int rcode;

	fd = fileno(fp);
	rcode = fPollIn(fp,500);
	GZDBG(stderr,"-- %X Zfgzflush(%X)=%d\n",TID,fd,rcode);
	return rcode <= 0;
}
#if UNDER_CE
static char *Zstrerror(int code){
	GZDBG(stderr,"-- %X Zstrerror(%X)\n",TID,code);
	return "";
}
#else
static char *Zstrerror(int code){
	char *es;
	es = strerror(code);
	GZDBG(stderr,"---- Zstrerror(%d)\n",code);
	return es;
}
#endif


static int zlib_dl;
static int zlib_pid;
int withZlib(){
	return 0 < zlib_dl;
}
static int _dg_zlib;
int withDG_Zlib(){
	return 0 < _dg_zlib;
}
int gzipInit(){
	int code;

	if( 0 < zlib_dl ){
		if( isCYGWIN() ){
			if( zlib_pid != getpid() ){
				zlib_pid = 0;
				zlib_dl = 0;
			}
		}
	}
	if( zlib_dl != 0 ){
		if( 0 < zlib_dl )
			return 0;
		else	return -1;
	}
	code = gzipInit0();
	if( code == 0 ){
		if( isWindowsCE() )
		fprintf(stderr,"Loaded: %s\n",zlibVersion());
		if( mydlsym("gziocallback") )
		if( gziocallback("gzionotify",(void*)Znotify) == 0 ){
			_dg_zlib = 1;
			gziocallback("clearerr", (void*)Zclearerr);
			gziocallback("fclose",   (void*)Zfclose);
			gziocallback("fdopen",   (void*)Zfdopen);
			gziocallback("feof",     (void*)Zfeof);
			gziocallback("ferror",   (void*)Zferror);
			gziocallback("fflush",   (void*)Zfflush);
			gziocallback("fgetc",    (void*)Zfgetc);
			gziocallback("fprintf",  (void*)Zfprintf);
			gziocallback("fputc",    (void*)Zfputc);
			gziocallback("fread",    (void*)Zfread);
			gziocallback("fwrite",   (void*)Zfwrite);
			gziocallback("ftell",    (void*)Zftell);
			gziocallback("strerror", (void*)Zstrerror);
			if( strneq(zlibVersion(),"1.2.3.f-DeleGate-v",18) )
			if( 4 <= atoi(zlibVersion()+18) ){
				gziocallback("malloc",  (void*)Zmalloc);
				gziocallback("free",    (void*)Zfree);
				gziocallback("fgzflush",(void*)Zfgzflush);
				InitLog("+++ fgzflush() / %s\n",zlibVersion());
			}
		}
	}
	if( code == 0 ){
		InitLog("+++ loaded Zlib %s\n",zlibVersion());
		if( lDYLIB() )
		printf("+++ loaded Zlib %s\n",zlibVersion());
		zlib_pid = getpid();
		zlib_dl = 1;
		if( _gzfuncs = (GZFUNCS)mydlsym("gzfuncs") ){
//fprintf(stderr,"----------- fdopen=%X,fread=%X\n",fdopen,fread);
			(*_gzfuncs)((void*)xfdopen,(void*)xfread,(void*)xfwrite,0,0,(void*)xfflush,(void*)xfclose);
			DGzlibVer = 1;
		}
	}else{
		zlib_dl = -1;
	}
	return code;
}
const char *ZlibVersion(){
	if( 0 < zlib_dl )
	{
		if( isCYGWIN() ){
			gzipInit();
		}
		return zlibVersion();
	}
	if( zlib_dl == 0 )
		return "Not Yet";
	return "Not Found";
}
void putZLIBver(FILE *fp){
	if( 0 < zlib_dl )
		fprintf(fp,"Loaded: Zlib %s\r\n",zlibVersion());
}

#include "file.h"

#ifdef MMAP
#ifdef _MSC_VER /*{*/
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 0
static HANDLE last_fmh[2];
void *mmap(void *adr,size_t len,int pro,int flg,int fd,off_t off){
	void *addr;
	HANDLE fh,fmh;
	int protect;
	int acc;
	int rw;

	fh = (HANDLE)_get_osfhandle(fd);
	if( pro == PROT_READ ){
		protect = PAGE_READONLY;
		acc = FILE_MAP_READ;
	}else{
		protect = PAGE_READWRITE;
		acc = FILE_MAP_WRITE;
	}

	fmh = CreateFileMapping(fh,NULL,protect,0,off+len,NULL);
	if( last_fmh[0] == 0 )
		last_fmh[0] = fmh;
	else	last_fmh[1] = fmh;
	addr = MapViewOfFile(fmh,acc,0,off,len);
	return addr;
}
int munmap(void *adr,size_t le){
	int ok = UnmapViewOfFile(adr);
	if( last_fmh[0] ){
		CloseHandle(last_fmh[0]);
		last_fmh[0] = 0;
	}
	if( last_fmh[1] ){
		CloseHandle(last_fmh[1]);
		last_fmh[0] = 0;
	}
	return ok ? 0 : -1;
}

#else /*}{*/
#include <sys/mman.h>
#endif /*}*/

int gzipMmap(int do_comp,FILE *in,FILE *out){
	double Start = Time();
	int ifd,ofd;
	int iz,izm;
	unsigned long oz;
	Byte *ia,*iam;
	Byte *oa,*oam;
	int rcode;
	int ioff;
	int ooff;

	ifd = fileno(in);
	ofd = fileno(out);
	if( !file_isreg(ifd) || !file_isreg(ofd) ){
		syslog_ERROR("--- gzipMmap: not reg-file: %d %d\n",ifd,ofd);
		return -1;
	}

	ioff = lseek(ifd,0,1);
	ooff = lseek(ofd,0,1);
	izm = file_size(ifd);
	iz = izm - ioff;
	if( do_comp )
		oz = 1024+iz;
	else	oz = 1024+iz*20;

	iam = (Byte*)mmap(0,izm,PROT_READ,MAP_SHARED,ifd,0);
	if( iam == 0 ){
		syslog_ERROR("--- gzipMmap: can't open in mmap(%d)\n",ifd);
		return -1;
	}
	ia = iam + ioff;

	oa = (Byte*)mmap(0,oz,PROT_READ|PROT_WRITE,MAP_SHARED,ofd,ooff);
	if( oa == 0 ){
		syslog_ERROR("--- gzipMmap: can't open out mmap(%d)\n",ofd);
		munmap(iam,iz);
		return -1;
	}

	lseek(ofd,oz-1,1);
	write(ofd,"",1);
	if( do_comp ){
		/*
		Byte *op = oa;
		*op++ = 0x1F; *op++ = 0x8B; *op++ = 8;
		*op++ = 0; *op++ = 0; *op++ = 0; *op++ = 0;
		*op++ = 0; *op++ = 0; *op++ = 3;
		rcode = compress2(op,&oz,ia,iz,-1);
		if( rcode == 0 ){
			oz += (op - oa);
		}
		*/
		rcode = compress2(oa,&oz,ia,iz,-1);
	}else{
		rcode = uncompress(oa,&oz,ia,iz);
	}

	munmap(iam,izm);
	munmap(oa,oz);

	syslog_ERROR("(%.4f)g%szip/mmap(%d) %d -> %d\n",
		Time()-Start,do_comp?"":"un",rcode,iz,oz);

	if( rcode == 0 ){
		Ftruncate(out,ooff+oz,0);
		fseek(out,0,0);
		if( do_comp )
			return iz;
		else	return oz;
	}
	lseek(ifd,ioff,0);
	lseek(ofd,ooff,0);
	Ftruncate(out,0,1);
	return -1;
}
#endif

int setNonblockingIO(int,int);
int finputReady(FILE *fs,FILE *ts);
int ready_cc(FILE *fp);

static int xread(FILE *fp,PVStr(buf),int siz){
	int rcc;
	int ch;

	if( 0 < ready_cc(fp) ){
		for( rcc = 0; rcc < siz; rcc++ ){
			if( ready_cc(fp) <= 0 ){
				break;
			}
			ch = getc(fp);
			if( ch == EOF )
				break;
			setVStrElem(buf,rcc,ch);
		}
	}else{
		rcc = read(fileno(fp),(char*)buf,siz);
	}
	return rcc;
}

FileSize Lseek(int,FileSize,int);
int IsConnected(int sock,const char **reason);
int file_isSOCKET(int fd);
int gotSIGPIPE();
/*
int GZIPready = -1;
static void sendsync(int fd,int code){
	CStr(stat,1);
	if( fd < 0 ){
	}else{
		setVStrElem(stat,0,code);
		write(fd,stat,1);
		close(fd);
	}
}
*/
typedef int SyncXF(void *sp,int si,int code);
static void sendsyncX(SyncXF syncf,void *sp,int si,int code){
	if( syncf != 0 ){
		syslog_ERROR("--- gzipFX SYNC %X(%X,%d,%d)\n",xp2i(syncf),p2i(sp),si,code);
		(*syncf)(sp,si,code);
	}
}
#define sendsync(fd,code) sendsyncX(syncf,sp,si,code)
int gzipFilterX(FILE *in,FILE *out,SyncXF syncf,void *sp,int si);
int gzipFilter(FILE *in,FILE *out){
	int leng;
	leng = gzipFilterX(in,out,0,0,0);
	return leng;
}
int gzipFilterX(FILE *in,FILE *out,SyncXF syncf,void *sp,int si){
	gzFile gz;
	int len,rcc;
	CStr(buf,1024*8);
	int size;
	int gsize;
	int wcc;
	int bcc = 0;
	double Start = Time();
	double Prevf = 0;
	int ibz = sizeof(buf);
	int gi;
	int fd = -1;
	int ofd = fileno(out);
	int xfd;
	int zerr = 0;
	/*
	int rready = -1;
	*/

	errno = 0;
	fd = dup(fileno(out));
	if( fd < 0 ){
		syslog_ERROR("--gzipFilter[%d]<-[%d] errno=%d\n",fd,ofd,errno);
		return -1;
	}

	/*
	if( 0 <= GZIPready )
		rready = dup(GZIPready);
	*/
	len = 0;
	/*
	if( gz = GZdopen(dup(fileno(out)),"w") ){
	*/
	if( file_isSOCKET(ofd) || file_ISSOCK(ofd) )
	if( !IsConnected(ofd,NULL) || !IsAlive(ofd) ){

fprintf(stderr,"[%d.%X] gzip DISCONN\n",getpid(),getthreadid());
fprintf(stderr,"[%d.%X] gzip DISCONN fd[%d] con=%d isSOCK=%d,%d,%d\n",
getpid(),getthreadid(),ofd,IsConnected(ofd,NULL),
file_isSOCKET(ofd),file_ISSOCK(ofd),file_issock(ofd));

		sendsync(rready,1);
		close(fd);
		return -1;
	}
	gz = GZdopen(fd,"w");
	if( file_isSOCKET(ofd) || file_ISSOCK(ofd) )
	if( !IsConnected(ofd,NULL) || !IsAlive(ofd) ){

fprintf(stderr,"[%d.%X] gzip DISCONN gx=%d\n",getpid(),getthreadid(),p2i(gz));
fprintf(stderr,"[%d.%X] gzip DISCONN fd[%d] con=%d isSOCK=%d,%d,%d\n",
getpid(),getthreadid(),ofd,IsConnected(ofd,NULL),
file_isSOCKET(ofd),file_ISSOCK(ofd),file_issock(ofd));

		close(fd);
		sendsync(rready,2);
		close(fd);
		return -1;
	}

	if( gz ){
		LOGX_gzip++;
		if( Gzip_NoFlush ){
			GZDBG(stderr,"-- %X gzip flush disabled(%d)\n",
				TID,Gzip_NoFlush);
		}
		Prevf = Time();

		sendsync(rready,0);
		setCloseOnFork("GZIPstart",fd);
		/*
		while( rcc = fread(buf,1,sizeof(buf),in) ){
		*/
		for( gi = 0;; gi++ ){
			if( gotsigTERM("gzip gi=%d",gi) ){
				if( numthreads() && !ismainthread() ){
					thread_exit(0);
				}
				break;
			}
			if( !Gzip_NoFlush )
			if( bcc )
			if( 0 < len && finputReady(in,NULL) == 0 ){
				zerr =
				gzflush(gz,Z_SYNC_FLUSH);
if( zerr ){
porting_dbg("+++EPIPE[%d] gzflush() zerr=%d %d SIG*%d",fd,zerr,len,gotSIGPIPE());
}
				bcc = 0;
			}
			if( lSINGLEP() ) /* could be generic */
			{
				if( 0 < len )
				if( !Gzip_NoFlush
				 || 4 < gi && 5 < Time()-Prevf
				){
				GZDBG(stderr,"-- %X gzip flush %d(%f) %d/%d\n",
				TID,Gzip_NoFlush,Time()-Start,len,gi);
					Prevf = Time();
					zerr = gzflush(gz,Z_SYNC_FLUSH);
					bcc = 0;
					if( zerr ){
				GZDBG(stderr,"-- %X gzip gzflush()%d err=%d\n",
				TID,len,zerr);
						break;
					}
				}
			}
			/*
			rcc = fread(buf,1,sizeof(buf),in);
			*/
			rcc = xread(in,AVStr(buf),QVSSize(buf,ibz));

			if( rcc <= 0 ){
				break;
			}
			wcc =
			gzwrite(gz,buf,rcc);

//fprintf(stderr,"[%d] Gzwrite %d/%d / %d\n",getpid(),wcc,rcc,len);

if( wcc <= 0 ){
porting_dbg("+++EPIPE[%d] gzwrite() %d/%d %d SIG*%d",fd,wcc,rcc,len,gotSIGPIPE());
fprintf(stderr,"[%d] Gzwrite %d/%d / %d\n",getpid(),wcc,rcc,len);
break;
}

			if( wcc != rcc ){
				syslog_ERROR("gzwrite %d/%d\n",wcc,rcc);
			}
			if( 0 < wcc ){
				bcc += wcc;
			}
			if( sizeof(buf) <= len ){
				ibz = sizeof(buf);
			}
			if( !Gzip_NoFlush )
			if( bcc )
			if( sizeof(buf) <= bcc || len < 16*1024 ){
				zerr =
				gzflush(gz,Z_SYNC_FLUSH);
				bcc = 0;
			}
			if( zerr || gotSIGPIPE() ){
porting_dbg("+++EPIPE[%d] gzflush() zerr=%d %d SIG*%d",fd,zerr,len,gotSIGPIPE());
				break;
			}
			len += rcc;
		}
		if( len == 0 ){
			const char *em;
			int en;
			int ef;
			em = gzerror(gz,&en);
			ef = gzeof(gz);
			if( en == -1 /* see errno */ && errno == 0 ){
				/* no error */
			}else{
			daemonlog("F","FATAL: gzwrite(%d)=%d/%d eof=%d %d %s\n",
				fd,len,bcc,ef,en,em);
			porting_dbg("FATAL: gzwrite(%d)=%d/%d eof=%d %d %s",
				fd,len,bcc,ef,en,em);
			}
		}
		clearCloseOnFork("GZIPend",fd);
		gzflush(gz,Z_SYNC_FLUSH);
		xfd = dup(fd);
		gsize = GZtell(gz);
		GZclose(gz);
		if( isWindowsCE() || lMULTIST() ){
			/* duplicated close of fd is harmful */
		}else
		if( isWindows() ) close(fd); /* to clear osf-handle mapping */
		Lseek(xfd,0,2);
		size = Lseek(xfd,0,1);
		Lseek(xfd,0,0);
		close(xfd);
		syslog_DEBUG("(%f)gzipFilter %d -> %d / %d\n",Time()-Start,
			len,gsize,size);
		return len;
	}
	sendsync(rready,3);
	close(fd);
	return 0;
}
typedef int SyncF(void *sp,int si);
int gunzipFilterX(FILE *in,FILE *out,SyncF syncf,void *sp,int si);
int gunzipFilter(FILE *in,FILE *out){
	int leng;
	leng = gunzipFilterX(in,out,0,0,0);
	return leng;
}
int gunzipFilterX(FILE *in,FILE *out,SyncF syncf,void *sp,int si){
	gzFile gz;
	int rcc;
	int wcc;
	int werr;
	CStr(buf,1024*8);
	int size;
	double Start = Time();
	const char *em;
	int en;
	int ef;
	int ready;
	int rd;
	int eof = 0;
	int nonblock;
	int serrno = 0;

	int ibz = sizeof(buf);
	int gi;
	int fd = -1;

	inlen = 0;
	errno = 0;
	fd = dup(fileno(in));

    if( isWindows() ){
	int pollPipe(int,int);
	nonblock = 0;
	ready = fPollIn(in,10*1000);
	gz = GZdopen(fd,"r");
	if( gz == 0 )
	syslog_ERROR("##gunzipFilter[%d/%d] gz=%X ready=%d/%d\n",
		fd,fileno(in),p2i(gz),ready,pollPipe(fd,1));
    }else{
	/*
	 * to make smooth streaming of data relayed on narrow network
	 * apply NBIO to gzopen() which will do fread() at the start.
	 * applying NBIO also to gzread() seems to break the gzip.
	 */
	/*
	setNonblockingIO(fileno(in),1);
	*/
	setNonblockingIO(fd,1);
	nonblock = 1;
	ready = fPollIn(in,10*1000);
	if( ready == 0 ){
fprintf(stderr,"----[%d] gunzipFilter: ready[%d]=%d\n",
getpid(),fileno(in),ready);
	}
	/*
	gz = GZdopen(fd = dup(fileno(in)),"r");
	*/
	gz = GZdopen(fd,"r");
	if( DGzlibVer == 0 )
	{
		/*
	setNonblockingIO(fileno(in),0);
		*/
		setNonblockingIO(fd,0);
		nonblock = 0;
	}
    }
	if( syncf != 0 ){
		syslog_ERROR("--- gunzipFX SYNC %X(%X,%d)\n",xp2i(syncf),p2i(sp),si);
		(*syncf)(sp,si);
	}

	ibz = 1024;
	//ibz = 256;

	size = 0;
	/*
	if( gz = GZdopen(dup(fileno(in)),"r") ){
	*/
	if( gz ){
		LOGX_gunzip++;
		setCloseOnFork("GUNZIPstart",fd);
		em = gzerror(gz,&en);
		/*
		while( 0 < (rcc = gzread(gz,buf,sizeof(buf))) ){
		*/
		for( gi = 0;; gi++ ){
			if( gotsigTERM("gunzip gi=%d em=%X",gi,p2i(em)) ){
				if( numthreads() ){
					if( em ){
						putfLog("thread-gunzip gi=%d _exit() em=(%s)",gi,em?em:"");
						_exit(0);
					}
					thread_exit(0);
				}
				break;
			}
			if( nonblock ){
				if( 0 < gi ){
					/*
					setNonblockingIO(fileno(in),0);
					*/
					setNonblockingIO(fd,0);
					nonblock = 0;
				}
			}
			/*
			if( 0 < size && inputReady(fileno(in),NULL) == 0 ){
			*/
			/*
			if( 0 < size && inputReady(fd,NULL) == 0 ){
			*/
			if( eof == 0 )
			if( 0 < size )
			if( ready = inputReady(fd,&rd) ){
				if( ready == 2 ){ /* both PS_IN and PS_PRI */
					eof = 1;
				}
			}else{
//fprintf(stderr,"[%d] -- gzread#%d %d / %d FLUSH\n",getpid(),gi,rcc,size);
				fflush(out);
			}
			ready = fPollIn(in,10*1000);
			errno = 0;
			rcc = gzread(gz,buf,QVSSize(buf,ibz));
			serrno = errno;
			if( rcc <= 0 ){
				break;
			}
//fprintf(stderr,"[%d] -- gzread %d / %d\n",getpid(),rcc,size);
			wcc =
			fwrite(buf,1,rcc,out);
			/* this fflush seems significant */
			werr =
			fflush(out);
			if( wcc < rcc || werr || ferror(out) || gotSIGPIPE() ){
porting_dbg("+++EPIPE[%d] gunzip fwrite() %d/%d err=%d/%d %d SIG*%d",fileno(out),wcc,rcc,werr,ferror(out),size,gotSIGPIPE());
				break;
			}

			size += rcc;
			if( size < sizeof(buf) ){
				fflush(out);
			}else{
				ibz = sizeof(buf);
			}
		}
		fflush(out);
		if( rcc < 0 || size == 0 ){
			em = gzerror(gz,&en);
			ef = gzeof(gz);
			if( en == -1 /* see errno */ && serrno == 0 ){
				/* no error */
			}else{
			daemonlog("F","FATAL: gzread(%d)=%d/%d eof=%d %d %s %d\n",
				fd,rcc,size,ef,en,em,serrno);
			porting_dbg("FATAL: gzread(%d)=%d/%d eof=%d %d %s",
				fd,rcc,size,ef,en,em);
			if( lTHREAD() )
			fprintf(stderr,"--[%d]gzread(%d)=%d/%d eof=%d %d %s\n",
				getpid(),fd,rcc,size,ef,en,em);
			}
		}
		clearCloseOnFork("GUNZIPend",fd);
		GZclose(gz);
		if( isWindowsCE() || lMULTIST() ){
			/* duplicated close of fd is harmful */
		}else
		if( isWindows() ) close(fd);
		fseek(out,0,0);
		syslog_DEBUG("(%f)gunzipFilter -> %d\n",Time()-Start,size);

if( lTHREAD() )
if( 0 < inlen )
syslog_ERROR("###GUNZIP filter %d/%d\n",inlen,size);
		return size;
	}
	return 0;
}

/*
int inflateFilter(FILE *in,FILE *out){
	int rcc;
	CStr(ibuf,1024*8);
	int size;
	double Start = Time();
	const char *em;
	int en;
	int ibz = sizeof(buf);
	int gi;
	int fd = -1;

	ibz = 512;
	if( gz ){
		for( gi = 0;; gi++ ){
			if( 0 < size && inputReady(fileno(in),NULL) == 0 ){
				fflush(out);
			}
			rcc = fread(gz,buf,QVSSize(buf,ibz));
			if( rcc <= 0 ){
				break;
			}
			inflate();
			fwrite(buf,1,rcc,out);
			size += rcc;
			if( size < sizeof(buf) ){
				fflush(out);
			}else{
				ibz = sizeof(buf);
			}
		}
		if( rcc < 0 ){
			em = gzerror(gz,&en);
			daemonlog("F","FATAL: gzread()=%d %d %s\n",rcc,en,em);
		}
		fseek(out,0,0);
		syslog_DEBUG("(%f)gunzipFilter -> %d\n",Time()-Start,size);
		return size;
	}
	return 0;
}
*/

#define Z_OK		 0
#define Z_STREAM_END	 1
#define Z_ERRNO		-1
#define Z_STREAM_ERROR	-2
#define Z_VERSION_ERROR	-6
#define Z_SYNC_FLUSH	 2
#define Z_BEST_SPEED	 1

/* portable z_stream ...
 * z_stream available at the runtime might be different from the one
 * at the compile time ...
 */
typedef struct _Z64_stream {
     const char	*next_in;
	int	 avail_in;
	Int64	 total_in; /* long or off_t */

	char	*next_out;
	int	 avail_out;
	Int64	 total_out; /* long or off_t */

	char	*msg;
	void	*state;

	void  *(*zalloc)(void*,unsigned int,unsigned int);
	void   (*zfree)(void*,void*);
	void	*opaque;

	int	 data_type;
	long	 adler;
	long	 reserved;
} Z64_stream;
typedef struct _Z32_stream {
     const char	*next_in;
	int	 avail_in;
	long	 total_in; /* long or off_t */

	char	*next_out;
	int	 avail_out;
	long	 total_out; /* long or off_t */

	char	*msg;
	void	*state;

	void  *(*zalloc)(void*,unsigned int,unsigned int);
	void   (*zfree)(void*,void*);
	void	*opaque;

	int	 data_type;
	long	 adler;
	long	 reserved;
} Z32_stream;
static int Zenpack(Z1Ctx *Zc,Z32_stream *Z32){
	Z64_stream *Z64 = (Z64_stream*)Zc->z1_Z1;

	Z32->next_in   = Z64->next_in;
	Z32->avail_in  = Z64->avail_in;
	Z32->total_in  = Z64->total_in;
	Z32->next_out  = Z64->next_out;
	Z32->avail_out = Z64->avail_out;
	Z32->total_out = Z64->total_out;
	Z32->msg       = Z64->msg;
	Z32->state     = Z64->state;
	Z32->zalloc    = Z64->zalloc;
	Z32->zfree     = Z64->zfree;
	Z32->opaque    = Z64->opaque;
	Z32->data_type = Z64->data_type;
	Z32->adler     = Z64->adler;
	Z32->reserved  = Z64->reserved;
	return 0;
}
static int Zdepack(Z1Ctx *Zc,Z32_stream *Z32){
	Z64_stream *Z64 = (Z64_stream*)Zc->z1_Z1;

	Z64->next_in   = Z32->next_in;
	Z64->avail_in  = Z32->avail_in;
	Z64->total_in  = Z32->total_in;
	Z64->next_out  = Z32->next_out;
	Z64->avail_out = Z32->avail_out;
	Z64->total_out = Z32->total_out;
	Z64->msg       = Z32->msg;
	Z64->state     = Z32->state;
	Z64->zalloc    = Z32->zalloc;
	Z64->zfree     = Z32->zfree;
	Z64->opaque    = Z32->opaque;
	Z64->data_type = Z32->data_type;
	Z64->adler     = Z32->adler;
	Z64->reserved  = Z32->reserved;
	return 0;
}

static void *zalloc(void *opq,unsigned int ne,unsigned int siz){
	Z1Ctx *Zc = (Z1Ctx*)opq;
	void *ptr;

	ptr = calloc(ne,siz);
	if( ptr == 0 ){
		fprintf(stderr,"----Za no more memory\r\n");
		syslog_ERROR("----Za no more memory\n");
		exit(-1);
	}
	Zc->z1_asize += ne*siz;
	Zc->z1_acnt++;
	if( Zc->z1_debug ){
		fprintf(stderr,"----Za %6d (%d,%d) = %X, OPQ=%X %d %d\r\n",
			ne*siz,ne,siz,p2i(ptr),p2i(opq),Zc->z1_acnt,Zc->z1_asize);
	}
	return ptr;
}
static void zfree(void *opq,void *ptr){
	Z1Ctx *Zc = (Z1Ctx*)opq;

	if( ptr == 0 ){
		return;
	}
	if( Zc->z1_debug ){
		fprintf(stderr,"----Zf %8X\r\n",p2i(ptr));
	}
	free(ptr);
	Zc->z1_fcnt++;
}
int XdeflateInit_(Z1Ctx *Zc,int level,const char *version,int siz){
	Z32_stream Z32;

	if( deflateInit_(Zc->z1_Z1,level,version,sizeof(Z64_stream)) == Z_OK ){
		Zc->z1_ssize = sizeof(Z64_stream);
		return Z_OK;
	}
	Zenpack(Zc,&Z32);
	if( deflateInit_(&Z32,level,version,sizeof(Z32_stream)) == Z_OK ){
		Zdepack(Zc,&Z32);
		Zc->z1_ssize = sizeof(Z32_stream);
		return Z_OK;
	}
	return Z_VERSION_ERROR;
}
int XinflateInit_(Z1Ctx *Zc,const char *version,int siz){
	Z32_stream Z32;

	if( inflateInit_(Zc->z1_Z1,version,sizeof(Z64_stream)) == Z_OK ){
		Zc->z1_ssize = sizeof(Z64_stream);
		return Z_OK;
	}
	Zenpack(Zc,&Z32);
	if( inflateInit_(&Z32,version,sizeof(Z32_stream)) == Z_OK ){
		Zdepack(Zc,&Z32);
		Zc->z1_ssize = sizeof(Z32_stream);
		return Z_OK;
	}
	return Z_VERSION_ERROR;
}
int Xdeflate(Z1Ctx *Zc,int flush){
	Z32_stream Z32;
	int rcode;

	if( Zc->z1_ssize == sizeof(Z64_stream) ){
		return deflate(Zc->z1_Z1,flush);
	}
	Zenpack(Zc,&Z32);
	rcode = deflate(&Z32,flush);
	Zdepack(Zc,&Z32);
	return rcode;
}
int Xinflate(Z1Ctx *Zc,int flush){
	Z32_stream Z32;
	int rcode;

	if( Zc->z1_ssize == sizeof(Z64_stream) ){
		return inflate(Zc->z1_Z1,flush);
	}
	Zenpack(Zc,&Z32);
	rcode = inflate(&Z32,flush);
	Zdepack(Zc,&Z32);
	return rcode;
}
int XdeflateEnd(Z1Ctx *Zc){
	Z32_stream Z32;
	int rcode;

	if( Zc->z1_ssize == sizeof(Z64_stream) ){
		return deflateEnd(Zc->z1_Z1);
	}
	Zenpack(Zc,&Z32);
	rcode = deflateEnd(&Z32);
	Zdepack(Zc,&Z32);
	return rcode;
}
int XinflateEnd(Z1Ctx *Zc){
	Z32_stream Z32;
	int rcode;

	if( Zc->z1_ssize == sizeof(Z64_stream) ){
		return inflateEnd(Zc->z1_Z1);
	}
	Zenpack(Zc,&Z32);
	rcode = inflateEnd(&Z32);
	Zdepack(Zc,&Z32);
	return rcode;
}

Z1Ctx *createZ1(Z1Ctx *Zc,int de){
	int siz = sizeof(Z64_stream);
	const char *ver;
	Z64_stream *Z1;
	int rcode;

	if( gzipInit() != 0 ){
		fprintf(stderr,"----createZ1 FATAL Zlib unavailable\n");
		return 0;
	}
	ver = zlibVersion();
	Z1 = (Z64_stream*)malloc(siz);
	bzero(Z1,siz);

	Z1->zalloc = zalloc;
	Z1->zfree = zfree;
	Z1->opaque = Zc;
	Zc->z1_Z1 = Z1;
	if( de ){
		rcode = XdeflateInit_(Zc,Z_BEST_SPEED,ver,siz);
	}else{
		rcode = XinflateInit_(Zc,ver,siz);
	}
	if( rcode != Z_OK ){
		fprintf(stderr,"----createZ1(de=%d)=%X rcode=%d\n",de,p2i(Z1),rcode);
	}
	return Zc;
}
Z1Ctx *deflateZ1new(Z1Ctx *Zc){
	return createZ1(Zc,1);
}
Z1Ctx *inflateZ1new(Z1Ctx *Zc){
	return createZ1(Zc,0);
}
int deflateZ1end(Z1Ctx *Zc){
	XdeflateEnd(Zc);
	free(Zc->z1_Z1);
	return 0;
}
int inflateZ1end(Z1Ctx *Zc){
	XinflateEnd(Zc);
	free(Zc->z1_Z1);
	return 0;
}
int deflateZ1(Z1Ctx *Zc,PCStr(in),int len,PVStr(out),int osz){
	Z64_stream *Z1 = (Z64_stream*)Zc->z1_Z1;
	int rcode;

	Z1->next_in = in;
	Z1->avail_in = len;
	Z1->next_out = (char*)out;
	Z1->avail_out = osz;
	rcode = Xdeflate(Zc,Z_SYNC_FLUSH);
	return Z1->next_out - out;
}
int inflateZ1(Z1Ctx *Zc,PCStr(in),int len,PVStr(out),int osz){
	Z64_stream *Z1 = (Z64_stream*)Zc->z1_Z1;
	int rcode;

	Z1->next_in = in;
	Z1->avail_in = len;
	Z1->next_out = (char*)out;
	Z1->avail_out = osz;
	rcode = Xinflate(Zc,Z_SYNC_FLUSH);
	return Z1->next_out - out;
}
int Zsize(int *asize){
	Z1Ctx eZcb,*eZc = &eZcb;
	Z1Ctx dZcb,*dZc = &dZcb;
	const char *sb = "012345678901234567890123456789";
	IStr(eb,1024);
	IStr(xb,1024);
	int slen,elen,xlen;

	if( gzipInit() < 0 ){
		*asize = 0;
		return 0;
	}
	bzero(eZc,sizeof(Z1Ctx));
	bzero(dZc,sizeof(Z1Ctx));
	deflateZ1new(eZc);
	inflateZ1new(dZc);
	slen = strlen(sb)+1;
	elen = deflateZ1(eZc,sb,slen,AVStr(eb),sizeof(eb));
	xlen = inflateZ1(dZc,eb,elen,AVStr(xb),sizeof(xb));
	inflateZ1end(dZc);
	deflateZ1end(eZc);
	*asize = eZc->z1_asize+dZc->z1_asize;
	return eZc->z1_ssize;
}

int zlib_main(int ac,const char *av[]){
	Z1Ctx eZcb,*eZc = &eZcb;
	Z1Ctx dZcb,*dZc = &dZcb;
	const char *sb = "012345678901234567890123456789";
	IStr(eb,1024);
	IStr(xb,1024);
	int slen,elen,xlen;
	int ssize,asize;

	gzipInit();
	ssize = Zsize(&asize);
	fprintf(stderr,"----Zlib: %s (%d %d)\n",zlibVersion(),ssize,asize);
	bzero(eZc,sizeof(Z1Ctx));
	bzero(dZc,sizeof(Z1Ctx));
	eZc->z1_debug = 1;
	dZc->z1_debug = 1;

	deflateZ1new(eZc);
	if( eZc->z1_ssize == 0 ){
		exit(-1);
	}
	slen = strlen(sb)+1;
	elen = deflateZ1(eZc,sb,slen,AVStr(eb),sizeof(eb));

	inflateZ1new(dZc);
	xlen = inflateZ1(dZc,eb,elen,AVStr(xb),sizeof(xb));
	fprintf(stderr,"----Z: %d => %d => %d [%s]\n",slen,elen,xlen,xb);

	deflateZ1end(eZc);
	inflateZ1end(dZc);
	fprintf(stderr,"----Zlib-deflate-mem: (%d %d %d %d)\n",
		eZc->z1_ssize,eZc->z1_asize,eZc->z1_acnt,eZc->z1_fcnt);
	fprintf(stderr,"----Zlib-inflate-mem: (%d %d %d %d)\n",
		dZc->z1_ssize,dZc->z1_asize,dZc->z1_acnt,dZc->z1_fcnt);
	fprintf(stderr,"----Zlib--mem: (%d %d %d %d)\n",
		dZc->z1_ssize,
		dZc->z1_asize+eZc->z1_asize,
		dZc->z1_acnt+eZc->z1_acnt,
		dZc->z1_fcnt+eZc->z1_fcnt
	);
	return 0;
}

int zlibUncompress(void *in,int isiz,void *out,int osiz){
	int stat;
	int dlen;

	dlen = osiz;
	stat = uncompress((Byte*)out,(uLong*)&dlen,(const Byte*)in,(uLong)isiz);
	if( stat == 0 )
		return dlen;
	else	return -1;
}
