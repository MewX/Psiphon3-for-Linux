#ifndef _FILE_H
#define _FILE_H

#if defined(STAT64) && (defined(QSC) || !defined(__cplusplus))
#define _LARGEFILE64_SOURCE 1
#endif

#include "ystring.h"

#if defined(STAT64) && (defined(QSC) || !defined(__cplusplus))
//#include <features.h>
#define __USE_LARGEFILE64 1
#endif

#include <sys/stat.h>
#ifdef STAT32 /*{*/
typedef struct stat FileStat;
#else /*}{*/
#ifdef STAT64 /*{*/
typedef struct stat64 FileStat;
#define stat(p,b)	stat64(p,b)
#define lstat(p,b)	lstat64(p,b)
#define fstat(d,b)	fstat64(d,b)
#define lseek(f,o,w)	lseek64(f,o,w)
#define ftruncate(F,z)	ftruncate64(F,z)
#else
#ifdef _MSC_VER /*{*/
typedef struct _stati64 FileStat;
__int64 stati64(const char *path,struct _stati64 *buff);
#define stat(p,b)	Xstat(p,b)
#define statX(p,b)	stati64(p,b)
int Xstat(PCStr(path),FileStat *st);
extern __int64 lstati64(const char *p,struct _stati64 *b);
#define lstat(p,b)	lstati64(p,b)
#define fstat(d,b)	_fstati64(d,b)
#define lseek(f,o,w)	_lseeki64(f,o,w)
#else /*}{*/
typedef struct stat FileStat;
#endif /*}*/
#endif /*}*/
#endif /*}*/

static int Istat(const char *p,FileStat *b){
	return stat(p,b);
}
#undef stat
#define stat(p,b)	statXX(p,b)
int statXX(const char *p,FileStat *b);
/* hooking stat() to monitor the attributes of system files */

typedef struct { int b[4]; } Fpos_t;
int Fgetpos(FILE *fp,Fpos_t *pos);
int Fsetpos(FILE *fp,Fpos_t *pos);
int Fseeko(FILE *fp,FileSize off,int whence);
FileSize Ftello(FILE *fp);

void setBinaryIO();
int valid_fdl(PVStr(vfd));
/*
int dupclosed(int fd);
*/
int dupclosed_FL(FL_PAR,int fd);
#define dupclosed(fd) dupclosed_FL(FL_ARG,fd)
int fd2handle(int fd);

FILE *TMPFILE(PCStr(what));
FILE *TMPFILEX(PVStr(path));
FILE *NULLFP();
FILE *WRNULLFP();
int   openNull(int rw);
void  freeTmpFile(PCStr(what));
FILE *getTmpFile(PCStr(what));
const char *getTMPDIR();
FILE *reusableTMPFILE(PCStr(what),iFUNCP where);


typedef int (*scanDirCallP)(PCStr(elem),...);
#define scanDirFunc int
#define scanDirCall (scanDirCallP)
int   Scandir(PCStr(dirpath),scanDirCallP,...);

int   Ftruncate(FILE *fp,FileSize offset,int whence);
char *FileModes(int);
void  setTMPDIR(PCStr(dir));
int   fcompare(FILE *fp1,FILE *fp2);

int file_is(int fd);
int file_isreg(int);
int file_isfifo(int fd);
int file_issock(int fd);
int file_ISSOCK(int fd);
int file_isSOCKET(int fd);
int file_stat(int fd,int *sizep,int *mtimep,int *atimep);
int file_atime(int fd);
int file_mtime(int fd);
int file_size(int);
FileSize file_sizeX(int);
int file_uid(int fd);
int file_gid(int fd);
int file_ino(int fd);
int file_mod(int fd);
int file_cmp(int fd1,int fd2);
int file_nlink(int fd);
int file_timeoff(int fd,int created_now);

int fileIsdir(PCStr(path));
int fileIsflat(PCStr(path));
int File_is(PCStr(path));
int File_isreg(PCStr(path));
int File_stats(PCStr(path),int,int*,int*,int*,int*,int*);
int File_stat(PCStr(path),FileSize *size,int *time,int *isdir);
int File_sizetime(PCStr(path),int *fsize,int *ctime,int *mtime,int *atime);
int File_mtime(PCStr(path));
int File_ctime(PCStr(path));
int File_size(PCStr(path));
FileSize File_sizeX(PCStr(path));
int File_copymod(PCStr(src),PCStr(dst));
int File_mod(PCStr(path));
int File_cmp(PCStr(path1),PCStr(path2));
int File_ino(PCStr(path));
int File_uid(PCStr(path));
int File_gid(PCStr(path));

int isBoundpath(PCStr(path));
int isFullpath(PCStr(path));
int access_RWX(PCStr(path));

void setOWNER(PCStr(dir),int uid,int gid);
int  set_utimes(PCStr(path),int atime,int mtime);
int  set_futimes(int fd,int atime,int mtime);
void File_touch(PCStr(path),int clock);
void ftouch(FILE *fp,int time);
int file_touch(int fd);

int lock_exclusiveNB(int fd);
int lock_exclusiveTO(int fd,int timeout,int *elapsedp);
int lock_exclusive(int fd);
int lock_sharedNB(int fd);
int lock_sharedTO(int fd,int timeout,int *elapsedp);
int lock_shared(int fd);
int lock_unlock(int fd);

FILE *fopenShared(PCStr(path),PCStr(mode));
void  chmodShared(PCStr(path));
int   chmodIfShared(PCStr(path),int);
int   mkdirShared(PCStr(dir),int mode);
int   setSHARE(PCStr(pathpat));

int   Fwrite(PCStr(buf),int esize,int ecount,FILE *fp);
char *Fgets(PVStr(buf),int size,FILE *fp);
int   Fputs(PCStr(str),FILE *fp);
char *freadfile(FILE *fp,int *sizep);
FileSize copyfile1(FILE*,FILE*);

/*
int RecvPeek(int sock,void *buf,int len);
*/
int RecvPeek_FL(int sock,void *buf,int len,FL_PAR);
#define RecvPeek(s,b,l) RecvPeek_FL(s,b,l,FL_ARG)
int reads(int fd,PVStr(buf),int len);
int readsTO(int fd,PVStr(buf),int len,int timeout);

int   FullpathOfExe(PVStr(path));
void  path_escchar(PVStr(path));
FILE *fopen_PATH(const char *pathv[],PCStr(file),PCStr(mode),PVStr(xpath));
FILE *fopen_PATHX(const char *pathv[],PCStr(file),PCStr(mode),int ftype,PVStr(xpath));
#define FTY_ANY	0xFFFFFFFF
#define FTY_REG	1
#define FTY_DIR	2
FILE *fopen_LIBPATH(PCStr(file),PCStr(mode),PVStr(xpath));
const char **vect_PATH(PCStr(path));
void  chdir_cwd(PVStr(cwd),PCStr(go),int userdir);
#define CHDIR_USEDIR	1
#define CHDIR_NODOSPATH	2

typedef FileStat *StP;
void dir2ls(PCStr(dirpath),StP stp,PCStr(opt),xPVStr(fmt),FILE *fp);
FILE *ls_unix(FILE *fp,PCStr(opt),PVStr(fmt),PCStr(dir),StP stp);

#endif /* _FILE_H */
