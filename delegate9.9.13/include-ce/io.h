typedef unsigned int *uintptr_t;

//---- open file */
//int open(const char*,int);
//int close(int fd);
//int dup2(int,int);
//int dup(int);
int isatty(int);
int read(int,void*,int);
int write(int,const void*,int);
int tell(int fd);
int chsize(int fd,int size);
#define O_BINARY _O_BINARY

int _open(const char*,int,int);
int _close(int fd);
//int _dup(int);
//int _dup2(int,int);
//int _get_osfhandle(int fd);
int _get_osfhandle_FL(const char *F,int L,int fd);
#define _get_osfhandle(fd) _get_osfhandle_FL(__FILE__,__LINE__,fd)
int _open_osfhandle(int h,int mode);
#define GetHandleInformation(a,b) 0
#define SetHandleInformation(a,b,c) 0

//---- pipe
int _pipe(int[],int,int);
#define PIPE_READMODE_BYTE 0
#define PIPE_NOWAIT 0
#define SetNamedPipeHandleState(p,m,x,y) 0
#define GetNamedPipeHandleState(p,a,b,c,d,e,f) 0
#define PeekNamedPipe(p,a,b,c,d,e) 0

//---- STDIO
void _rmtmp();
void *tmpfile();
void XY_setbuf(void*fp,char*buf);
#define setbuf(fp,buf) XY_setbuf(fp,buf)
extern int Xfileno(void *fp);
#undef fileno
#define fileno(f) Xfileno(f)
int perror(const char*);
void *_fdopen(int,const char*);
void *freopen(const char*,const char*,void*);
int rewind(void*);

#ifndef __FDOPEN
#define __FDOPEN
void *fdopen(int,const char*);
#endif

//---- prpcess
int execlp(const char*,...);
void abort();
int _cwait(int*,int,int);
int _getpid();
void *_popen(char const *,char const *);
int _pclose(void *);

//---- signal
int raise(int sig);
int _sleep(int);

//---- file system
int umask(int mask);
int creat(const char*path,int mod);
int unlink(const char *path);
int rename(const char *on,const char *nn);
int chmod(const char *path,int mod);
int rmdir(const char *dir);
int _mkdir(const char *dir);

#define GetFileType(h) 0
#define FILE_TYPE_PIPE 1
#define FILE_TYPE_CHAR 2
#define HANDLE_FLAG_INHERIT 0

//---- file status
#ifndef __FILE_STAT
#define __FILE_STAT
struct stat {
	int st_dev;
	int st_ino;
	int st_uid;
	int st_gid;
	int st_size;
	int st_mode;
	int st_mtime;
	int st_ctime;
	int st_atime;
	int st_nlink;
};
#define S_IREAD   0x0001
#define S_IWRITE  0x0002
#define S_IEXEC   0x0004
#define S_IFMT    0x00F0
#define S_IFREG   0x0010
#define S_IFDIR   0x0020

#define _stati64 stat
int _fstati64(int fd,struct stat *st);
int _lseeki64(int fd,int off,int wh);
int fstat(int fd,struct stat *st);
#endif

//---- file lock
#define _LK_RLCK   1
#define _LK_NBRLCK 2
#define _LK_LOCK   3
#define _LK_NBLCK  4
#define _LK_UNLCK  5
int locking(int fd,int,int);
/*
#define UnlockFile(oh,offl,offh,lenl,lenh) 0
#define LockFile(oh,offl,offh,lenl,lenh) 0
*/
int LockFile(void *hf,int ol,int oh,int bl,int bh);
int UnlockFile(void *hf,int ol,int oh,int bl,int bh);

//---- console
#define CoCreateInstance(i,a,b,c,d) (HRESULT)0
#define CLSID_ShellLink 0
#define IID_IShellLink 0

//---- time
#ifndef __FTIME
#define __FTIME
#define DosDateTimeToFileTime(ddate,dtime,ftime) 0
struct timeb {
	int time;
	int millitm;
};
int ftime(struct timeb *buf);
#endif

//---- current directory
int chdir(const char *dir);
char *getcwd(char*p,int z);

//---- environment variable
char *getenv(const char *name);
//int putenv(const char*env);
