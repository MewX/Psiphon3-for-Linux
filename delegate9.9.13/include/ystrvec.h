#ifndef _YSTRVEC_H
#define _YSTRVEC_H

typedef struct _StrHead {
	int	sh_magic;
	xMStr(	sh_id,16);
	xMStr(	sh_mode,16);
	defQStr(sh_base);
	int	sh_peak;
	int	sh_maxsize;		/* limit of auto expansion */
	int	sh_size;
} StrHead;
typedef StrHead MemFile;
/*
typedef int MemFile[16];
*/

#ifdef NONEMPTYARRAY
#define sv_idBASE sv_id
#endif
typedef struct _StrVec {
	xMStr(	sv_id,16);
  const	char  **sv_ev;
	int	sv_ec;
	int	sv_ecmax;
	MemFile	sv_MemF;
} StrVec;

void  SVinit(StrVec *Sv,PCStr(what),const char **ev,int ecmax,PVStr(eb),int ebsiz);
char *MemFStr(MemFile *MemF);
char *EnvpStr(StrVec *Evp);

#if defined(FMT_CHECK) /*{*/
#define SVaddEnvf(Envp,fmt,...) (sprintf(EnvpStr(Envp),fmt,##__VA_ARGS__),strtail(EnvpStr(Envp)))
#define SPrintf(MemF,fmt,...)   (sprintf(MemFStr(MemF),fmt,##__VA_ARGS__),strtail(MemFStr(MemF)))
#else
#define FMT_SVaddEnvf SVaddEnvf
#define FMT_SPrintf   SPrintf
char *FMT_SVaddEnvf(StrVec *Evp,PCStr(fmt),...);
char *FMT_SPrintf(MemFile *MemF,PCStr(fmt), ...);
#endif

#endif
