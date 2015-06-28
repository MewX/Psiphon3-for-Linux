#ifndef _YSTRING_H
#define _YSTRING_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#define MaxHostNameLen	256

extern int isWindows95();
#ifdef _MSC_VER
#include "ywinsock.h"
#define isWindows()	1
#define MSCver() _MSC_VER
#define Foff_t __int64
#define Int64 __int64
#else
#define isWindows()	0
#define MSCver() 0
#define Foff_t long long int
#define Int64 long long int
#endif

#ifdef __CYGWIN__
#define isCYGWIN()	1
#else
#define isCYGWIN()	0
#endif

#ifdef SIZE32
typedef int FileSize;
#else
typedef Foff_t FileSize;
#endif

#define sizeof(x)	sizeof(x)

#ifndef NULL
#define NULL 0L
#endif

typedef const char CChar;
typedef const char *ROStr;

#define elnumof(a)	((int)(sizeof(a)/sizeof(a[0])))

static char *rawfgets(char *buf,int siz,FILE *fp){
	return fgets(buf,siz,fp);
}

#if defined(QVSTR) || defined(QS) || defined(QSS) || defined(QSX) || defined(QSC)
#define WITH_QVSTR 1

extern char VStrUNKNOWN[];
#define PCStr(s)    const char *s
#define STail(s)    &((char*)s)[sizeof(s)-1]

#if defined(__cplusplus) && !defined(QSS) || defined(QSX) || defined(QSC)
/*if(Q2){*/
#define _CAT(a,b)    a ## b
#if defined(QSC) /*{*/
#define _SIZEOF(s)  ((int)((const char*)_CAT(s,NEXT)-(const char*)_CAT(s,BASE)))
#define VStrSIZQ(s) ((const char*)_CAT(s,NEXT)) /* size quantifier, SIZE or NEXT */
#define VStrSIZE(s) _SIZEOF(s)
#define PVTag(s)    const char *s##FILE,int s##LINE,const char *s##BASE,const char *s##NEXT
#define PVStr(s)    PVTag(s),const char*const s
#define PRVStr(r)   PVTag(r),const char**const r
#define xPVStr(s)   PVTag(s),const char*s
#define UTail(b)    &b##BASE[_SIZEOF(b)-1]
#define whStr(s)    s##FILE,s##LINE
#define UVStr(s)    s##FILE,s##LINE,s##BASE,s##NEXT,
#else /*}{*/
#define _SIZEOF(s)  _CAT(s,SIZE)
#define VStrSIZQ(s) _SIZEOF(s)
#define VStrSIZE(s) _SIZEOF(s)
#define PVTag(s)    const char *s##FILE,int s##LINE,const char *s##BASE,int s##SIZE
#define PVStr(s)    PVTag(s),const char*const s
#define PRVStr(r)   PVTag(r),const char**const r
#define xPVStr(s)   PVTag(s),const char*s
#define UTail(b)    &b##BASE[b##SIZE-1]
#define whStr(s)    s##FILE,s##LINE
#define UVStr(s)    s##FILE,s##LINE,s##BASE,s##SIZE,
#endif /*}*/

/*
#define _HERE_      __FILE__,__LINE__,__func__
*/
#define _HERE_      __FILE__,__LINE__

#if defined(QSC) /*{*/
#define TVSTR(t)    _HERE_,(const char*)_CAT(t,BASE),VStrSIZQ(t),
#define SVStr(s,b)  _HERE_,s==b?b:s,s==b?VStrSIZQ(b):VStrSIZQ(s),
#define ZVStr(s,z)  _HERE_,s,((const char*)s+(z)),s
#define LVStr(m)    _HERE_,(char*)m,(const char*)_CAT(m,NEXT),(char*)m
#define MVStrSiz(m) _HERE_,(char*)m,(const char*)_CAT(m,NEXT),(char*)m,sizeof(m)
#define NVStr(m)    _HERE_,m,(const char*)_CAT(m,NEXT),
#define setPStr(p,b,z)	(p = b),p##BASE=b,p##NEXT=b+z,p##LINE=__LINE__,p##FILE=__FILE__
#define defQStr(n)	const char *n;const char*n##BASE;const char *n##NEXT
#define refQStr(n,p)	const char *n=p;const char*n##BASE=_CAT(p,BASE);const char *n##NEXT=(const char*)_CAT(p,NEXT)
#define UrefQStr(n,p)	const unsigned char *n=(const unsigned char*)p;const unsigned char*n##BASE=(const unsigned char*)_CAT(p,BASE);const char *n##NEXT=_CAT(p,NEXT)
#define MrefQStr(n,b)	const char *n=b;const char*n##BASE=n;const char *n##NEXT=(const char*)_CAT(b,NEXT)
#define setQStr(n,p,z)	(n = (char*)p),(_CAT(n,BASE)=n),(_CAT(n,NEXT)=n+z),n
#define McpyQStr(n,p)	(n = (char*)p),(_CAT(n,BASE)=n),(_CAT(n,NEXT)=(const char*)_CAT(p,NEXT)),n
#define cpyQStr(n,p)	(n = (char*)p),(_CAT(n,BASE)=_CAT(p,BASE)),(_CAT(n,NEXT)=_CAT(p,NEXT)),n
#define UcpyQStr(n,p)	(n = (unsigned char*)p),(_CAT(n,BASE)=(unsigned char*)_CAT(p,BASE)),(_CAT(n,NEXT)=_CAT(p,NEXT)),n
#else /*}{*/
#define TVSTR(t)    _HERE_,(const char*)_CAT(t,BASE),_CAT(t,SIZE),
#define SVStr(s,b)  _HERE_,s==b?b:s,s==b?b##SIZE:s##SIZE,
#define ZVStr(s,z)  _HERE_,s,z,s
#define LVStr(m)    _HERE_,(char*)m,_CAT(m,SIZE),(char*)m
#define MVStrSiz(m) _HERE_,(char*)m,_CAT(m,MSIZE),(char*)m,sizeof(m)
#define NVStr(m)    _HERE_,m,_CAT(m,MSIZE),
#define setPStr(p,b,z)	(p = b),p##BASE=b,p##SIZE=z,p##LINE=__LINE__,p##FILE=__FILE__
#define defQStr(n)	const char *n;const char*n##BASE;int n##SIZE
#define refQStr(n,p)	const char *n=p;const char*n##BASE=_CAT(p,BASE);int n##SIZE=_CAT(p,SIZE)
#define UrefQStr(n,p)	const unsigned char *n=(const unsigned char*)p;const unsigned char*n##BASE=(const unsigned char*)_CAT(p,BASE);int n##SIZE=_CAT(p,SIZE)
#define MrefQStr(n,b)	const char *n=b;const char*n##BASE=n;int n##SIZE=_CAT(b,MSIZE)
#define setQStr(n,p,z)	(n = (char*)p),(_CAT(n,BASE)=n),(_CAT(n,SIZE)=z),n
#define McpyQStr(n,p)	(n = (char*)p),(_CAT(n,BASE)=n),(_CAT(n,SIZE)=_CAT(p,SIZE)),n
#define cpyQStr(n,p)	(n = (char*)p),(_CAT(n,BASE)=_CAT(p,BASE)),(_CAT(n,SIZE)=_CAT(p,SIZE)),n
#define UcpyQStr(n,p)	(n = (unsigned char*)p),(_CAT(n,BASE)=(unsigned char*)_CAT(p,BASE)),(_CAT(n,SIZE)=_CAT(p,SIZE)),n
#endif /*}*/

typedef struct {
  const	char   *qFILE;
	int	qLINE;
  const	char   *qBASE;
#if defined(QSC)
  const char   *qNEXT;
#else
	int	qSIZE;
#endif
	char   *q;
} QPtr;
#if defined(QSC)
#define cpyQPtr(d,s)	(d.qFILE = s##FILE),(d.qLINE = s##LINE),(d.qBASE = s##BASE),(d.qNEXT = s##NEXT),(d.q = (char*)s)
#else
#define cpyQPtr(d,s)	(d.qFILE = s##FILE),(d.qLINE = s##LINE),(d.qBASE = s##BASE),(d.qSIZE = s##SIZE),(d.q = (char*)s)
#endif

#endif /*}*/

const char *XcheckPtr(PVStr(t),const char *s);
#define QVStr(s,t)  TVSTR(t) (const char*)s
#define QRVStr(r,t) TVSTR(t) (const char **)&r
#define AVStr(s)    QVStr(s,s)
#define BVStr(s)    UVStr(s) s
#define EVStr(s)    ZVStr(s,sizeof(s))
#define FVStr(s)    ZVStr((char*)s,sizeof(s))
#define GVStr(s)    ZVStr((char*)s,sizeof(*(s)))
#define CVStr(s)    ZVStr(s,0)
#define DVStr(s,d)  QVStr(XcheckPtr(AVStr(s),(char*)s+d),s)
#define TVStr(s)    QVStr(s+strlen(s),s)

int Xassert(PVStr(b),PCStr(p));
#define assertVStr(b,p)	{ if(b && UTail(b) < p){ Xassert(AVStr(b),p); break; } }
#define alertVStr(b,z)	{ if(b && UTail(b) < b+z-1){ Xassert(BVStr(b),b+z-1);} }

int XQVSSize(PVStr(d),int z);
#define QVSSize(d,z)	XQVSSize(AVStr(d),z)
#define QVZsizeof(d)	XQVSSize(AVStr(d),sizeof(d)-1)

void VStr_overflow(PCStr(where),PVStr(d),int l,int z,PCStr(fmt),...);
char *VStrId(PVStr(wh),PVStr(vs));
void Xwhatis(PVStr(s));
char *Xstrcpy(PVStr(d),PCStr(s));
void *Xmemmove(PVStr(d),PCStr(s),int z);
char *Xstrncpy(PVStr(d),PCStr(s),int z);
char *Xstrcat(PVStr(d),PCStr(s));
#undef strcpy
#define strcpy(d,s)	Xstrcpy(TVSTR(d) d,s)
#define memmove(d,s,z)	Xmemmove(TVSTR(d) d,s,z)
#define Xovstrcpy(d,s)	Xstrcpy(d,s)
#undef strncpy
#define strncpy(d,s,z)	Xstrncpy(TVSTR(d) d,s,z)
#define strcat(d,s)	Xstrcat(TVSTR(d) d,s)
int Xsscanf(PCStr(str),PCStr(fmt),...);
int XsetVStrEnd(PVStr(p),int x);

#if defined(QSC)
#define rangeOK(p,x)          (0<VStrSIZE(p) && _CAT(p,BASE)<=&p[x] && &p[x]<=UTail(p))
#else
#define rangeOK(p,x) (0<_CAT(p,SIZE) && _CAT(p,BASE)<=&p[x] && &p[x]<=UTail(p))
#endif
#define setVStrEnd(p,x)	      (rangeOK(p,x))?(((char*)p)[x] = 0):XsetVStrEnd(AVStr(p),x)
#define setVStrElem(p,x,v)    (rangeOK(p,x))?(((char*)p)[x] = v):XsetVStrEnd(AVStr(p),x)
#define setVStrElemInc(p,x,v) (rangeOK(p,x))?(((char*)p)[x++]=v):XsetVStrEnd(AVStr(p),x)
#define setVStrPtrInc(p,v)    (rangeOK(p,0))?(*((char*)p++) = v):XsetVStrEnd(AVStr(p),0)

char *Xfgets(PVStr(b),int z,FILE *f);
#define fgets(b,z,f)	Xfgets(AVStr(b),z,f)
void Xbcopy(const void *s,PVStr(d),int z);
#define Bcopy(s,d,z)	Xbcopy(s,AVStr(d),z)
char *XStrncpy(PVStr(d),PCStr(s),int len);
#define QStrncpy(d,s,z)	XStrncpy(AVStr(d),s,z)
#define FStrncpy(d,s)	XStrncpy(LVStr(d),s,sizeof(d))

typedef struct {
	char *tp; /* tail */
	char *sp; /* top */
} QSP;
#define qStr(s,t) QSP s = {XVStr(t)}
#define pStr(s)   QSP *s

#define AStr(s)   s->sp
#define BStr(s)   s.sp


#else /* ---- without QVSTR ---- */

typedef struct {
	char   *q;
} QPtr;
#define cpyQPtr(d,s)	(d.q = s)

#define VStrSIZE(s) sizeof(s)
#define PCStr(s) const char *s
#define PVStr(s) char *s
#define PRVStr(r) char **r
#define xPVStr(s) char *s
#define UTail(t) t
#define TVSTR(t)
#define UVStr(t)
#define whStr(s) "",0
#define QVStr(s,t) s
#define QRVStr(r,t) &r
#define SVStr(s,b)
#define AVStr(s) s
#define BVStr(s) s
#define ZVStr(s,z) s
#define FVStr(s) s
#define EVStr(s) s
#define CVStr(s) (char*)s
#define DVStr(s,d) s+d
#define TVStr(s) s+strlen(s)
#define GVStr(s) (char*)s
#define MVStrSiz(s) s,sizeof(s)
#define NVStr(m)
#define VStrId(wh,vs) ""

#define assertVStr(b,p)
#define Xassert(b,p)
#define alertVStr(b,z)
#define QVSSize(d,z) z
#define QVZsizeof(d) (sizeof(d)-1)

#define setPStr(p,b,z)	(p = b)
#define defQStr(name)	char *name
#define refQStr(n,p)	char *n = p
#define UrefQStr(n,p)	unsigned char *n = (unsigned char*)p
#define MrefQStr(n,b)	char *n = b
#define setQStr(n,p,z)	(n = p)
#define McpyQStr(n,p)	(n = p)
#define cpyQStr(n,p)	(n = p)
#define UcpyQStr(n,p)	(n = (unsigned char*)p)

#define Xstrcpy strcpy
#define Xovstrcpy ovstrcpy
#define Xstrncpy strncpy
#define Xstrcat strcat
/*
#define Xsprintf sprintf
#define Xsscanf sscanf
*/
int Ysprintf(char *str,const char *fmt,...);
#define Xsprintf Ysprintf
int Ysscanf(const char *str,const char *fmt,...);
#define Xsscanf Ysscanf

#define Rsprintf XRsprintf
#define setVStrEnd(p,x)	p[x] = 0
#define setVStrElem(p,x,v) p[x] = v
#define setVStrElemInc(p,x,v) p[x++] = v
#define setVStrPtrInc(p,v) *p++ = v
#define XsetVStrEnd setVStrEnd
#define Xfgets fgets
#define Xfread fread
#define Xmemmove memmove
#define Bcopy bcopy
#define Xbcopy bcopy
#define QStrncpy Strncpy
#define XStrncpy Strncpy
#define FStrncpy(d,s)	Strncpy(d,s,sizeof(d))

#define qStr(s,t) char *s
#define pStr(s)   char *s
#define AStr(s)   s
#define BStr(s)   s

#endif /* ---- end QVSTR ---- */

#define VStrNULL	ZVStr(((char*)NULL),0)
#define truncVStr(p)	*(char*)p = 0
#define clearVStr(p)	setVStrEnd(p,0);
#define QVSize(p)	p

#define tty_fgets(s,z,f) (isatty(0)&&isatty(1) ? fgets(s,z,f) : NULL)
#define fieldScan(f,n,v) scan_field1(f,AVStr(n),sizeof(n),AVStr(v),sizeof(v))
#define wordScanY(s,w,b) wordscanY(s,AVStr(w),sizeof(w),b)
#define wordScan(s,w)	wordscanX(s,AVStr(w),sizeof(w))
#define lineScan(s,l)	linescanX(s,AVStr(l),sizeof(l))
#define textScan(s,l)	wordscanY(s,AVStr(l),sizeof(l),"^\r\n")

int modifyFmt(PCStr(fmt),PVStr(xfmt),int xsiz);
  
extern int FGSZ_flags;
#define FGSZ_ISSET	1
#define FGSZ_NONE	2
#define FGSZ_KILL	4
#define FGSZ_UTF8	8

#ifdef DOFGSZ
#undef fgets
#undef fputs
const char *fgetsZ(PVStr(str),int siz,FILE *fp);
int fputsZ(PCStr(str),FILE *fp);
#define fgets(s,z,f)	fgetsZ(AVStr(s),z,f)
#define fputs(s,f)	fputsZ(s,f)
#endif

/*
#ifdef __cplusplus
class CString {
private:
	int len;
	char *buf;
public:
	CString(int siz){ len = siz; buf = new char[siz]; }
};
#define CStr(name,size)	CString name(size)
#else
#define CStr(name,size)	char name[size]
#endif
*/

#if defined(QC) && !defined(_MSC_VER) && !defined(NONC99)
#define QVCONST	const
#else
#define QVCONST
#endif

#ifndef ASIZ0
#if defined(NONAZ0)
#define ASIZ0
#else
#define ASIZ0 0
#endif
#endif

#ifdef WITH_QVSTR /*{*/
#if defined(QSC) /*{*/
#define SStr(n,z)	char n[z];static const char *n##NEXT=((const char*)n+z)
#define CStr(nam,z)	char nam[z];const char*nam##BASE=(const char*)nam;const char *nam##NEXT=(const char *)nam+z
#define UCStr(nam,z)	unsigned char nam[z];const unsigned char*nam##BASE=(const unsigned char*)nam;const char *nam##NEXT=(const char*)nam+z
#define UJStr(nam,z)	QVCONST unsigned char nam[z]={0};const unsigned char*nam##BASE=(const unsigned char*)nam;const unsigned char *nam##NEXT=(const unsigned char*)nam+z
#define IStr(nam,z)	QVCONST char nam[z]={0};const char*nam##BASE=(const char*)nam;const char *nam##NEXT=(const char*)nam+z
#define JStr(nam,z)	IStr(nam,z)
#define ACStr(nam,n,z)	char nam[n][z];const char *nam##NEXT=(const char*)nam+n*z
#define NStr(n,z)	char n[z];char n##NEXT[ASIZ0]
#define MStr(n,z)	char n##BASE[ASIZ0];NStr(n,z)
#else /*}{*/
#if defined(__cplusplus) && !defined(QSS) || defined(QSX) /*{*/
#define SStr(n,z)	char n[z];enum{n##SIZE=z,n##MSIZE=z}
#define CStr(nam,z)	char nam[z];const char*nam##BASE=(const char*)nam;enum{nam##SIZE=z}
#define UCStr(nam,z)	unsigned char nam[z];const unsigned char*nam##BASE=(const unsigned char*)nam;enum{nam##SIZE=z}
#define UJStr(nam,z)	QVCONST unsigned char nam[z]={0};const unsigned char*nam##BASE=(const unsigned char*)nam;enum{nam##SIZE=z}
#define IStr(nam,z)	QVCONST char nam[z]={0};const char*nam##BASE=(const char*)nam;enum{nam##SIZE=z}
#define JStr(nam,z)	IStr(nam,z)
#define ACStr(nam,n,z)	char nam[n][z];enum{nam##SIZE=n*z}
#define NStr(n,z)	char n[z];enum{n##SIZE=z,n##MSIZE=z}
#define MStr(n,z)	char n##BASE[0];NStr(n,z)
#else /*}{*/
#define SStr(nam,z)	char nam[z]
#define CStr(nam,z)	char nam[z]
#define UCStr(nam,z)	unsigned char nam[z]
#define UJStr(nam,z)	unsigned char nam[z]
#define IStr(nam,z)	char nam[z]={0}
#define JStr(nam,z)	CStr(nam,z)
#define ACStr(nam,n,z)	char nam[n][z]
#define NStr(nam,z)	char nam[z]
#define MStr(nam,z)	char nam[z]
#endif /*}*/
#endif /*}*/
#define AMStr(nam,n,z)	char nam[n][z]

#else /*}{*/
#define CStr(nam,z)	char nam[z]
#define UCStr(nam,z)	unsigned char nam[z]
#define UJStr(nam,z)	unsigned char nam[z]
#define IStr(nam,z)	char nam[z]={0}
#define JStr(nam,z)	CStr(nam,z)
#define ACStr(nam,n,z)	char nam[n][z]
#define NStr(nam,z)	char nam[z]
#define MStr(nam,z)	char nam[z]
#define AMStr(nam,n,z)	char nam[n][z]
#define SStr(nam,z)	char nam[z]
#endif /*}*/

#if defined(_MSC_VER) || defined(NONC99)
#define NONEMPTYARRAY
#define xMStr(n,z)	NStr(n,z)
#else
#define xMStr(n,z)	MStr(n,z)
#endif

int usedFDX(PCStr(F),int L,int fd);
int nextFDX(PCStr(F),int L);
#define nextFD()	nextFDX(__FILE__,__LINE__)
#define usedFD(fd)	usedFDX(__FILE__,__LINE__,fd)

int   streq(PCStr(s1),PCStr(s2));
int   strneq(PCStr(s1),PCStr(s2),int);
int   strcaseeq(PCStr(s1),PCStr(s2));
int   strcasseq(PCStr(s1),PCStr(s2));
int   strncaseeq(PCStr(s1),PCStr(s2),int);
const char *strheadstrX(PCStr(str1),PCStr(str2),int igncase);
int   strtailchr(PCStr(str));
int   isdigits(PCStr(str));
int   isdigit2(PCStr(str));
const char *Isnumber(PCStr(str));
char *strtail(PCStr(str));
char *strrpbrk(PCStr(str),PCStr(brk));
char *strtailstr(PCStr(str),PCStr(ss));
char *strtailstrX(PCStr(str),PCStr(ss),int igncase);
char *strchrX(PCStr(str),int fch,PCStr(inc),PCStr(dec));

#if !defined(__KURO_BOX__)
char *Strcasestr(PCStr(str),PCStr(ss));
#define strcasestr(s,t) Strcasestr(s,t)
#endif

char *strcats3(PVStr(dst),PCStr(s0),PCStr(s1),PCStr(s2));
void  strreverse(PCStr(str));
void  strsubst(PVStr(str),PCStr(pat),PCStr(subs));
char *sgetsX(PCStr(src),PVStr(line),int cr,int lf);
char *linescanX(PCStr(str),PVStr(line),int);
char *paramscanX(PCStr(src),PCStr(brk),PVStr(dst),int size);
char *wordscanX(PCStr(str),PVStr(word),int);
char *wordscanY(PCStr(str),PVStr(word),int,PCStr(brk));
char *valuescanX(PCStr(str),PVStr(val),int);
char *valuescanY(PCStr(str),PVStr(val),int);
const char *awordscanX(PCStr(str),PVStr(word),int size);
void  scanwords(PCStr(sp),int wc,const char *words[]);
int   numscan(const char **spp);
char *numscanX(PCStr(str),PVStr(val),int siz);
const char *scanint(PCStr(str),int *valp);
void  scan_field1(PCStr(field),PVStr(name),int nsiz,PVStr(body),int bsiz);
int   scan_namebody(PCStr(namebody),PVStr(name),int nsiz,PCStr(nbrk),PVStr(body),int bsiz,PCStr(bbrk));

#define awordscan(s,w)   awordscanX(s,AVStr(w),sizeof(w))
#define majorminorScan(s,j,n) scan_namebody(s,AVStr(j),sizeof(j),"/",AVStr(n),sizeof(n),NULL)


int   del8bits(PVStr(dst),PCStr(src));
char *strip_spaces(PCStr(value));
FileSize kmxatoi(PCStr(ai));
char *strtolowerX(PCStr(s1),PVStr(s2),int siz);
char *strtoupperX(PCStr(s1),PVStr(s2),int siz);
#define strtolower(s1,s2) strtolowerX(s1,AVStr(s2),sizeof(s2))
#define strtoupper(s1,s2) strtoupperX(s1,AVStr(s2),sizeof(s2))
int strtoHexX(PCStr(str),int len,PVStr(out),int siz,PCStr(opts));

/*
#define FStrncpy(d,s)	Strncpy(d,s,sizeof(d))
*/
char *Strncpy(char d[],PCStr(s),int len);

char *strncpy0(PVStr(d),PCStr(s),int len);
void  Strins(PVStr(d),PCStr(s));
void  Strrplc(PVStr(d),int len,PCStr(s));

void  strdelchr(PCStr(src),PVStr(dst),PCStr(del));
void  reverseDomainX(PCStr(dom),PVStr(rdom),int dlm,PCStr(sep));
void  reverseDomain(PCStr(dom),PVStr(rdom));


#ifdef NONEMPTYARRAY
#define sh_idBASE sh_id
#define sh_modeBASE sh_mode
#endif

typedef struct {
	char	ut_strg;
	char	ut_dmmy;
	short	ut_type;
	int	ut_size;
	int	ut_leng;
	defQStr(ut_addr); /* to be used by AVStr() */
} UTag;
#define Utos(u,s)	utosX(u,AVStr(s),sizeof(s))

void  uvinit(UTag *tagv[],UTag tagvb[],int nelem);
int   uvtosf(PVStr(str),int siz,PCStr(fmt),UTag *tagv[]);
int   ufromsf(PCStr(str),int siz,PCStr(fmt),UTag *tagp);
int   uvfromsf(PCStr(str),int siz,PCStr(fmt),UTag *tagv[]);
int   uvfromsfX(PCStr(str),int siz,PCStr(fmt),UTag *tagv[],const char **rsp,const char **rfp);
void  uvfmtreverse(PCStr(src),PCStr(dst),const char **rsrc,const char **rdst);
int   utosX(UTag *tag,PVStr(str),int siz);
int   utoi(UTag *tag);
int   stoV(PCStr(abuf),int mac,const char *av[],int sep);
int   stoVX(PCStr(abuf),int mac,const char *av[],int sep,int depth);
int   ustrcmp(UTag *tag,PCStr(str));

#ifndef _FL_PAR_
#define _FL_PAR_
#define FL_PAR   const char *FL_F,int FL_L
#define FL_PAR_P FL_PAR,int pstm
#define FL_BAR   FL_F,FL_L
#define FL_BAR_P FL_BAR,pstm
#define FL_BAR_r FL_BAR,1
#define FL_BAR_s FL_BAR,0
#define FL_ARG   __FILE__,__LINE__
#define FL_ARG_r FL_ARG,1 /* resident */
#define FL_ARG_s FL_ARG,0 /* stacked */
#endif

/*
UTag  UTalloc(int lev,int size,int algn);
void  UTfree(UTag *up);
void  UTclear(UTag *up);
char *stralloc(PCStr(str));
void  strfree(void *str);
char *StrAlloc(PCStr(str));
*/
UTag  UTalloc_FL(FL_PAR, int lev,int size,int algn);
#define UTalloc(l,z,a) UTalloc_FL(FL_ARG, l,z,a)
void  UTfree_FL(FL_PAR, UTag *up);
#define UTfree(u) UTfree_FL(FL_ARG, u)
void  UTclear_FL(FL_PAR, UTag *up);
#define UTclear(u) UTclear_FL(FL_ARG, u)
char *stralloc_FL(FL_PAR_P, PCStr(str));
#define stralloc(str) stralloc_FL(FL_ARG, 0,str)
void  strfree_FL(FL_PAR, void *str);
#define strfree(str) strfree_FL(FL_ARG, str)
char *StrAlloc_FL(FL_PAR, PCStr(str));
#define StrAlloc(str) StrAlloc_FL(FL_ARG, str)

char *StrBufAlloc();
int  *StructAlloc(int);
#define NewStruct(t)	(t*)StructAlloc(sizeof(t))
const char *strid_alloc(PCStr(str));


char *getStrBuffer(int lev,int size,int al);
void *addStrBuffer_FL(FL_PAR_P, int lev,void *buff,int size);
#define addStrBuffer(l,b,z) addStrBuffer_FL(FL_ARG_s, l,b,z)

void  freeStrBuffer(int lev,void *bp);
void  delStrBuffer(int lev);

#define SB_STAT	0 /* static environment */
#define SB_PROC	1
#define SB_CONN	2
#define SB_SERV	3 /* environment for each request */
#define SB_HEAP 4 /* malloc() */


char *Strdup_FL(FL_PAR, char **dst,PCStr(src));
#define Strdup(dst,src) Strdup_FL(FL_ARG, dst,src)

const char **Xdupv(FL_PAR_P, const char *const*sv,int length);
#if defined(QSC)
#define dupv(v,l)         Xdupv(FL_ARG_r,(const char*const*)v,l)
#define STKM_dupv(v,l)    Xdupv(FL_ARG_s,(const char*const*)v,l)
#else
#define dupv(v,l)         Xdupv(FL_ARG_r,v,l)
#define STKM_dupv(v,l)    Xdupv(FL_ARG_s,v,l)
#endif
void  freev(char *sv[]);
int   cmpv(const char *v1[],const char *v2[],int len);
char **Dupv_FL(FL_PAR_P,const char *const ev[]);
#define Dupv(ev)          Dupv_FL(FL_ARG_r,ev)
#define STKM_Dupv(ev)     Dupv_FL(FL_ARG_s,ev)

char *MallocX(FL_PAR, void *ptr,int size);
#define Malloc(p,z)	MallocX(FL_ARG, p,z)
void markStackBase(void *mp);
#define PSTM_malloc(z)    Xmalloc(FL_ARG_r,z)
#define PSTM_calloc(n,z)  Xcalloc(FL_ARG_r,n,z)
#define PSTM_realloc(p,z) Xrealloc(FL_ARG_r,p,z)
#define PSTM_stralloc(s)  stralloc_FL(FL_ARG_r,s)

const char *getMainArg(PCStr(where),PCStr(name));

/*
#include "yarg.h"
*/
#ifndef _YARG_H
#define _YARG_H
typedef int (*iFUNCP)(const void*,...);
typedef int (*IFUNCP)(void*,...);
typedef void (*vFUNCP)(void*,...);
typedef char *(*sFUNCP)(void*,...);
#include <stdarg.h>
#define VARGS(ac,a0) \
	char *va[ac]; va_list ap; va_start(ap,a0); \
	{ int ai; for(ai = 0; ai < ac; ai++) va[ai] = va_arg(ap,char*); }
#define VA4	va[0],va[1],va[2],va[3]
#define VA8	va[0],va[1],va[2],va[3],va[4],va[5],va[6],va[7]
#define VA14    va[0],va[1],va[2],va[3],\
                va[4],va[5],va[6],va[7],\
                va[8],va[9],va[10],va[11],va[12],va[13]
#define VA16    va[0],va[1],va[2],va[3],\
                va[4],va[5],va[6],va[7],\
                va[8],va[9],va[10],va[11],\
		va[12],va[13],va[14],va[15]
#endif /* _YARG_H */

int Setproctitle(const char *fmt,...);

/*-- SCANNING LIST */
#define STR_VOLA  0
#define STR_ALLOC 1
#define STR_OVWR  2
#define STR_RO    4
#define STR_QUOTE 0x8000 /* ignore ",{}" */

typedef int (*scanListFuncP)(PCStr(elem),...);
#define scanListFunc int
#define scanListCall (scanListFuncP)

int   scan_List(PCStr(list),int sep,int allocm,scanListFuncP func, ...);
int   scan_ListL(PCStr(list),int,int,scanListFuncP,...);
int   scan_commaList(PCStr(list),int,scanListFuncP,...);
int   scan_commaListL(PCStr(list),int,scanListFuncP,...);

int   scanv(const char *av[],PCStr(name),iFUNCP func,void *arg1);
int   isinList(PCStr(list),PCStr(word));
int   isinListX(PCStr(list),PCStr(word),PCStr(sopts));
int   wordIsinList(PCStr(list),PCStr(word));
int   scan_Listlist(PCStr(list),int sep,PVStr(a),PVStr(b),PVStr(c),PVStr(d),PVStr(e));
#define scan_Listlist3(l,s,a,b,c) scan_Listlist(l,s,a,b,c,VStrNULL,VStrNULL)
#define scan_Listlist4(l,s,a,b,c,d) scan_Listlist(l,s,a,b,c,d,VStrNULL)
#define scan_Lists3(l,s,a,b,c) scan_Listlist(l,s,AVStr(a),AVStr(b),AVStr(c),VStrNULL,VStrNULL)
#define scan_Lists4(l,s,a,b,c,d) scan_Listlist(l,s,AVStr(a),AVStr(b),AVStr(c),AVStr(d),VStrNULL)
#define scan_Lists5(l,s,a,b,c,d,e) scan_Listlist(l,s,AVStr(a),AVStr(b),AVStr(c),AVStr(d),AVStr(e))

char *scan_ListElem1(PCStr(list),int sep,PVStr(e1));
int   num_ListElems(PCStr(list),int sep);
void  subSetList(PCStr(s1),PCStr(s2),PVStr(sb));
int   list2vect(PCStr(list),int del,int ac,const char *av[]);
int   list2vectX(PCStr(list),int del,int allocm,int ac,const char *av[]);
char *Str2vstr(PCStr(sstr),int slen,PVStr(vstr),int vlen);
int   decomp_args(const char *av[],int mac,PCStr(args),PVStr(argb));
int   strmatch_list(PCStr(str),PCStr(list),PCStr(cntrl),iFUNCP lfunc,void *lfile);

/*-- TIME FORMATTING */
extern const char *TIMEFORM_ANSI_C;
extern const char *TIMEFORM_USENET;
extern const char *TIMEFORM_HTTPDs;
extern const char *TIMEFORM_YmdHMS;
extern const char *TIMEFORM_RFC822;
extern const char *TIMEFORM_mdHMS;
extern const char *TIMEFORM_HTTPD;
extern const char *TIMEFORM_TAR;
extern const char *TIMEFORM_LS;
int   wdaytoi(PCStr(wday));
int   strfRusage(PVStr(usg),PCStr(fmt),int who,PCStr(sru));
#include <time.h> /* for time_t */
int   StrftimeGMT(PVStr(atime),int size,PCStr(fmt),time_t clock,int usecond);
int   StrftimeLocal(PVStr(atime),int size,PCStr(fmt),time_t clock,int usecond);
int   StrfTimeGMT(PVStr(atime),int size,PCStr(fmt),double T);
int   StrfTimeLocal(PVStr(atime),int size,PCStr(fmt),double T);
int   fromclockLocal(time_t clock,int *w,int *y,int *m,int *d,int *H,int *M,int *S);
int   LsDateClock(PCStr(date),time_t now);
int   scanYmdHMS_GMT(PCStr(stime));
int   YMD_HMS_toi(PCStr(ymdhms));
int   scan_period(PCStr(period),int dfltunit,int dflt);
int   scanNNTPtime(PCStr(stime));
int   scanHTTPtime(PCStr(stime));
int   scanUNIXFROMtime(PCStr(stime));
void  canon_date(PVStr(date));
double Scan_period(PCStr(period),int dfltunit,double dflt);
void  getTimestamp(PVStr(stime));
char *scanLsDate(PCStr(str),PVStr(date));
long  Gettimeofday(int *usec);

/*-- CODE CONVERSION */
typedef struct _CCX *CCXP;
CCXP  CCXnew(PCStr(from),PCStr(to));
int   CCXcreate(PCStr(from),PCStr(to),CCXP);
void  CCXtosv(CCXP,int tosv);
int   CCXexec(CCXP,PCStr(cinb),int ilen,PVStr(out),int osiz);
int   CCXactive(CCXP);
void  CCX_setincode(CCXP,PCStr(ccn));
int   CCX_setoutcode(CCXP,PCStr(ocs));
void  CCXthru8(CCXP,PCStr(thru8));
int   CCXwithJP(CCXP);
int   CCXnonJP(CCXP);
int   CCX_inputIsJP(CCXP);
int   CCXstats(CCXP,PVStr(buf));
void  CCXclear(CCXP);
const char *CCXcharset(CCXP);
int   CCXoutcharset(CCXP,const char **xcode);
int   CCXoutJP(CCXP);
int   CCXguessing(CCXP);
const char *CCXident(CCXP);
int   CCX_setindflt(CCXP ccx,PCStr(from));
const char *CCX_getindflt(CCXP);
const char *CCXgotincharcode(CCXP);
int   CCXinURL(CCXP ccx,int inURL);
int   CCX_converror(CCXP);
int   CCXcharsetcmp(PCStr(cs1),PCStr(cs2));
int   UCSinit();
void  UCSreset();
void  strip_ISO2022JP(PVStr(str));
char *strpbrk1B(const void *src,PCStr(brks),char **dst,PVStr(end));
int   FIX_2022(PCStr(src),PVStr(dst),PCStr(ctype));
void  TO_JIS(PCStr(src),PVStr(dst),PCStr(ctype));
void  TO_EUC(PCStr(src),PVStr(dst),PCStr(ctype));
void  TO_SJIS(PCStr(src),PVStr(dst),PCStr(ctype));
void  TO_UTF8(PCStr(src),PVStr(dst),PCStr(ctype));
void  TO_euc(PCStr(in),PVStr(out),int osiz);
FileSize CCXfile(PCStr(icharset),PCStr(ocharset),FILE *in,FILE *out);
int   codeconv_set(int enable,PCStr(charcode),int p2h);
int   codeconv_get(PCStr(ctype),const char **xcharset, int *p2h);
int   codeconv_line(PCStr(src),PVStr(dst),PCStr(ctype),int repair);

/*-- stdio on memory */
#include "ystrvec.h"
void  str_sopen(StrHead*,PCStr(id),char buf[],int size,int peak,PCStr(mode));
int   str_sputc(int ch, StrHead*);
char *str_sptell(StrHead*);
int   str_stell(StrHead*);
int   str_sprintf(StrHead*,PCStr(form), ... );
FILE *str_fopen(char buf[],int,PCStr(mode));
char *str_fgets(PVStr(s),int z,FILE *f);
int   str_fclose(FILE*);

/*-- MIME */
char *strSeekEOH(PCStr(head));
int   RFC821_skipheader(FILE *afp,FILE *out,PCStr(field));
int   RFC821_skipbody(FILE *afp,FILE *out,PVStr(line),int size);
void  RFC822_addHeaderField(PVStr(dst),PCStr(src));
void  RFC822_addresspartX(PCStr(in),PVStr(out),int siz);
char *RFC822_readHeader(FILE *in,int seeEOR);
const char *matchFields(PCStr(spec),PCStr(field),PCStr(ivalue));
void  filterFields(PCStr(spec),PVStr(head));
void  generic_domain(PVStr(hostaddr));
char *RFC822_fgetsHeaderField(PVStr(line),int size,FILE *fp);
#define fgetsHF(f,m,b) fgetsHeaderField(f,m,AVStr(b),sizeof(b))
char *fgetsHeaderField(FILE *hfp,PCStr(name),PVStr(value),int size); 
int   relayBODYpart(FILE *src,FILE *dst,const char *boundaries[],int extract,PVStr(endline));
void  relayRESPBODY(FILE *fs,FILE *tc,PVStr(line),int size);
void  decodeHEAD1(PCStr(tp),PVStr(xp),int decode,int cconv);
int   relay_pgpSIGN(FILE *fs,FILE *tc,const char *boundaries[],PVStr(endline));
int   relay_pgpSIGNED(FILE *fs,FILE *tc,const char *boundaries[],PVStr(endline));
int   scanAddrInBody(int mask,PCStr(spec),PVStr(line));
char *findField(PCStr(head),PCStr(field),const char **value);
char *findFieldValue(PCStr(head),PCStr(field));
int   replace_charset(PVStr(head),PCStr(charset));
int   replace_charset_value(PVStr(ctype),PCStr(charset),int force);
int   replaceContentType(PVStr(head),PCStr(type));
int   erase_charset_param(PVStr(ctype),PVStr(charset));
char *RFC822_valuescan(PCStr(vp),PVStr(value),int size);
void  RFC822_decompField2(PCStr(head),PVStr(fname),PVStr(value),int size);
void  RFC822_strip_commentX(PCStr(in),PVStr(out),int siz);
char *nextField(PCStr(field),int ignEOH);
char *getFieldValue2(PCStr(head),PCStr(field),PVStr(value),int size);
#define MIME_getfv(h,f,v) getFieldValue2(h,f,AVStr(v),sizeof(v))
int   removeFields(PVStr(head),PCStr(field),int wild);
int   rmField(PVStr(head),PCStr(field));
int   getParamX(PVStr(params),PCStr(name),PVStr(val),int siz,int del,int cookie);
int   getParam(PVStr(params),PCStr(name),PVStr(val),int siz,int del);
int   delParam(PVStr(params),PCStr(name));
int   extractParam(PVStr(head),PCStr(fname),PCStr(pname),PVStr(pvalue),int pvsize,int del);
void  msg_charcount(FILE *fp,int chcount[]);
void  PGPdecodeMIME(FILE*src,FILE*dst,FILE*cache, int filter,int codeconv,int enHTML);
void  PGPencodeMIME(FILE *src,FILE *dst);
typedef struct {
	int	me_filter;
	CCXP	me_ccx;
} MimeEnv;
int   encodeMIMEXX(MimeEnv *me,FILE *src,FILE *dst);
int   PGPencodeMIMEXX(MimeEnv *me,FILE *src,FILE *dst);
void  thruRESP(FILE *fs,FILE *tc);
int   uu_skip(int *ctx,PCStr(src));

typedef FILE *(*headFilter)(PVStr(head),FILE *tc,FILE *cache);
headFilter set_HEAD_filter(headFilter filter);

void  myMIMEversion(PVStr(ver));
void  scan_PGP(void*,PCStr(conf));

double Time();
void  MIME_rewriteHeader(PCStr(poster),PCStr(rewfmt),PVStr(head),PCStr(fname));
int   get_charset(PCStr(ctype),PVStr(chset),int size);
void  selectXref(PCStr(host),PCStr(xref1),PVStr(xref2));
int   findXref(FILE *afp,int (*matchfunc)(PCStr(a),PCStr(b)),PCStr(host),PVStr(xref),int size);
int   decodeBODY(FILE *fs,FILE *tc,int filter,PCStr(encoding),PCStr(decodeto),int do_enHTML);
void  decodeTERM(FILE *fs, FILE *tc, int enHTML);
void  decodeTERM1(PCStr(line),PVStr(xline));
void  MIME_strHeaderEncode(PCStr(ins),PVStr(outs), int osize);
void  MIME_strHeaderDecode(PCStr(ins),PVStr(outs), int osize);
void  MIME_to64(FILE *in, FILE *out);
int   QPfprintf(FILE *out,PCStr(escs),PCStr(fmt),...);
int   str_to64(PCStr(in),int isize,PVStr(out),int osize,int pnl);
int   str_from64(PCStr(in),int isize,PVStr(out),int osize);
int   str_fromqp(PCStr(in),int isize,PVStr(out),int osize);
int   str_toqp(PCStr(in),int isize,PVStr(out),int osize);
int   replaceFieldValue(PVStr(head),PCStr(field),PCStr(value));

/*-- REGULAR EXPRESSION */
struct fa_stat *frex_create(PCStr(rexp));
struct fa_stat *frex_append(struct fa_stat *fsp,PCStr(rexp));
char *frex_match(struct fa_stat *fsp,PCStr(str));
char *frex_matchX(struct fa_stat *fsp,PCStr(str),const char **start);
void  frex_free(struct fa_stat *fsp);
int   rexpmatchX(PCStr(rexp),PCStr(str),PCStr(ropts));
int   rexpmatch(PCStr(rexp),PCStr(str));
int   RexpMatch(PCStr(str),PCStr(rexp));

/*-- HASH */
int   Hcreate(int nelem,PCStr(nulval));
const char *Hsearch(int htid,PCStr(key),PCStr(data));
int   Hnext(int htid,int kx,const char **keyp,const char **datap);
int   strid_create(int nelem);
long int strid(int tab,PCStr(str),long int id);
void  strid_stat(int tab);
unsigned int FQDN_hash(PCStr(key));

/*-- URL */
int   nonxalpha_unescape(PCStr(src),PVStr(dst),int spacealso);
void  safe_escapeX(PCStr(src),PVStr(dst),int siz);
int   url_escapeX(PCStr(src),PVStr(dst),int siz,PCStr(escs),PCStr(sbrk));
int   URL_unescape(PCStr(src),PVStr(dst),int isform,int escrsvd);
int   URL_reescape(PCStr(src),PVStr(dst),int isform,int rstrsvd);

/*-- HTML */
int   isHTMLentity(PCStr(str),int*);
void  decode_entities(PCStr(src),PVStr(dst));
void  decodeEntities(PCStr(src),PVStr(dst),int);
void  decodeEntitiesX(PCStr(src),PVStr(dst),int siz,int anywhere);
int   encodeEntitiesX(PCStr(src),PVStr(dst),int siz);
#define HT_ISFORM 1
int   encodeEntitiesXX(PCStr(src),PVStr(dst),int siz,int opts);
int   encodeEntitiesY(PCStr(src),PVStr(dst),int dsize,PCStr(cset),int anywhere);
int   encode_entitiesX(PCStr(src),PVStr(dst),int siz);

void  onoff_flags(PVStr(flags),PCStr(delta),int on);
char *getv(const char *vv[],PCStr(name));
char *getvX(const char *av[],PCStr(name),int *ax);

void  PutEnv(PCStr(name),PCStr(value));

typedef int (*sortFunc)(const void*,const void*);
void  toMD5(PCStr(str),char md5[]);

char *getUsernameCached(int,PVStr(name));
int   Uname(PVStr(name));

char *ovstrcpy(char dst[],PCStr(src));
void  stackcopy(char *av[],int ac,char *asT,char *esT,char **areap,int *lengp,int *sizep);

#include <sys/types.h>
#include <time.h>
char *rsctime(time_t clock,PVStr(lsdate));
long timeBaseDayLocal(time_t clock);

#ifdef _MSC_VER /* VC++ {*/
int  bcmp(const void *,const void *,unsigned int);
void bcopy(const void*,void*,unsigned int);
void bzero(void*,unsigned int);

FILE *popen(const char*,const char*);
int  pclose(FILE*);

#include <io.h>
#include <direct.h>
#include <process.h>
#include <malloc.h>

#ifdef __cplusplus
unsigned int alarm(unsigned int);
int  chdir(const char*);
int  chown(const char *,int,int);
int  fchmod(int,int);
int  fcntl(int,int,void*);
int  fork();
int  ftruncate(int fd,unsigned int);
int  getegid();
int  geteuid();
int  getgid();
int  getppid();
int  gettimeofday(struct timeval *tv, struct timezone *tz);
int  getuid();
int  inet_aton(const char*,struct in_addr *);
int  kill(int,int);
int  killpg(int,int);
off_t lseek(int,off_t offset,int);
int  link(const char*,const char*);
int  lstat(const char *,struct stat *);
// int  mkdir(const char*,int);
#define mkdir(d,m) _mkdir(d)
int  pipe(int []);
int  seteuid(int);
void sleep(unsigned int);
int  strcasecmp(const char*,const char*);
int  strncasecmp(const char*,const char*,unsigned int n);
int  usleep(unsigned int);
int  utimes(const char*,struct timeval*);
int  readlink(const char*,char*,unsigned int);
int  rmdir(const char*);
int  vfork();
int  wait(int*);
int  wait3(int*,int,void*);
int  wait4(int,int*,int,void*);
int  waitpid(int,int*,int);
int  initgroups(const char*,int);

int  setsid();
int  nice(int);
int  chroot(const char*);
void setlinebuf(FILE*);
int  symlink(const char*,const char*);
void setbuffer(FILE*,char*,unsigned int);
int  fchown(int,int,int);
int  setegid(int);
int  setgid(int);
int  setuid(int);
/*
int  socketpair(int,int,int,int[]);
*/

char *getlogin(void);
int setlogin(const char *name);
struct passwd *getpwent();
void setpwent();
void endpwent();
void endhostent();

#define snprintf _snprintf
#define vsnprintf _vsnprintf

#else
#endif

#define sigsetjmp(b,s)	setjmp(b)
#define siglongjmp	longjmp
#ifndef sigjmp_buf
#define sigjmp_buf	jmp_buf
#endif

struct rusage {
 struct timeval ru_utime;
 struct timeval ru_stime;
	long	ru_maxrss;
	long	ru_ixrss;
	long	ru_idrss;
	long	ru_isrss;
	long	ru_minflt;
	long	ru_majflt;
	long	ru_nswap;
	long	ru_inblock;
	long	ru_oublock;
	long	ru_msgsnd;
	long	ru_msgrcv;
	long	ru_nsignals;
	long	ru_nvcsw;
	long	ru_nivcsw;
};
int getrusage(int who,struct rusage *rusage);

#else /*}else(UNIX){*/
#include <unistd.h>
#ifndef __EMX__
#include <sys/wait.h>
#endif
#if defined(hpux) || defined(__hpux__)
#include <alloca.h>
int seteuid(int uid);
int setegid(int gid);
void setbuffer(FILE *fp,char *buff,unsigned int size);
void setlinebuf(FILE *fp);
#endif

#if !defined(__KURO_BOX__)
int  bcmp(const void *s1, const void *s2, size_t n);
void bcopy (const void *src, void *dest, size_t n);
void bzero(void *s, size_t n);
#endif

#ifndef _VSIGNAL_H
#if defined(sun) || defined(__CYGWIN__)
int sigblock(int mask);
int sigmask(int signum);
int sigsetmask(int mask);
#endif
#endif

#if defined(sun) /* SunOS5.* {*/
#undef FS

#if defined(SOLARIS2) || defined(SOLARIS25) /* SunoS5.X {*/
#ifdef __cplusplus
extern "C" {
#endif

#ifndef snprintf
int __snprintf(char *str,size_t size,const char *format,...);
#define snprintf __snprintf
#endif
#define NOVSNPRINTF

int getrusage(int who, struct rusage *rusage);
int usleep(unsigned int useconds);
int utimes(const char *file, struct timeval *tvp);
int killpg(pid_t pgrp,int sig);
pid_t wait3(int *statusp, int options,struct rusage *rusage);
int gethostname(char *name,int namelen);
int inet_aton(const char *addr,struct in_addr *inap);
void setbuffer(FILE *iop,char *abuf,size_t asize);
int setlinebuf(FILE *iop);
#ifdef __cplusplus
}
#endif
#endif /*}*/
#endif /*}*/
#endif /*}*/

#ifdef sun
#define isSolaris() 1
#include <alloca.h>
#else
#define isSolaris() 0
#endif

#ifdef __cplusplus
extern "C" {
#endif
int yp_get_default_domain(char**);
int yp_match(PCStr(dom),PCStr(map),PCStr(uids),int len,char **val,int *vlen);
#ifdef __cplusplus
}
#endif

#ifdef WITH_QVSTR /*{*/
extern char *Xstrdup(FL_PAR_P, const char *s);
extern void *Xmalloc(FL_PAR_P, unsigned int z);
extern void *Xcalloc(FL_PAR_P, unsigned int n,unsigned int z);
extern void *Xrealloc(FL_PAR_P, void *p,unsigned int z);
extern void Xfree(FL_PAR, void *p);
extern int Xfclose(FL_PAR, FILE *);
extern int XXfcloseFILE(FL_PAR, FILE*);
#ifdef strdup
#undef strdup
#endif
#define strdup(s)	Xstrdup(FL_ARG_s, s)
#ifdef malloc
#undef malloc
#endif
#define malloc(z)	Xmalloc(FL_ARG_s, z)
#ifdef calloc
#undef calloc
#endif
#define calloc(p,z)	Xcalloc(FL_ARG_s, p,z)
#ifdef realloc
#undef realloc
#endif
#define realloc(p,z)	Xrealloc(FL_ARG_s, p,z)
#ifdef free
#undef free
#endif
#define free(p)		Xfree(FL_ARG,p)
#ifdef fclose
#undef fclose
#endif
#define fclose(p)	Xfclose(FL_ARG,p)
#ifdef fcloseFILE
#undef fcloseFILE
#endif
#define fcloseFILE(p)	XXfcloseFILE(FL_ARG,p)
#else /*}{*/
int FL_fcloseFILE(FL_PAR,FILE *fp);
#define fcloseFILE(p)   FL_fcloseFILE(FL_ARG,p)
#endif /*}*/

int mallocSize(void *p);
int pipeX(int sv[2],int size);

#ifdef _MSC_VER
void wlfprintf(const char *fmt,...);
#else
#define wlfprintf 0?1:printf
#endif

#ifdef _MSC_VER
int Xsocket_FL(FL_PAR,int,int,int);
int Xaccept_FL(FL_PAR,int fd,void *sa,int *len);
int Xsocketpair_FL(FL_PAR,int,int,int,int[]);
int Xopen_FL(FL_PAR,const char *path,int mode);
int Xclose_FL(FL_PAR,int fd);
int Xdup_FL(FL_PAR, int fd);
int Xdup2_FL(FL_PAR, int sfd,int dfd);
#define socketpair(d,t,p,v) Xsocketpair_FL(FL_ARG,d,t,p,v)
#undef socket
#define socket(d,t,p)     Xsocket_FL(FL_ARG,d,t,p)
#undef accept
#define accept(fd,sa,len) Xaccept_FL(FL_ARG,fd,sa,len)

//#if defined(UNDER_CE)
#define open(p,m)       Xopen_FL(FL_ARG,p,m)
#define close(d)        Xclose_FL(FL_ARG,d)
//#endif

#else
#define Xclose_FL(FL_PAR,fd)     close(fd)
#define Xdup2_FL(FL_PAR,sfd,dfd) dup2(sfd,dfd)
#endif

FILE *Xfopen(FL_PAR,    const char *f,const char *m);
#define fopen(f,m)	Xfopen(FL_ARG, f,m)
FILE *Xfdopen(FL_PAR,   int fd,PCStr(mode));
#define fdopen(f,m)	Xfdopen(FL_ARG, f,m)
int Xfwrite(FL_PAR,     const void *b,int z,int n,FILE *f);
#define fwrite(b,z,n,f)	Xfwrite(FL_ARG, b,z,n,f)
int Xfputs(             const char *s,FILE *f);
#define Xfputs(s,f)	Xfputs(s,f)
/* was to be #define fputs() ? */
int Xfputs_FL(FL_PAR,   const char *s,FILE *fp);
int Xfflush(FL_PAR,     FILE *f);
#define fflush(f)       Xfflush(FL_ARG, f)
int fflushTrace(FILE *fp,int set);
int pendingcc(FILE *fp);
int fcloseTIMEOUT_FL(FL_PAR,FILE *fp);
int fflushTIMEOUT_FL(FL_PAR,FILE *fp);
/*
FILE *Xpopen();
int Xpclose();
FILE *Xtmpfile(FL_PAR);
#define tmpfile() Xtmpfile(FL_ARG)
*/

#define TIMEOUT_isNEVER(t) (t == -1 || t == -1*1000 || t == -1*1000*1000 || t==0)
#define TIMEOUT_isIMM(t)   (t == -2 || t == -2*1000 || t == -2*1000*1000)
#define TIMEOUT_NEVER      -1
#define TIMEOUT_IMM        -2

#if !defined(__KURO_BOX__)
#if defined(SOLARIS25)
#define flockfile(f)
#define funlockfile(f)
#else
#ifdef __cplusplus
extern "C" {
#endif
#ifndef flockfile
void flockfile(FILE *fp);
void funlockfile(FILE *fp);
#endif
#ifdef __cplusplus
}
#endif
#endif
#endif

#ifndef NOVSNPRINTF /*{*/
#define xdaVARGS(siz,fmt) \
	CStr(_msg,LINESIZE); \
	CStr(llfmt,1024); \
	char *va[siz]; \
	va_list nap; \
	va_start(nap,fmt); \
	if( modifyFmt(fmt,AVStr(llfmt),sizeof(llfmt)) ) \
                fmt = llfmt; \
	vsnprintf(_msg,sizeof(_msg),fmt,nap); \
	va_end(nap); \
	va[0] = _msg; /* for(i=1;i<siz;i++)va[i]=0; */ \
	fmt = "%s";

#if defined(__KURO_BOX__) \
 || defined(__arm__) \
 || defined(__amd64__) \
 || defined(UNDER_CE) \
 || defined(__osf__) \
 || DOUBLEARG_ALIGNED
#define daVARGS xdaVARGS
#endif
#endif /*}*/

int fpurge(FILE *fp);
#ifdef fileno_unlocked
#undef fileno
#define fileno fileno_unlocked
#endif
#ifdef feof_unlocked
#undef feof
#define feof feof_unlocked
#endif
#ifdef ferror_unlocked
#undef ferror
#define ferror ferror_unlocked
#endif

/*
int Xwait(int *status);
#define wait(s)		Xwait(s)
*/

#if defined(_MSC_VER) && 1400 <= _MSC_VER /* VC2005 or laters */
__time32_t _time32(__time32_t *t);
#define time(t) _time32(t)
#endif

extern int STDIO_IOFBF;
#if defined(_MSC_VER) && defined(UNDER_CE) /* isWindowsCE(){*/
#define isWindowsCE() 1
void dumposf(FILE *tc,PCStr(wh),int min,int max,int dup);
void dumpFILEX(FILE *tc,int inact);
void exitX(int code,const char *fmt,...);
#define exit(code) \
	exitX(code,"%X exit(%d) from %s:%d",getpid(),code,__FILE__,__LINE__)
void exitmessage(const char *fmt,...);
FILE *XX_fopen(const char *path,const char *mode);
int XX_fgetc(FILE *fp);
int XX_fread(FL_PAR, void *b,int siz,int nel,FILE *fp);
int XX_fputc(int ch,FILE *fp);
int XX_fputs(FL_PAR,const char *s,FILE *fp);
int XX_fwrite(FL_PAR, const void *b,int siz,int nel,FILE *fp);
int XX_vfprintf(FILE *fp,const char *fmt,va_list ap);
int XX_fflush(FILE *fp);
int XX_fseek(FILE *fp,int off,int wh);
long XX_ftell(FILE *fp);
int XX_fclose_FL(FL_PAR, FILE *fp);
int XX_fcloseFILE_FL(FL_PAR, FILE *fp);
int XX_setvbuf(FILE *fp,char *buf,int mode,size_t size);
#undef getc
#define getc(fp) XX_fgetc(fp)
#undef fgetc
#define fgetc(fp) XX_fgetc(fp)
#undef putc
#define putc(c,fp) XX_fputc(c,fp)
#undef fputc
#define fputc(c,fp) XX_fputc(c,fp)
#undef fputs
#define fputs(s,f) XX_fputs(FL_ARG,s,f)
#define fread(b,z,n,f) XX_fread(FL_ARG, b,z,n,f)

#undef fseek
#define fseek(fp,off,wh) XX_fseek(fp,off,wh)
#undef ftell
#define ftell(fp) XX_ftell(fp)
#undef setvbuf
#define setvbuf(fp,buf,mode,size) XX_setvbuf(fp,buf,mode,size)

#include <io.h>
#define dup(fd) Xdup_FL(FL_ARG, fd)
#define dup2(sfd,dfd) Xdup2_FL(FL_ARG, sfd,dfd)

int XX_feof(FILE *fp);
int XX_ferror(FL_PAR, FILE *fp);
int XX_clearerr(FILE *fp);
#define feof(fp) XX_feof(fp)
#define clearerr(fp) XX_clearerr(fp)
#define ferror(fp) XX_ferror(FL_ARG, fp)

int XX_ungetc(FL_PAR,int ch,FILE *fp);
#define ungetc(ch,fp) XX_ungetc(FL_ARG,ch,fp)

#else /*}{ !WindowsCE */
#define isWindowsCE() 0
#define dumposf(fp,wh,min,max,dup) 0
#define dumpFILEX(fp,inact) 0
#define XX_fopen(p,m) 0
#define XX_fgetc(fp) 0
#define XX_fread(FL_PAR, b,s,n,fp) 0
#define XX_fputs(b,fp) 0
#define XX_fwrite(F,L, b,s,n,fp) 0
#define XX_fflush(fp) 0
#define XX_fclose(fp) 0
#define XX_vfprintf(fp,m,v) 0
/*
9.9.8-pre5
#undef fcloseFILE
int fcloseFILE(FILE *fp);
*/
int FL_fcloseFILE(FL_PAR,FILE *fp);

#if defined(_MSC_VER)
void abortX(FL_PAR);
void exitX(int code,FL_PAR);
void _exitX(int code,FL_PAR);
#define abort() abortX(FL_ARG)
#define exit(code) exitX(code,FL_ARG)
#define _exit(code) _exitX(code,FL_ARG)
#define dup(fd) Xdup_FL(FL_ARG, fd)
#define dup2(sfd,dfd) Xdup2_FL(FL_ARG, sfd,dfd)
#endif

#endif /*} !WindowsCE */

void FinishX(PCStr(F),int L,int code);
#define Finish(code) FinishX(__FILE__,__LINE__,code)

int inputReady(int sock,int *rd);
static int inputReady_FL(FL_PAR, int sock,int *rd){
	int rdy;
	fprintf(stderr,"---- inputReady[%d] %s:%d ...\n",sock,FL_BAR);
	rdy = inputReady(sock,rd);
	return rdy;
}

typedef double _heapLock_01[16];
#define _heapLock _heapLock_01
int heapLock(FL_PAR,void *lock);
int heapUnLock(FL_PAR,void *lock);

typedef double CriticalSec_01[16];
#define CriticalSec CriticalSec_01
int setupCSC(const char *wh,void *acs,int asz);
/*
int enterCSC(void **cs);
int enterCSCX(void **cs,int timeout);
*/
int enterCSC_FL(FL_PAR,void *cs);
int enterCSCX_FL(FL_PAR,void *cs,int timeout);
#define enterCSC(cs)      enterCSC_FL(FL_ARG,cs)
#define enterCSCX(cs,to)  enterCSCX_FL(FL_ARG,cs,to)

/*
int leaveCSC(void **cs);
*/
int leaveCSC_FL(FL_PAR,void *cs);
#define leaveCSC(cs) leaveCSC_FL(FL_ARG,cs)
int debugCSC(void *acs,int on);

typedef struct {
	void *m_addr;
	int   m_size;
	void *m_mh;
	void *m_fh;
	FILE *m_fp;
} MMap;
MMap *filemmap(PCStr(fname),PCStr(fmode),int off,int len);
int freemmap(MMap *mm);


#ifdef __cplusplus
#if defined(__hpux__) || defined(sun)
extern "C" int unsetenv(const char *name);
#endif
#endif
#ifdef _MSC_VER
void unsetenv(const char *name);
#endif

#if defined(_MSC_VER)
MMap *Xfilemmap_FL(FL_PAR,PCStr(fname),PCStr(fmode),int off,int len);
int Xfreemmap_FL(FL_PAR,MMap *mm);
#define filemmap(fn,fm,off,len) Xfilemmap_FL(FL_ARG,fn,fm,off,len)
#define freemmap(mm) Xfreemmap_FL(FL_ARG,mm)
#endif

void *getmmap(MMap *mmap);
void *setmmap(void *mh,int off,int len);

#undef putenv
int Xputenv_FL(FL_PAR,PCStr(str));
#define putenv(str) Xputenv_FL(FL_ARG,str)

int newthreads();
int numthreads();
int pnumthreads();
int actthreads();
int actthreadsmax();
int getthreadid();
int setthreadgid(int tid,int gid);
int getthreadgid(int tid);
int getthreadgix(int tid);
int setthread_FL(int tid,FL_PAR,PCStr(st));
int dumpthreads(PCStr(wh),FILE *tc);

#if defined(_MSC_VER) && !isWindowsCE()
#define tidof(tix)	(tix & 0x00FFFFFF)
#define tideq(ttid,tid)	(tidof(ttid) == tidof(tid))
#else
#define tidof(tix)	(tix)
#define tideq(ttid,tid)	(tidof(ttid) == tidof(tid))
#endif

#define SVX (STX_tix)
#define SVI (STX_tid)
#define PRTID(tid) (0xFFFF & tidof(tid))
#define TID PRTID(getthreadid())

#ifndef _SIGMASKINT_
#define _SIGMASKINT_
typedef unsigned int SigMaskInt;
#endif

void putResTrace(PCStr(fmt),...);

int isAlive_FL(FL_PAR,int sock);
int IsAlive_FL(FL_PAR,int sock);
#define isAlive(sock) isAlive_FL(FL_ARG,sock) 
#define IsAlive(sock) IsAlive_FL(FL_ARG,sock) 

int startMD5(void *ctx,int size);
int updateMD5(void*ctx,const char *str,int len);
int finishMD5(void*ctx,char md5b[],char md5a[]);

int *IgnRet(FL_PAR);
#define IGNRETZ	*IgnRet(FL_ARG) += 0 !=
#define IGNRETP	*IgnRet(FL_ARG) += 0 >=
#define IGNRETS	*IgnRet(FL_ARG) += 0 ==

Int64 p2lluX(FL_PAR,const void *p);
Int64 p2llX(FL_PAR,const void *p);
#define p2llu(p) p2lluX(FL_ARG,(const void*)(p))
#define p2ll(p) p2lluX(FL_ARG,(const void*)(p))
int p2iX(FL_PAR,const void *p);
#define p2i(p) p2iX(FL_ARG,p)
#define xp2i(p) p2iX(FL_ARG,(const void*)(p))
const void *ll2pX(FL_PAR,Int64 ll);
#define ll2p(ll) ll2pX(FL_ARG,ll)
int ll2iX(FL_PAR,Int64 ll);
#define ll2i(ll) ll2iX(FL_ARG,ll)
const void *i2pX(FL_PAR,int i);
#define i2p(i) i2pX(FL_ARG,i)
#define pp2cpp(p) ((const char **)(p))
#define pp2cpcp(p) ((const char*const*)(p))

#define isizeof(d) ((int)sizeof(d))
#define itime(t)   ((int)time(t))
#define iftell(f)  ((int)ftell(f))
#define istrlen(s) ((int)strlen(s))

#if defined(FMT_CHECK) /*{ 9.9.7 for testing format & values */
#define G_GNUC_PRINTF(fmtx,vax)

int strRL(const char **d);
#define putInitlog(fmt,...)      fprintf(stderr,fmt,##__VA_ARGS__)
#define daemonlog(flags,fmt,...) fprintf(stderr,fmt,##__VA_ARGS__)
#define syslog_ERROR(fmt, ...)   fprintf(stderr,fmt,##__VA_ARGS__)
#define syslog_DEBUG(fmt, ...)   fprintf(stderr,fmt,##__VA_ARGS__)
#define porting_dbg(fmt,...)     fprintf(stderr,fmt,##__VA_ARGS__)
#define proc_title(fmt,...)      fprintf(stderr,fmt,##__VA_ARGS__)
#define Xfprintf(fp,fmt,...)     fprintf(stderr,fmt,##__VA_ARGS__)

#define XAVStr(s) s
#define XBVStr(s) s
#define XEVStr(s) s
#define XFVStr(s) s
#define XTVSTR(t)
#define XUVStr(t) (char*)
#define XTVStr(s) (s+strlen(s))
#define XDVStr(s,d) (s+d)
#define XZVStr(s,z) s
#define XQVStr(s,b) s

#define Rsprintf(d,fmt,...)      (sprintf(d,fmt,##__VA_ARGS__),strRL(&d))
#define sprintf(d,fmt,...)       sprintf((char*)(d),fmt,##__VA_ARGS__)
#define Xsprintf(d,fmt,...)      sprintf(X##d,fmt,##__VA_ARGS__)
#define Sprintf(d,fmt,...)       (sprintf(X##d,fmt,##__VA_ARGS__),strtail(X##d))

#else /*}{*/

#define FMT_putInitlog   putInitlog
#define FMT_daemonlog    daemonlog
#define FMT_syslog_ERROR syslog_ERROR
#define FMT_syslog_DEBUG syslog_DEBUG
#define FMT_porting_dbg  porting_dbg
#define FMT_proc_title   proc_title
#define FMT_Xfprintf     Xfprintf
#define FMT_Sprintf      Sprintf
#define FMT_Xsprintf     Xsprintf
#define FMT_XRsprintf    XRsprintf

int FMT_putInitlog(PCStr(fmt),...);
int FMT_daemonlog(PCStr(flags),PCStr(fmt),...);
int FMT_syslog_ERROR(PCStr(fmt), ...);
int FMT_syslog_DEBUG(PCStr(fmt), ...);
int FMT_porting_dbg(PCStr(fmt),...);
int FMT_Xfprintf(FILE *fp,PCStr(fmt),...);
#define fprintf	Xfprintf
int FMT_proc_title(PCStr(fmt),...);
char *FMT_Sprintf(PVStr(str),PCStr(fmt),...);

int FMT_Xsprintf(PVStr(d),PCStr(f),...);
int FMT_XRsprintf(PRVStr(d),PCStr(f),...);
#if defined(_MSC_VER) || defined(NONC99)
#else
#undef Rsprintf
#define sprintf(d,f,...) FMT_Xsprintf(TVSTR(d) d,f,##__VA_ARGS__)
#define Rsprintf(d,f,...) FMT_XRsprintf(TVSTR(d) &d,f,##__VA_ARGS__)
#endif
#endif /*}*/

typedef struct _Z1Ctx {
	int	z1_debug;
	int	z1_ssize;
	int	z1_asize;
	int	z1_acnt;
	int	z1_fcnt;
	void   *z1_Z1;
} Z1Ctx;
Z1Ctx *deflateZ1new(Z1Ctx *Zc);
Z1Ctx *inflateZ1new(Z1Ctx *Zc);
int deflateZ1end(Z1Ctx *Zc);
int inflateZ1end(Z1Ctx *Zc);
int deflateZ1(Z1Ctx *Zc,PCStr(in),int len,PVStr(out),int osz);
int inflateZ1(Z1Ctx *Zc,PCStr(in),int len,PVStr(out),int osz);

#endif /* _YSTRING_H */
