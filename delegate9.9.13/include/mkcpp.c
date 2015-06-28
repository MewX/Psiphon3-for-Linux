/*
 * 041129 ysato@delegate.org
 */
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#if defined(__linux__) /* RedHat6 */ \
 || defined(__APPLE__) /* gcc4.0 */ \
 || defined(__osf__) /* DEC ALPHA */ \
 || defined(__CYGWIN__)

#include <sys/time.h>
#endif
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef _MSC_VER
#include <stdlib.h>
#endif

#ifdef _MSC_VER
#include <windows.h>
#include <winbase.h>
static void utime2ftime(struct timeval *tv,FILETIME *ftime)
{	int year,mon,day,hour,min,sec;
	struct tm *tm;
	WORD ddate,dtime;
	struct tm tm0;
	time_t tsec;

	tsec = tv->tv_sec;
	tm = gmtime(&tsec);
	/*
	tm = gmtime(&tv->tv_sec);
	*/
	if( tm == 0 ){
		memset(&tm0,0,sizeof(tm0));
		tm = &tm0;
	}

	year = tm->tm_year + 1900 - 1980;
	mon  = tm->tm_mon  +  1;
	day  = tm->tm_mday;
	hour = tm->tm_hour;
	min  = tm->tm_min;
	sec  = tm->tm_sec / 2;
	ddate = (year <<  9) | (mon << 5) | day;
	dtime = (hour << 11) | (min << 5) | sec;
	DosDateTimeToFileTime(ddate,dtime,ftime);
}
int utimes(const char *path,struct timeval *tvp)
{	HANDLE fh;
	FILETIME atime,mtime;
	BOOL ok;
	struct tm *tm;

	fh = CreateFile(path,GENERIC_READ|GENERIC_WRITE,
		0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if( fh == NULL )
		return -1;

	utime2ftime(&tvp[0],&atime);
	utime2ftime(&tvp[1],&mtime);

	ok = SetFileTime(fh,NULL,&atime,&mtime);
	CloseHandle(fh);
	if( ok )
		return 0;
	else	return -1;
}
#endif


#include "../putsigned.c"
#ifndef _PUTSIGNED_C_
int putsigned(FILE *in,FILE *out,char *line,int didsign){
	return 0;
}
#endif

static int p2i(const void *p){
	union {
		const void *p;
		int i;
	} u;
	u.p = p;
	return u.i;
}

static FILE *include_inline(FILE *out,const char *line){
	char file[1024];
	FILE *fp;
	file[0] = 0;
	sscanf(line,"#include \"%[^\"]",file);
	if( fp = fopen(file,"r") ){
		return fp;
	}
	return 0;
}
static int strheq(const char *str,const char *hs){
	if( strncmp(str,hs,strlen(hs)) == 0 )
		return strlen(hs);
	return 0;
}
typedef struct {
	FILE *fp_fp;
	int   fp_li;
} filePos;
int main(int ac, char *av[]){
	FILE *in = stdin;
	FILE *out = stdout;
	char orig[1024];
	char line[1024],*lp,ch,arg[1024];
	int nlen;
	struct stat st;
	int mtime = -1;
	const char *src = "--stdin";
	const char *dst = "--stdout";
	int lni,lno;
	FILE *in1;
	filePos fP = {0,0};

	int ai;
	int dosign = 0;
	int didsign = 0;

	for( ai = 1; ai < ac; ai++ ){
		if( strcmp(av[ai],"-sign") == 0 ){
			dosign = 1;
		}
	}

	if( 1 < ac ){
		if( 2 < ac && strcmp(av[1],av[2]) == 0 ){
			sprintf(orig,"%s.orig",av[1]);
			in = fopen(orig,"r");
			if( in != 0 ){
				fclose(in);
			}else{
				rename(av[1],orig);
			}
			av[1] = orig;
		}
		in = fopen(av[1],"r");
		src = av[1];
	}
	if( 2 < ac ){
		out = fopen(av[2],"w");
		dst = av[2];
	}
	if( src == 0 || dst == 0 ){
		fprintf(stderr,"--- mkcpp %X %X\n",p2i(src),p2i(dst));
		exit(-1);
	}
	if( in == 0 || out == 0 ){
		fprintf(stderr,"--- mkcpp %X:%s %X:%s\n",p2i(in),src,p2i(out),dst);
		exit(-1);
	}
	if( fstat(fileno(in),&st) == 0 ){
		mtime = st.st_mtime;
	}

	lni = lno = 0;
	while( 1 ){
		if( fgets(line,sizeof(line),in) == NULL ){
			if( fP.fp_fp ){
				lni = fP.fp_li;
				in = fP.fp_fp;
				fP.fp_fp = 0;
				continue;
			}
			break;
		}
		if( dosign ){
			didsign = putsigned(in,out,line,didsign);
			continue;
		}
		if( lni != lno ){
			fprintf(out,"#line %d\n",lni+1);
			lno = lni;
		}
		if( strncmp(line,"#line ",6) == 0 ){
			lni = lno = atoi(line+6);
			fprintf(out,"#line %d /*INH*/\n",lni);
			continue;
		}
		if( strncmp(line,"#include",8)==0 && strstr(line,"{inline}") ){
			if( in1 = include_inline(out,line) ){
				fprintf(out,"#if 0\n");
				fprintf(out,"%s",line);
				fprintf(out,"#endif\n");
				fprintf(out,"#line 1\n");
				fP.fp_fp = in;
				fP.fp_li = lni;
				in = in1;
				lni = lno = 0;
				continue;
			}
		}
		lni++;
		for(lp = line; (ch = *lp) != 0; lp += nlen){
			if( line[0] != '#' && (nlen = strheq(lp,"putMssg(")) ){
				fprintf(out,"HTML_putmssg(Conn,");
			}else
			if( nlen = strheq(lp,"MStr(") ){
				sscanf(lp+nlen,"%[^,)]",arg);
				if( lp[nlen+strlen(arg)] != ',' ){
					fprintf(stderr,"ERROR: %s\n",line);
					return -1;
				}
				fprintf(out,"\n#define %sBASE %s\n\tNStr(",
					arg,arg);
				lno += 2;
			}else
			if( nlen = strheq(lp,"sprintf(") ){
				sscanf(lp+nlen,"%[^,]",arg);
				fprintf(out,"Xsprintf(AVStr(%s)",arg);
				nlen += strlen(arg);
			}else
			if( nlen = strheq(lp,"Rsprintf(") ){
				sscanf(lp+nlen,"%[^,]",arg);
				fprintf(out,"XRsprintf(TVSTR(%s)&%s",arg,arg);
				nlen += strlen(arg);
			}else{
				if( isalnum(ch) || ch == '_' ){
					while( isalnum(ch) || ch == '_' ){
						putc(ch,out);
						ch = *++lp;
					}
					nlen = 0;
				}else{
					putc(ch,out);
					nlen = 1;
					if( ch == '\n' ){
						lno++;
					}
				}
			}
		}
	}
	fclose(out);
	if( 0 < mtime ){
		struct timeval tv[2];
		int nmtime = -1;
		if( stat(dst,&st) == 0 ){
			nmtime = st.st_mtime;
		}
		if( dosign ){
			/* making gen/*.h (depending mkcpp) later than mkcpp */
			mtime = time(0) + 1;
		}
		printf("-- mkcpp set time: %d -> %d %s\n",nmtime,
			mtime,dst);
		tv[0].tv_sec = mtime;
		tv[0].tv_usec = 0;
		tv[1] = tv[0];
		utimes(dst,tv);
	}
	return 0;
}
