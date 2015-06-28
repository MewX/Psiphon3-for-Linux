#include "ystring.h"
#include <ctype.h>

#ifndef _MSC_VER
#include <sys/time.h>
#include <sys/resource.h>
#endif

#define RUSAGE_SELF 0
#define RUSAGE_CHILDREN -1

char *rusage_ALL = "%uu %ss %SS %RR %rr %tt %dd %kk %ee %ff %ww %ii %oo %gg %xx %yy";

/*
 * should include the real-time in the extended Rusage structure
 * real-time is one of important resource usage (to hold process)
 * also it is useful to see the rusage per a unit time
 * it might be represented as the real-time of start and end
 */

static void addru(struct rusage *dru,struct rusage *sru){
	dru->ru_utime.tv_sec += sru->ru_utime.tv_sec;
	dru->ru_utime.tv_usec += sru->ru_utime.tv_usec;
	dru->ru_stime.tv_sec += sru->ru_stime.tv_sec;
	dru->ru_stime.tv_usec += sru->ru_stime.tv_usec;
	dru->ru_maxrss += sru->ru_maxrss;
	dru->ru_ixrss += sru->ru_ixrss;
	dru->ru_idrss += sru->ru_idrss;
	dru->ru_isrss += sru->ru_isrss;
	dru->ru_minflt += sru->ru_minflt;
	dru->ru_majflt += sru->ru_majflt;
	dru->ru_nswap += sru->ru_nswap;
	dru->ru_inblock += sru->ru_inblock;
	dru->ru_oublock += sru->ru_oublock;
	dru->ru_msgsnd += sru->ru_msgsnd;
	dru->ru_msgrcv += sru->ru_msgrcv;
	dru->ru_nsignals += sru->ru_nsignals;
	dru->ru_nvcsw += sru->ru_nvcsw;
	dru->ru_nivcsw += sru->ru_nivcsw;
}
int strfRusage(PVStr(usg),PCStr(fmt),int who,PCStr(sru)){
	const char *sp;
	char ch;
	refQStr(dp,usg);
	double dt;
	struct rusage ru;
	struct rusage ruc;
	CStr(lfm,32);
	refQStr(lp,lfm);
	CStr(xlfm,32);
	struct timeval tv;
	int iv;

	bzero(&ru,sizeof(ru));
	if( who & 1 ) getrusage(RUSAGE_SELF,&ru);
	if( who & 2 ){ getrusage(RUSAGE_CHILDREN,&ruc); addru(&ru,&ruc); }
	if( who & 4 ) if( sru != NULL ) addru(&ru,(struct rusage*)(sru));

	for( sp = fmt; ch = *sp; sp++ ){
		if( ch != '%' ){
			setVStrPtrInc(dp,ch);
			continue;
		}
		ch = *++sp;

		if( ch == '{' ){
			ch = *++sp;
			switch( ch ){
			}
		}

		lp = lfm;
		while( *sp == '-' || isdigit(*sp) || *sp == '.' ) 
		{
			setVStrPtrInc(lp,*sp);
			ch = *++sp;
		}
		setVStrEnd(lp,0);

		setVStrEnd(dp,0);
		switch( ch ){
			case 'A':
				return strfRusage(BVStr(usg),rusage_ALL,4,(char*)&ru);
				break;
			case 'B':
				Bcopy(&ru,usg,sizeof(struct rusage));
				break;
			case 'u':
			case 's':
				if( ch == 'u' )
					tv = ru.ru_utime;
				else	tv = ru.ru_stime;
				dt = tv.tv_sec + tv.tv_usec / 1000000.0;
				if( lp == lfm )
					sprintf(dp,"%3.2f",dt);
				else{
					sprintf(xlfm,"%%%sf",lfm);
					sprintf(dp,xlfm,dt);
				}
				break;

			case 'r':
			case 't':
			case 'd':
			case 'k':
			case 'e':
			case 'f':
			case 'w':
			case 'i':
			case 'o':
			case 'S':
			case 'R':
			case 'g':
			case 'x':
			case 'y':
				switch( ch ){
					case 'r': iv = ru.ru_maxrss; break;
					case 't': iv = ru.ru_ixrss; break;
					case 'd': iv = ru.ru_idrss; break;
					case 'k': iv = ru.ru_isrss; break;
					case 'e': iv = ru.ru_minflt; break;
					case 'f': iv = ru.ru_majflt; break;
					case 'w': iv = ru.ru_nswap; break;
					case 'i': iv = ru.ru_inblock; break;
					case 'o': iv = ru.ru_oublock; break;
					case 'S': iv = ru.ru_msgsnd; break;
					case 'R': iv = ru.ru_msgrcv; break;
					case 'g': iv = ru.ru_nsignals; break;
					case 'x': iv = ru.ru_nvcsw; break;
					case 'y': iv = ru.ru_nivcsw; break;
				}
				if( lp == lfm )
					sprintf(dp,"%d",iv);
				else{
					sprintf(xlfm,"%%%sd",lfm);
					sprintf(dp,xlfm,iv);
				}
				break;
		}
		dp += strlen(dp);
	}
	setVStrEnd(dp,0);
	return dp - usg;
}
