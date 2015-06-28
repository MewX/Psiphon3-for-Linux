#include <stdio.h>
#include <stdlib.h>
#include "ystring.h"
#include "fpoll.h"
extern double Time();
int CFI_init(int ac,const char *av[]);

int dping_main(int ac,const char *av[])
{	int oi,ox,oc,ix,ic,ifd,ofd,rcc;
	int iwait;
	char *outstr;
	double ss,ds,rtt,min,max,total;
	CStr(buf,2);
	FILE *fs;

	if( ac <= 1 ){
		fprintf(stderr,"usage: %s string\n",av[0]);
		return -1;
	}
	CFI_init(ac,av);
	outstr = (char*)av[1];
	iwait = 2;
	ifd = 0;
	ofd = 1;


	ox = 0;
	for( oi = 0; oc = outstr[oi]; oi++ ){
		if( oc == '\\' ){
			switch( outstr[oi+1] ){
			case 'r': outstr[ox++] = '\n'; oi++; continue;
			case 'n': outstr[ox++] = '\r'; oi++; continue;
			}
		}
		outstr[ox++] = oc;
	}
	outstr[ox] = 0;

	max = total = 0;
	min = 1000000;
	ix = 0;


	sleep(iwait);
	fs = fdopen(ifd,"r");
	for( oi = 0; outstr[oi]; oi++ ){
		sleep(1);
		IGNRETP write(ofd,&outstr[oi],1);
		ss = Time();
		do {
			ic = getc(fs);
			ix++;
			ds = Time();
			rtt = (ds - ss) * 1000;
			buf[0] = ic;
			fprintf(stderr,"[%f] put:%02X get:%02X %f ms\n",
				ds,outstr[oi],buf[0],rtt);
			total += rtt;
			if( max < rtt ) max = rtt;
			if( rtt < min ) min = rtt;
			if( ic == EOF )
				break;
		} while( 0 < fPollIn(fs,1) );
	}
	fprintf(stderr,"min/ave/max: %f/%f/%f ms\n",min,total/ix,max);
	return 0;
}
#ifdef MAIN
main(ac,av)
	char *av[];
{
	exit(dping_main(ac,av));
}
#endif
