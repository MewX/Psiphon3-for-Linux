/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2005 National Institute of Advanced Industrial Science and Technology (AIST)

Permission to use this material for evaluation, copy this material for
your own use, and distribute the copies via publically accessible on-line
media, without fee, is hereby granted provided that the above copyright
notice and this permission notice appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
//////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	tsp.c (Time Stamp Protocol)
Author:		Yutaka Sato <ysato@delegate.org>
Description:

History:
	050504	created
//////////////////////////////////////////////////////////////////////#*/
#include "delegate.h"

int service_tsp(Connection *Conn)
{
	return 0;
}

int req1(PCStr(host),int port){
	int sock;
	FILE *ts,*fs;
	int ch;

	fprintf(stderr,"------------ %s %d\n",host,port);
	sock = client_open("TSP","TSP",host,port);
	if( sock < 0 )
		return -1;

	ts = fdopen(sock,"w");
	fs = fdopen(sock,"r");

	putc(0,ts); putc(0,ts); putc(0,ts); putc(0,ts);
	putc(0,ts);
	fflush(ts);

	for(;;){
		ch = getc(fs);
		if( ch == EOF ){
			break;
		}
		if( 0x20 <= ch && ch < 0x7F )
			fprintf(stderr,"%c",ch);
		else	fprintf(stderr,"[%X]",ch);
	}
	fprintf(stderr,"\n");
	fclose(ts);
	fclose(fs);
	return 0;
}
int tsp_main(int ac,const char *av[]){
	req1("xxx.xxx.xxx",318);
	return 0;
}
