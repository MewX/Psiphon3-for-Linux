#include "vsocket.h"

int RecvOOB(int sock,void *buf,int len)
{
	((char*)buf)[0] = 0;
	return recv(sock,(char*)buf,len,MSG_OOB);
}
/*
int RecvPeek(int sock,void *buf,int len)
*/
#define RecvPeek(s,b,l) RecvPeek_FL(s,b,l,FL_ARG)
int RecvPeek_FL(int sock,void *buf,int len,FL_PAR)
{
	((char*)buf)[0] = 0;
#ifdef __APPLE__
	return recvDarwin(sock,(char*)buf,len,MSG_PEEK,FL_BAR);
#else
	return recv(sock,(char*)buf,len,MSG_PEEK);
#endif
}

int RecvLine(int sock,void *vbuf,int len)
{	int rcc,ci;
	char *buf = (char*)vbuf;

	rcc = RecvPeek(sock,buf,len-1);
	if( 0 < rcc ){
	    for( ci = 0; ci < rcc; ci++ ){
		if( buf[ci] == '\n' ){
			ci++;
			recv(sock,buf,ci,0);
			buf[ci] = 0;
			return ci;
		}
	    }
	}
	for( ci = 0; ci < len-1; ci++ ){
		if( read(sock,&buf[ci],1) <= 0 )
			break;
		if( buf[ci] == '\n' ){
			ci++;
			break;
		}
	}
	buf[ci] = 0;
	return ci;
}
