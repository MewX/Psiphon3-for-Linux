/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2003 National Institute of Advanced Industrial Science and Technology (AIST)

Permission to use this material for evaluation, copy this material for
your own use, and distribute the copies via publically accessible on-line
media, without fee, is hereby granted provided that the above copyright
notice and this permission notice appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	dgbind.c
Author:		Yutaka Sato <ysato@delegate.org>
Description:

    INSTALL:
	% cc -o dgbind dgbind.c ../lib/lib*.a
	% cp -p dgbind ${DGROOT}/lib
	% cd ${DGROOT}/lib
	% su
	# chown root dgbind
	# chgrp Group dgbind
	# chmod 6550 dgbind

      where Group is the group ID of the user to be permitted to execute
      this program, which is specified in a DeleGate parameter as
          OWNER=User/Group 

History:
	030117	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <errno.h>
#include "dgxauth.c"
#include <sys/socket.h>
typedef struct VSAddr VSAddr;
int VSA_atosa(VSAddr *sa,int port,PCStr(addr));
int VSA_af(VSAddr *sap);
const char *VSA_ntoa(VSAddr *sap);
int sock_isv6(int sock);

int main(int ac,char *av[])
{	int addr[32],sock,port,leng,rcode;
	const char *host;
	int serrno;

	dgxauth(ac,av);
	if( ac < 3 ){
		fprintf(stderr,"ERROR: Usage: %s sock port [host]\n",av[0]);
		exit(-1);
	}
	sock = atoi(av[1]);
	port = atoi(av[2]);
	if( 3 < ac )
		host = av[3];
	else	host = "0.0.0.0";

	leng = VSA_atosa((VSAddr*)addr,port,host);
	errno = 0;
	rcode = bind(sock,(struct sockaddr*)addr,leng);
	serrno = errno;
	if( rcode < 0 )
	{
		fprintf(stderr,"-- ERROR [%d] bind(%s:%d) = %d, errno=%d\n",
			getpid(),host,port,rcode,serrno);
		fprintf(stderr,"-- ERROR [%d] sock=%d/%s %s af=%d leng=%d\n",
			getpid(),sock,sock_isv6(sock)?"IPv6":"IPv4",
			VSA_ntoa((VSAddr*)addr),VSA_af((VSAddr*)addr),leng);
		if( serrno ){
			return serrno;
		}
	}
	return rcode;
}
