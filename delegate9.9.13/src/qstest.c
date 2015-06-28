/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2009 National Institute of Advanced Industrial Science and Technology (AIST)
AIST-Product-ID: 2000-ETL-198715-01, H14PRO-049, H15PRO-165, H18PRO-443

Permission to use this material for noncommercial and/or evaluation
purpose, copy this material for your own use, and distribute the copies
via publicly accessible on-line media, without fee, is hereby granted
provided that the above copyright notice and this permission notice
appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	qstest.c (testing -DQS and -DQSC)
Author:		Yutaka Sato <y.sato@delegate.org>
Description:
History:
	091120	created
//////////////////////////////////////////////////////////////////////#*/

#ifdef NONE
#include <stdio.h>
int QStest_main(int ac,const char *av[]){
	printf("qstest: not available, compilation error\n");
	return 0;
}
#else
#include "ystring.h"
static void sub2(PVStr(b1),PVStr(b2)){
	printf("--size: %d %d\n",VStrSIZE(b1),VStrSIZE(b2));
	strcpy(b1,"0123456789");
	Xstrcpy(BVStr(b1),"0123456789");
	strcpy(b2,"0123456789");
	Xstrcpy(BVStr(b2),"0123456789");
}
static void sub1(PVStr(b1),PVStr(b2)){
	strcpy(b1,"0123456789");
	Xstrcpy(BVStr(b1),"0123456789");
	strcpy(b2,"0123456789");
	Xstrcpy(BVStr(b2),"0123456789");
	sub2(BVStr(b1),BVStr(b2));
}
int QStest_main(int ac,const char *av[]){
	IStr(buf,4);
	struct { MStr(buf,3); } st1;
	struct { char a[ASIZ0]; char b[3]; char c[ASIZ0]; } st2;
	struct { char a[ASIZ0]; char b[3]; char *c[ASIZ0]; } st3;

	strcat(buf,"0123456789");
	strcpy(buf,"0123456789");
	sprintf(buf,"%s","0123456789");
	Xsscanf("0123456789","%s",AVStr(buf));

	strcpy(st1.buf,"0123456789");
	printf("--VStrSIZE: %d / %d / %d\n",isizeof(st1.buf),
		(int)VStrSIZE(st1.buf),(int)sizeof(st1));
	printf("--disp: %d / %d / %d\n",
		(int)((char*)st2.a-(char*)&st2),
		(int)((char*)st2.b-(char*)&st2),
		(int)((char*)st2.c-(char*)&st2)
	);
	printf("--disp: %d / %d / %d\n",
		(int)((char*)st3.a-(char*)&st3),
		(int)((char*)st3.b-(char*)&st3),
		(int)((char*)st3.c-(char*)&st3)
	);
	sub1(AVStr(buf),AVStr(st1.buf));
	return 0;
}
#endif
