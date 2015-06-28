/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1995 Electrotechnical Laboratry (ETL), AIST, MITI

Permission to use, copy, modify, and distribute this material for any
purpose and without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies, and
that the name of ETL not be used in advertising or publicity pertaining
to this material without the specific, prior written permission of an
authorized representative of ETL.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	utmpident.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	951030	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <utmp.h>
#include "ystring.h"
#define UTMPFILE "/etc/utmp"

utmpident(int clienthost,PVStr(username))
{	FILE *utmpf;
	struct utmp utmpb;
	CStr(puser,9);
	CStr(user,9);
	CStr(host,17);
	const char *dp;
	int users;

	puser[0] = 0;
	users = 0;

	utmpf = fopen(UTMPFILE,"r");
	while( fread(&utmpb,1,sizeof(utmpb),utmpf) ){
		if( utmpb.ut_name[0] == 0 )
			continue;
		strncpy(host,utmpb.ut_host,16); setVStrEnd(host,16);
		if( dp = strchr(host,':') )
			truncVStr(dp);
		if( clienthost == gethostint_nbo(host) ){
			strncpy(user,utmpb.ut_name,8); setVStrEnd(user,8);

fprintf(stderr,"%x %x\n",clienthost,gethostint_nbo(host));

			if( puser[0] && strcmp(user,puser) != 0 ){
				users = 2;
				break;
			}
			users = 1;
			strcpy(puser,user);
		}
	}

	fclose(utmpf);
	strcpy(username,puser);
	return users == 1;
}
