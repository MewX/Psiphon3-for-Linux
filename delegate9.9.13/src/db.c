/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994 Electrotechnical Laboratry (ETL), AIST, MITI

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
Program:	db.c (DataBase Manager)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	941016	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "ystring.h"
#include "vsignal.h"
#include "vsocket.h"
#include "dglib.h"
#include "fpoll.h"

int DBmanager(int clsock,FILE *db)
{	int oseq,seq;
	int odate,count;
	int off,found;
	CStr(data,0x8000);
	CStr(db1,0x8000);

	seq = 0;
	while( 0 < recv(clsock,data,sizeof(data),0) ){
		seq++;
		found = 0;

		fseek(db,0,0);
		for(;;){
			off = ftell(db);
			if( fgets(db1,sizeof(db1),db) == NULL )
				break;

/* if it is a super set of original, replace it */
/* if it is a subset of original, replace it / ignore it ? */

			if( strcmp(db1+27,data) == 0 ){
				found = 1;
				break;
			}
		}

		if( found ){
			fseek(db,off,0);
			sscanf(db1,"%d %d %x",&count,&oseq,&odate);
		}else	count = 0;

		fprintf(db,"%08d %08d %08x ",count+1,seq,itime(0));

		if(!found )
			fputs(data,db);
		fflush(db);
	}
	return 0;
}
void static DBtimeout()
{
	Finish(-1);
}
void DBstore(int svsock,PCStr(key),PCStr(val))
{	CStr(buf,0x8000);
	int timer;
	int wcc;

	sprintf(buf,"%s=%s\n",key,val);
	timer = pushTimer("DBstore",(vfuncp)DBtimeout,10);
	wcc = send(svsock,buf,strlen(buf)+1,0);
	popTimer(timer);
	set_linger(svsock,10);
}
