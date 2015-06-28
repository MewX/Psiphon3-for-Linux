/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1996 Electrotechnical Laboratry (ETL), AIST, MITI

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
Program:	delegated (DeleGate Server)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	960416	created
//////////////////////////////////////////////////////////////////////#*/

#include <fcntl.h>
#include <stdio.h>
#include <ctype.h>
#include "ystring.h"
#include <ndbm.h>

main(ac,av)
	char *av[];
{	char *file;
	CStr(line,0x8000);
	DBM *db;
	int eid;

	if( (file = getenv("WWWLOG")) == NULL )
		file = "/usr/tmp/wwwlog";
	fprintf(stderr,"WWWLOG=%s\n",file);

	db = dbm_open(file,O_RDWR|O_CREAT,0644);
	if( db == NULL )
		return -1;

	if( 1 < ac && strncmp(av[1],"-d",2) == 0 ){
		dump(db,&av[1][2]);
		return 0;
	}

	eid = cardinal(db);
	while( fgets(line,sizeof(line),stdin) ){
		if( put1(db,eid,line) )
			eid++;
		/* if hour changed, rotate */
	}
	return 0;
}

cardinal(db)
	DBM *db;
{	int nent;
	datum data;

	data = dbm_firstkey(db);
	for( nent = 0; data.dptr != NULL; nent++ )
		data = dbm_nextkey(db);
	return nent;
}

dump(db,opt)
	DBM *db;
	char *opt;
{	datum key,data;
	int ser,cnt,cum,dx;

	key = dbm_firstkey(db);
	ser = 0;
	cum = 0;

	while( key.dptr != NULL ){
		data = dbm_fetch(db,key);
		if( data.dptr == NULL )
			break;
		ser += 1;
		cum += (cnt = atoi(data.dptr));
/*
		fprintf(stdout,"%8d %s %s\n",cum,data.dptr,key.dptr);
*/
		if( opt[0] == 'h' ){
			char *dp;
			CStr(hostport,128);

			if( dp = strstr(key.dptr,"//") ){
				Xsscanf(dp+2,"%[^/]",AVStr(hostport));
				for( dx = 0; dx < cnt; dx++ )
					fprintf(stdout,"%s\n",hostport);
			}
		}else{
			fprintf(stdout,"%s %s\n",data.dptr,key.dptr);
		}
		key = dbm_nextkey(db);
	}
	fprintf(stderr,"entry=%d cum=%d\n",ser,cum);
}

put1(db,eid,line)
	DBM *db;
	char *line;
{	datum key,odata,ndata;
	CStr(path,1024);
	char *porg;
	CStr(mtime,4096);
	CStr(url,4096);
	CStr(keys,4096);
	char *sp;
	char ch;
	CStr(sdata,4096);
	CStr(omtime,128);
	int count,new;

	new = 0;
	if( Xsscanf(line,"%s %*s %s %*s %s",AVStr(path),AVStr(mtime),AVStr(url)) != 3 ){
		fprintf(stderr,"? %s",line);
		return 0;
	}
	if( porg = strchr(path,'#') )
		porg = porg + 1;
	else	porg = path;

	if( sp = strstr(path,"://") ){
		while( ch = *sp ){
			if( ch != '/' )
				break;
			if( isupper(ch) )
				*sp = tolower(ch);
		}
	}

	if( sp = strrchr(url,'"') )
		if( sp[1] == 0 )
			*sp = 0;

	sprintf(keys,"%s %s",porg,url);
	key.dptr = keys;
	key.dsize = strlen(keys)+1;
	odata = dbm_fetch(db,key);

	if( odata.dptr == NULL ){
		new = 1;
		count = 0;
	}else{
		Xsscanf(odata.dptr,"%d %s",&count,AVStr(omtime));
		if( 0 < strcmp(omtime,mtime) )
			strcpy(mtime,omtime);
	}
	count += 1;
	sprintf(sdata,"%06d %s",count,mtime);
	fprintf(stderr,"%8d %4d %-10s %s %s\n",eid,count,porg,mtime,url);

	ndata.dptr = sdata;
	ndata.dsize = strlen(sdata)+1;
	dbm_store(db,key,ndata,DBM_REPLACE);
	return new;
}
