/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1995-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2006 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	strid.c (NNTP proxy)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	951211	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "ystring.h"

static struct { defQStr(gnstrbuff); } gnstrbuff;
static int gnstrsize;
static int gnstridx;
static int gnstrtotal;
static int gnstrrem;
static char *newStr(PCStr(group))
{	int len;
	defQStr(strp); /*alloc*//**/

	len = strlen(group) + 1;
	if( gnstrsize <= gnstridx+len ){
		gnstrrem += gnstrsize - gnstridx;
		gnstrsize = 0x8000;
		setQStr(gnstrbuff.gnstrbuff,(char*)StructAlloc(gnstrsize),gnstrsize);
		gnstridx = 0;
		gnstrtotal += gnstrsize;
	}
	strp = (char*)&gnstrbuff.gnstrbuff[gnstridx];
	Xstrcpy(QVStr(strp,gnstrbuff.gnstrbuff),group);
	gnstridx += len;
	return (char*)strp;
}
static int s_new,s_full,s_dup,s_uni;

void strid_stat(int tab)
{
	syslog_DEBUG("Strid NEW:%d FULL:%d UNI:%d DUP:%d\n",
		s_new,s_full,s_uni,s_dup);
}

#define NULLVAL	((char*)-1)

int strid_create(int nelem)
{	int htid;

	htid = Hcreate(nelem,NULLVAL);
	return htid;
}
long int stridX(int tab,PCStr(str),long int id,const char **rkey);
long int strid(int tab,PCStr(str),long int id)
{
	return stridX(tab,str,id,NULL);
}
long int stridX(int tab,PCStr(str),long int id,const char **rkey)
{	const char *sid;
	const char *key;

	if( tab <= 0 )
	{
		if( rkey ) *rkey = 0;
		return id;
	}

	sid = Hsearch(tab,str,NULLVAL);
	if( sid != NULLVAL ){
		if( (long int)sid == id )
			s_uni++;
		else	s_dup++;
		if( rkey ) *rkey = 0;
		return (long int)sid;
	}
/*
	if( Hsearch(tab,newStr(str),(char*)id) != NULLVAL )
*/
	key = newStr(str);
	if( Hsearch(tab,key,(char*)id) != NULLVAL )
		s_new++;
	else	s_full++;

	if( rkey ) *rkey = key;
	return id;
}
int strid_next(int tab,int hx,const char **strp,int *idp)
{
	return Hnext(tab,hx,strp,(const char**)idp);
}
const char *strid_find(int tab,int hx,int id)
{	int nhx,id1;
	const char *str;

	for( hx = 0; ; hx = nhx ){
		nhx = strid_next(tab,hx,&str,&id1);
		if( nhx < 0 )
			break;
		if( str == NULL )
			break;
		if( id1 == id ){
			return str;
		}
	}
	return 0;
}

static int _strid;
const char *strid_alloc(PCStr(str)){
	const char *key;

	if( _strid == 0 )
		_strid = strid_create(128);
	key = Hsearch(_strid,str,NULLVAL);
	if( key == NULLVAL ){
		key = newStr(str);
		Hsearch(_strid,(char*)key,(char*)key);
	}
	return key;
}
