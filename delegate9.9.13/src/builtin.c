/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato
Copyright (c) 1994-2000 Electrotechnical Laboratory (ETL), AIST, MITI
Copyright (c) 2001 National Institute of Advanced Industrial Science and Technology (AIST)

Permission to use, copy, and distribute this material for any purpose
and without fee is hereby granted, provided that the above copyright
notice and this permission notice appear in all copies.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
////////////////////////////////////////////////////////////////////////*/
#include "ystring.h"

/*
#define DEBUG 1
*/
#include "bldsign.h"
#include "_builtin.c"

#if defined(__hpux__) || defined(hpux)
#ifdef __cplusplus
extern "C" void allow_unaligned_data_access();
#else
void allow_unaligned_data_access();
#endif
static void hpuxsetup(){
	allow_unaligned_data_access();
}
#else
#define hpuxsetup()
#endif

static void showaddrs();
void mainX(int ac,const char *av[]);
int main(int ac,char *av[])
{
	hpuxsetup();
	showaddrs();
	mainX(ac,(const char**)av);
	return 0;
}

#ifndef BUILT_SRCSIGN
#define BUILT_SRCSIGN ""
#endif
const char *DELEGATE_bldsign(){
	return BUILT_SRCSIGN;
}

#ifdef DEBUG
#include "../../checktext.c"
#else
static void showaddrs(){}
#endif

#ifndef WINSERVDGROOT
#define WINSERVDGROOT	"delegate"
#endif
const char *WINSERV_DGROOT(){
	return WINSERVDGROOT; 
}

#ifndef ADMINPASS
#define ADMINPASS 0
#endif
const char *get_builtin_ADMINPASS(){
	return ADMINPASS;
}
int get_builtin_MADE_TIME(){
	return MADE_TIME;
}

const char *get_builtin_data(PCStr(name),int *sizep,int *datep)
{	int i;
	const char *file1;
	const char *name1;
	const char *data1;
	IStr(head,32);

	for(i = 0; file1 = get_builtin_file(i); i++){
		name1 = file1 + 16;
		if( strcmp(name,name1) == 0 ){
			data1 = name1 + strlen(name1) + 1;
			bcopy(file1,head,16);
			setVStrEnd(head,16);
			/* fix-140504e ... this string is  generated in embed.c as
			   %-8x%-8x%s where %s starts with "builtin/ ..." thus
			   the date value is postfixed with "0xb" and overflows 32bits
			sscanf(file1,"%x %x",sizep,datep);
			*/
			sscanf(head,"%x %x",sizep,datep);
			return data1;
		}
	}
	return 0;
}
void scan_builtin_data(PCStr(name),int (*func)(const void*,...),PCStr(arg1),PCStr(arg2))
{	const char *file1;
	const char *name1;
	const char *data1;
	int i,size1,date1;

	for(i = 0; file1 = get_builtin_file(i); i++){
		name1 = file1 + 16;
		if( strstr(name1,name) ){
			data1 = name1 + strlen(name1) + 1;
			sscanf(file1,"%x %x",&size1,&date1);
			(*func)(name1,data1,size1,arg1,arg2);
		}
	}
}
FILE *dirfopen(PCStr(what),PVStr(file),PCStr(mode));
const char *ACTDIR();
const char *dump_builtin_data(PCStr(name),PVStr(path)){
	FILE *fp;
	const char *data;
	int size,date;

	data = get_builtin_data(name,&size,&date);
	if( data == 0 ){
		return 0;
	}
	if( path[0] == 0 )
	sprintf(path,"%s/builtin-data/%s",ACTDIR(),name);
	if( fp = fopen(path,"r") ){
		fclose(fp);
		return path;
	}
	if( fp = dirfopen("builtin-data",AVStr(path),"w") ){
		fwrite(data,1,size,fp);
		fclose(fp);
		/* setutime? */
		return path;
	}
	return 0;
}
