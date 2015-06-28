/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2014 National Institute of Advanced Industrial Science and Technology (AIST)
AIST-Product-ID: H18PRO-443

Permission to use this material for noncommercial and/or evaluation
purpose, copy this material for your own use,
without fee, is hereby granted
provided that the above copyright notice and this permission notice
appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
//////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	winmisc.c
Author:		Yutaka Sato <y.sato@aist.go.jp>
Description:
History:
	140627	created (v9.9.10 new-140626g)
//////////////////////////////////////////////////////////////////////#*/

#ifndef _MSC_VER
#else

#include <iostream>
#include <string>
#include <windows.h>
#include "ystring.h"
using namespace std;
int File_is(PCStr(path));

typedef struct _ttyMode {
	DWORD	t_mode;      /* MS Console: GetConsoleMode */
	MStr(	t_stat,120); /* Cywin Console: stty -g */
} TtyMode;

static const char *sttypath(PVStr(path)){
	const char *exe[] = {
		"c:\\cygwin\\bin\\stty.exe",
		"d:\\cygwin\\bin\\stty.exe",
		"stty.exe",
		0
	};
	int ei;
	for( ei = 0; exe[ei]; ei++ ){
		if( File_is(exe[ei]) ){
			strcpy(path,exe[ei]);
		}
	}
	strcpy(path,"stty.exe");
	return path;
}
static int rsystem(PCStr(command),PVStr(result),int rsize){
	FILE *pfp;
	int rcc;

	setVStrEnd(result,0);
	if( pfp = popen(command,"r") ){
		rcc = fread((void*)result,1,rsize-1,pfp);
		setVStrEnd(result,rcc);
		fclose(pfp);
		return 0;
	}
	return -1;
}
static int fstty(PVStr(result),int rsize,PCStr(arg)){
	IStr(exe,256);
	IStr(command,256);
	int rcode;

	sttypath(AVStr(exe));
	sprintf(command,"%s %s",exe,arg);
	rcode = rsystem(command,BVStr(result),rsize);
	return rcode;
}

void *windumpTTyStat(FILE *infp,PVStr(stat),int ssiz){
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	/*
	HANDLE hStdin = (HANDLE)_get_osfhandle(fileno(infp)); // does not work with Windows Application
	*/
	DWORD mode = 0;
	IStr(cstat,256);
	TtyMode *tMode = (TtyMode*)stat;

	if( ssiz < sizeof(TtyMode) ){
		return 0;
	}
	bzero(tMode,sizeof(TtyMode));
	if( GetConsoleMode(hStdin,&mode) ){
		/* MS Console */
		tMode->t_mode = mode;
	}else{
		/* Cygwin Console */
		fstty(AVStr(cstat),sizeof(cstat),"-g");
		Xsscanf(cstat,"%[^\r\n]",AVStr(tMode->t_stat));
	}
	return tMode;
}

int winsetTTyStat(FILE *infp,void *ttyStat,const char *strStat){
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	/*
	HANDLE hStdin = (HANDLE)_get_osfhandle(fileno(infp));
	*/
	TtyMode *tMode = (TtyMode*)ttyStat;
	DWORD mode = 0;
	IStr(cstat,256);

	if( ttyStat == 0 ){
		return -1;
	}
	if( GetConsoleMode(hStdin,&mode) )
	if( SetConsoleMode(hStdin,mode & ~(ENABLE_ECHO_INPUT|ENABLE_LINE_INPUT)) ){
		tMode->t_mode = mode;
		return mode;
	}
	fstty(AVStr(cstat),sizeof(cstat),strStat);
	return 0;
}

int winrestoreTTyStat(FILE *infp,void *ttyStat){
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	/*
	HANDLE hStdin = (HANDLE)_get_osfhandle(fileno(infp));
	*/
	TtyMode *tMode = (TtyMode*)ttyStat;
	IStr(cstat,256);

	if( ttyStat == 0 ){
		return -1;
	}
	if( tMode->t_mode != 0 ){
		SetConsoleMode(hStdin,tMode->t_mode);
	}else{
		fstty(AVStr(cstat),sizeof(cstat),tMode->t_stat);
	}
	return 0;
}

#endif
