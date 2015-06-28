/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2010 National Institute of Advanced Industrial Science and Technology (AIST)

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
Program:	regex.c (regex DLL for Windows)
Author:		Yutaka Sato <ysato@delegate.org>
Description:
History:
	101004	created
//////////////////////////////////////////////////////////////////////#*/
#include "ystring.h"
#include "dglib.h"

/*BEGIN_STAB(regex)*/
#ifdef __cplusplus
extern "C" {
#endif
#ifdef __cplusplus
}
#endif
/*END_STAB*/


int dl_library(const char *libname,DLMap *dlmap,const char *mode);
static int regex_dlstat;
int regex_lib_init(){
	if( regex_dlstat < 0 ){
		return -2;
	}
	if( regex_dlstat == 0 ){
		int code;
		code = dl_library("regex-spencer",dlmap_regex,"");
		if( code != 0 ){
			regex_dlstat = -1;
			return -1;
		}
		regex_dlstat = 1;
	}
	return 0;
}

