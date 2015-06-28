#include <stdlib.h>
#include "ystring.h"

static int _isSolaris;
int IsSolaris(){
	CStr(uname,128);

	if( _isSolaris == 0 ){
		_isSolaris = -1;
		if( getenv("ImNotSolaris") == 0 )
		if( Uname(AVStr(uname)) == 0 )
		if( strncmp(uname,"SunOS/",6) == 0 && '5' <= uname[6] )
			_isSolaris = 1;
	}
	return 0 < _isSolaris;
}

static int _isBOW1_5;
int IsBOW1_5()
{	CStr(uname,128);

	if( _isBOW1_5 == 0 ){
		_isBOW1_5 = -1;
		if( Uname(AVStr(uname)) == 0 )
		if( strstr(uname,"BSD-BOW") )
			_isBOW1_5 = 1;
	}
	return 0 < _isBOW1_5;
}

static int _isWindows95;
int IsWindows95(){
	CStr(uname,128);

	if( _isWindows95 == 0 ){
		_isWindows95 = -1;
		if( Uname(AVStr(uname)) == 0 )
		if( strcmp(uname,"Windows95") == 0 )
			_isWindows95 = 1;
	}
	return 0 < _isWindows95;
}

static int _isMacOSX;
int IsMacOSX(){
	CStr(uname,128);

	if( _isMacOSX == 0 ){
		_isMacOSX = -1;
		if( Uname(AVStr(uname)) == 0 )
		if( strncmp(uname,"Darwin/",7) == 0 )
			_isMacOSX = 1;
	}
	return 0 < _isMacOSX;
}

#ifdef __EMX__
int IsOS2EMX(){ return 1; }
#else
int IsOS2EMX(){ return 0; }
#endif

#if defined(__sony_news) && defined(_SYSTYPE_SYSV)
#define ACCEPT_EXCLUSIVE	1
#else
#define ACCEPT_EXCLUSIVE	0
#endif

int acceptExclusive()
{
	if( IsSolaris() || IsBOW1_5() )
		return 1;
	else	return ACCEPT_EXCLUSIVE;
}
