/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2004-2010 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	modfmt.c (%ll portability)
Author:		Yutaka Sato <ysato@delegate.org>
Description:
History:
	100129	extracted from ystring.ccreated

TODO:
//////////////////////////////////////////////////////////////////////#*/
#include "ystring.h"

/*
 * "%lld" is used only for FileSize
 * it is replaced with "%I64d" for VC++
 * it is replaced with "%d" when FileSize is not long long
 */

#if defined(__FreeBSD__) && __FreeBSD__ <= 4
#define useQuad 1
#else
#define useQuad 0
#endif

#ifdef _MSC_VER
#define isWin 1
#else
#define isWin 0
#endif

#define LongFileSize	(sizeof(int) < sizeof(FileSize))

#if NO_LL_FMT \
 || defined(__osf__) && defined(__alpha) && defined(_LONGLONG)
#define NO_ll_FMT 1
#else
#define NO_ll_FMT 0
#endif
int NO_ll_Fmt(){
	if( NO_ll_FMT )
		return 1;
	return 0;
}

int modifyFmt(PCStr(fmt),PVStr(xfmt),int xsiz){
	const char *tp = &xfmt[xsiz-1];
	char fc;
	const char *fp;
	const char *sp;
	char *xp;

	if( NO_ll_Fmt() ){
	}else
	if( !useQuad )
	if( !isWin && LongFileSize )
		return 0;

	xp = 0;
	for( fp = fmt; fc = *fp; ){
		if( fc == '%' ){
			if( xp ){
				if( tp <= xp+1 ) goto OVF;
				*xp++ = fc;
			}
			for( fp++; fc = *fp; fp++ ){
				if( fc != '*' )
				if( fc != '-' && !('0' <= fc && fc <= '9') ){
					break;
				}
				if( xp ){
					if( tp <= xp+1 ) goto OVF;
					*xp++ = fc;
				}
			}
			if( fp[0] == 'l' && fp[1] == 'l' ){
				if( xp == NULL ){
					xp = (char*)xfmt;
					for( sp = fmt; sp < fp; sp++ ){
						if( tp <= xp+1 ) goto OVF;
						*xp++ = *sp;
					}
				}
				if( tp <= xp+3 ) goto OVF;
				if( NO_ll_Fmt() ){
					*xp++ = 'l';
				}else
				if( useQuad ){
					*xp++ = 'q';
				}else
				if( isWin && LongFileSize ){
					*xp++ = "I64"[0];
					*xp++ = "I64"[1];
					*xp++ = "I64"[2];
				}
				fp += 2;
				continue;
			}
		}
		if( xp ){
			if( tp <= xp+1 ) goto OVF;
			*xp++ = fc;
		}
		fp++;
	}
	if( xp ){
		*xp = 0;
		return 1;
	}
	return 0;
OVF:
	return 0;
}

int ll2iX(FL_PAR,Int64 ll){
	return (int)ll;
}
