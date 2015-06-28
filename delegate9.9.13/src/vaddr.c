/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1999 Electrotechnical Laboratry (ETL), AIST, MITI
Copyright (c) 1999 Yutaka Sato

Permission to use, copy, and distribute this material for any purpose
and without fee is hereby granted, provided that the above copyright
notice and this permission notice appear in all copies.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
//////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	vaddr.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

	Virtual and Universal Address for Applications.

History:
	991119	created
//////////////////////////////////////////////////////////////////////#*/
#include "ystring.h"
#include "vaddr.h"

#define F4	0xFFFFFFFF

VAddr AddrZero = { {0}, 0,0,0, {  0,  0,  0,  0 } };
VAddr AddrNull = { {0}, 0,0,0, { F4, F4, F4, F4 } };
VAddr MaskZero = { {0}, 0,0,0, { F4, F4, F4,  0 } };

