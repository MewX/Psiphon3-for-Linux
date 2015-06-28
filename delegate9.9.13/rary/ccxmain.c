/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1998 Electrotechnical Laboratry (ETL), AIST, MITI

Permission to use, copy, modify, and distribute this material 
for any purpose and without fee is hereby granted, provided 
that the above copyright notice and this permission notice 
appear in all copies, and that the name of ETL not be 
used in advertising or publicity pertaining to this 
material without the specific, prior written permission 
of an authorized representative of ETL.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY 
OF THIS MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", 
WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	ccxmain.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	980529	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
int ccx_main(int ac,const char *av[]);
int main(int ac,char *av[]){ return ccx_main(ac,(const char**)av); }
