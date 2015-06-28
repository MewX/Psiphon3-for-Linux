/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1992 Electrotechnical Laboratry (ETL)

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
Content-Type: program/C; charset=US-ASCII
Program:      mimeh_ovw.c
Author:       Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	921116	extracted from mmsencode.c
//////////////////////////////////////////////////////////////////////#*/

#include "mime.h"
int MIME_headerCodecOverwrite(FILE *file,int encode);

/*/////////////////////////////////////////////////////////////////////#*/
/*
 *	MIME-decode a given "file" and overwrite it with the result.
 */
int MIME_headerDecodeOverwrite(FILE *file)
{
	return MIME_headerCodecOverwrite(file,0);
}
int MIME_headerEncodeOverwrite(FILE *file)
{
	return MIME_headerCodecOverwrite(file,1);
}

static int filesize(FILE *fp)
{	int size;
	int pos;

	pos = ftell(fp);
	fseek(fp,0,2);
	size = ftell(fp);
	fseek(fp,pos,0);
	return size;
}
int MIME_headerCodecOverwrite(FILE *file,int encode)
{	const char *buf;
	int scc,dcc;
	int pos;
	FILE *temp;

	/*
	 *	make a pseudo file "temp" on memory with size of "file"
	 */
	scc = filesize(file);
	if( encode ) scc = scc * 2; /*X-<, str_file should be extensible*/
	buf = (char*)malloc(scc+2);
	temp = (FILE*)str_fopen((char*)buf,scc,"w");

	/*
	 *	decode "file" into "temp"
	 */
	pos = ftell(file);
	if( encode )
		MIME_headerEncode(file,temp);
	else	MIME_headerDecode(file,temp,1);
	dcc = str_ftell(temp);

	/*
	 *	write back "temp" to "file"
	 */
	fseek(file,pos,0);
	fwrite(buf,1,dcc,file);
	if( !str_isStr(file) )
		Ftruncate(file,dcc,0);
	fseek(file,pos,0);
	free((char*)buf);
	return 0;
}
