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
Program:      str_stdio.h
Author:       Yutaka Sato <ysato@etl.go.jp>
Description:

     This program redirects the file I/O from/to strings on memory.
     Include "str_stdio.h" instead of <stdio.h>

History:
	92.05.18   created
//////////////////////////////////////////////////////////////////////#*/

#include <stdio.h>
#undef getc
#undef putc
#undef fflush
#undef fprintf

#define getc(file)		str_fgetc(file)
#define fgetc(file)		str_fgetc(file)
#define ungetc(ch,file)		str_fungetc(ch,file)
#undef fgets
#define fgets(buf,size,file)	str_fgets(AVStr(buf),size,file)
#define putc(ch,file)		str_fputc(ch,file)
#define fputc(ch,file)		str_fputc(ch,file)
#define fputs(buf,file)		str_fputs(buf,file)
#define fflush(file)		str_fflush(file)
#define fseek(file,off,where)	str_fseek(file,off,where)
#define ftell(file)		str_ftell(file)
#undef fclose
#define fclose(file)		str_fclose(file)

#define fprintf			str_fprintf
