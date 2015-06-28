/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1997 Electrotechnical Laboratry (ETL), AIST, MITI

Permission to use, copy, modify, and distribute this material for any
purpose and without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies, and
that the name of ETL not be used in advertising or publicity pertaining
to this material without the specific, prior written permission of an
authorized representative of ETL.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	cafe.c (Cache file expirer)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970703	created
//////////////////////////////////////////////////////////////////////#*/
main(ac,av)
	char *av[];
{
	return cafe_main(ac,av);
}
Finish(rcode){ exit(rcode); }
syslog_ERROR(){ }
syslog_DEBUG(){ }
int LOG_type;
