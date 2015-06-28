/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2002 National Institute of Advanced Industrial Science and Technology (AIST)

Permission to use, copy, and distribute (via publically accessible
on-line media) this material for any purpose and without fee is hereby
granted, provided that the above copyright notice and this permission
notice appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	htswitch.h
Author:		Yutaka Sato <ysato@delegate.org>
Description:
History:
	020914	created
//////////////////////////////////////////////////////////////////////#*/
typedef struct htswitch {
  const	char   *s_requrl; /* requesting URL (as the query part) */
  const	char   *s_reqcmd; /* label of value in request body */
  const	char   *s_blabel; /* label on the submitt button */
  const char   *s_bcmmnt; /* comment on the button */
  const	char   *s_ctlurl; /* control URL (as the query part) */
  const	char   *s_swdesc; /* description */
	int	s_maxage; /* max age of the cookie */
struct htswitch *s_ctlsw; /* upper HtSwitch which contains this one */

	int	s_ison;	/* the switch is enabled currently (in request) */
	int	s_beon; /* to be enabled by this response */
	int	s_doset; /* send Set-Cookie in response */
	MStr(	s_key,32); /* the key value in POSTbody (possible in GETurl) */
} HtSwitch;

#define SW_MIS	0 /* not matched */
#define SW_RET	1 /* invocation button matched, and cookie OK */
#define SW_GOT	2 /* invocation button matched, but cookie NG */
#define SW_SET	3 /* on/off button matched */
