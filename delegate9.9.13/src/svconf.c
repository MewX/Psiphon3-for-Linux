/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1996-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2006 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	svconf.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	961029	extracted from service.c
//////////////////////////////////////////////////////////////////////#*/

#include "ystring.h"
#include "service.h"

extern char SERV_HTTP[];

servFunc service_ftp;
servFunc service_ftps;
servFunc service_telnet;
servFunc service_gopher;
servFunc service_http;
servFunc service_https;
servFunc service_ftpxhttp;
servFunc service_ftpxhttps;
servFunc service_nntp;
servFunc service_delegate;
servFunc service_imap;
servFunc service_pop;
servFunc service_smtp;
servFunc service_smtps;
servFunc service_X;
servFunc service_XSFlash;
servFunc service_XCFlash;
servFunc2 service_Y11;
servFunc2 service_yymux;
servFunc2 service_yysh;
servFunc service_wais;
servFunc service_whois;
servFunc2 service_domain;
servFunc service_tcprelay2;
servFunc service_tcprelay;
servFunc service_udprelay;
servFunc service_coupler;
servFunc2 service_teleport;
servFunc service_file;
servFunc service_socks;
servFunc service_nbt;
servFunc2 service_syslog;
servFunc service_cgi;
servFunc service_cfi;
servFunc service_vsap;
servFunc service_exec;
servFunc service_udprelay1;
servFunc service_admin;
servFunc2 service_icp;
servFuncX service_lpr;
servFunc service_ldap;
servFunc service_tunnel1;
servFuncX service_sockmux;
servFunc service_pam;
servFunc service_DGAuth;
servFunc service_icap;
servFunc2 service_sudo;
servFunc service_console;
servFunc2 service_ecc;

extern char DGAUTHpro[];

Service services[NSERVICES] = {
    {0},
    {0,PI_BOTH,0, "ftp-data",     20,service_tcprelay	},
    {0,PI_BOTH,0, "ftp-bounce",  -20,service_tcprelay	},
    {1,PI_SERV,0, "ftp",          21,service_ftp,	1},
    {1,PI_SERV,0, "ftps",        990,service_ftps	},
    {1,PI_SERV,0, "telnet",       23,service_telnet	},
    {1,PI_SERV,0, "telnets",     992,service_telnet	},
    {0,PI_SERV,0, "smtp",         25,service_smtp,	1},
    {0,PI_SERV,0, "smtp-data",    25,service_smtp	},
    {0,PI_SERV,0, "smtps",       465,service_smtps,	1},
    {1,PI_CLNT,0, "whois",	  43,service_whois	},
    {1,PI_CLNT,0, "domain",       53,(servFuncP)service_domain	},
    {1,PI_CLNT,0, "dns",          53,(servFuncP)service_domain	},
    {1,PI_CLNT,0, "gopher",	  70,service_gopher	},
    {0,PI_CLNT,0, "finger",	  79,service_tcprelay	},
    {1,PI_CLNT,1, "http",	  80,service_http,	1,SERV_HTTP },
    {1,PI_CLNT,1, "ftpxhttp",	  80,service_ftpxhttp	},
    {1,PI_CLNT,1, "httpft",       80,service_http 	},
    {1,PI_CLNT,1, "htmux",	  80,service_http	},
    {1,PI_CLNT,0, "https",       443,service_https	},
    {1,PI_CLNT,0, "ftpxhttps",   443,service_ftpxhttps	},
    {1,PI_CLNT,0, "ssltunnel",   443,service_https	},
    {1,PI_SERV,0, "pop",         110,service_pop,	1},
    {1,PI_SERV,0, "pop3s",       995,service_pop	},
    {0,PI_SERV,0, "imap",        143,service_imap,	1},
    {0,PI_SERV,0, "imaps",       993,service_imap	},
    {0,PI_CLNT,0, "ident",       113,service_tcprelay	},
    {1,PI_SERV,0, "nntp",	 119,service_nntp	},
    {1,PI_SERV,0, "nntps",	 563,service_nntp	},
    {1,PI_SERV,0, "news",	 119,service_nntp	},
    {0,PI_CLNT,0, "nbt",	 139,service_nbt	},
    {0,PI_CLNT,0, "prospero",    191,service_udprelay	},
    {0,PI_CLNT,0, "archie",      191,service_udprelay	},
    {0,PI_CLNT,0, "wais",	 210,service_wais	},
    {0,PI_CLNT,0, "tsp",         318,service_tcprelay	},
    {0,PI_CLNT,0, "ldap",        389,service_ldap	},
    {0,PI_CLNT,0, "ldaps",       636,service_ldap	},
    {1,PI_CLNT,0, "lpr",         515,(servFuncP)service_lpr	},
    {0,PI_CLNT,0, "X",	        6000,service_X		},
    {0,PI_CLNT,0, "XSFlash",    6001,service_XSFlash	},
    {1,PI_CLNT,0, "XCFlash",    6002,service_XCFlash	},
    {0,PI_SERV,0, "y11",        6010,(servFuncP)service_Y11	},
    {0,PI_SERV,0, "yy11",       6010,(servFuncP)service_Y11	},
    {0,PI_SERV,0, "yymux",      6060,(servFuncP)service_yymux	},
    {0,PI_SERV,0, "yy",         6060,(servFuncP)service_yymux	},
    {0,PI_CLNT,0, "yysh",       6023,(servFuncP)service_yysh	},
    {0,PI_CLNT,0, "syslog",      514,(servFuncP)service_syslog	},
    {0,PI_CLNT,0, "ntp",         123,service_udprelay	},
    {0,PI_SERV,0, "rsync",       873,service_tcprelay	},

    {0,PI_CLNT,0, "talk",        517,service_tcprelay	},
    {1,PI_CLNT,0, "socks",      1080,service_socks	},
    {1,PI_CLNT,0, "socks4",     1080,service_socks	},
    {1,PI_CLNT,0, "socks5",     1080,service_socks	},
    {1,PI_CLNT,0, "icap",       1344,service_icap	},
    {0,PI_CLNT,0, "cuseeme",    7648,service_tcprelay	},
    {0,PI_CLNT,0, "icp",        3130,(servFuncP)service_icp	},

    {1,PI_CLNT,1, "http-proxy",	8080,service_http	},
    {1,PI_CLNT,1, "mitm",       8080,service_http	},
    {0,PI_CLNT,0, "pam",        8686,service_pam	},
    {0,PI_CLNT,0, "httpam",     8686,service_pam	},
    {0,PI_CLNT,0, DGAUTHpro,    8787,service_DGAuth	},
    {0,PI_CLNT,0, "delegate",   8700,service_delegate	},
    {0,PI_BOTH,0, "tcprelay2",  8701,service_tcprelay2	},
    {0,PI_BOTH,0, "tcprelay",   8701,service_tcprelay	},
    {0,PI_BOTH,0, "udprelay",   8702,service_udprelay	},
    {0,PI_BOTH,0, "udprelay1",  8703,service_udprelay1	},
    {0,PI_CLNT,0, "teleport",   8704,(servFuncP)service_teleport},
    {0,PI_CLNT,0, "coupler",    8705,service_coupler	},
    {1,PI_CLNT,0, "vsap",       8706,service_vsap	},
    {1,PI_BOTH,0, "sockmux",    8707,(servFuncP)service_sockmux	},
    {1,PI_SERV,0, "sox",        8707,(servFuncP)service_sockmux	},
    {1,PI_CLNT,0, "thruway",    8715,0			},
    {1,PI_CLNT,0, "sudo",       8777,(servFuncP)service_sudo	},
    {1,PI_CLNT,0, "console",    8723,service_console	},
    {0,PI_CLNT,0, "htaccept",   8780,service_http	},
    {0,PI_CLNT,0, "incoming",   8781,0			},

    {0,PI_CLNT,0, "http-sp",    8888,(servFuncP)service_ecc	}, /* simplified proxy */
    {0,PI_CLNT,0, "ecc",        8888,(servFuncP)service_ecc	},
    {0,PI_SERV,0, "vnc",        5900,service_tcprelay		},
    {0,PI_SERV,0, "sftp",         22,0			},
    {0,PI_SERV,0, "ssh",          22,0			},

    {0,PI_CLNT,0, "tunnel1",     -10,service_tunnel1	},
    {0,PI_CLNT,0, "file",        -21,service_file	},
    {0,PI_CLNT,0, "cgi",         -22,service_cgi	},
    {0,PI_CLNT,0, "cfi",         -23,service_cfi	},
    {1,PI_CLNT,0, "exec",        -35,service_exec	},
    {1,PI_CLNT,0, "data",        -40,service_http	},
    {1,PI_CLNT,0, "admin",       -80,service_admin	},
    {0,PI_CLNT,0, "builtin",     -91,0			},
    {0,PI_CLNT,0, "override",    -92,0			},
    {0,PI_CLNT,0, "readonly",    -93,0			},
    {0,PI_CLNT,0, "tar",         -94,0			},

    {0}
};
