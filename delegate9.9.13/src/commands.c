/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	commands.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	981120	extracted from delegated.c (5.7.6)
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>

/* for P_LOGFILE */
#include <stdlib.h>
#include "ystring.h"
#include "proc.h"
#include "file.h"
#include "log.h"
#include "dglib.h"
#include "param.h"

void setIsFunc(DGC*Conn,int fc);
void DELEGATE_config(DGC*Conn,int csock);
void DELEGATE_ScanGlobal(DGC*Conn,PCStr(proto));
FILE *openLogFile(int now);
int ServSock();

typedef int mainFunc(int ac,const char *av[]);
typedef int mainFunc2(int ac,const char *av[],DGC*Conn);
typedef int mainFunc3(int ac,const char *av[],DGC*Conn,int sock,int port);

mainFunc help_main;
mainFunc myid_main;
mainFunc dump_main;
mainFunc ccx_main;
mainFunc2 urlccx_main;
mainFunc2 ssi_main;
mainFunc sched_main;
mainFunc resolvy_main;
mainFunc2 dget_main;
mainFunc2 dput_main;
mainFunc2 mirror_main;
mainFunc urlfind_main;
mainFunc thruwayd_main;
mainFunc system_main;
mainFunc htget_main;
mainFunc2 connect_main;
mainFunc icp_client;
mainFunc lpr_main;
mainFunc lpq_main;
mainFunc ls_main;
mainFunc ps_main;
mainFunc backup_main;
mainFunc MD5_main;
mainFunc binmd5_main;
mainFunc srcmd5_main;
mainFunc ENMIME_main;
mainFunc DEMIME_main;
mainFunc2 sendmail_main;
mainFunc alias_main;
mainFunc cafe_main;
mainFunc shio_main;
mainFunc console_main;
mainFunc tar_main;
mainFunc sed_main;
mainFunc uudec_main;
mainFunc urlescape_main;
mainFunc urlunescape_main;
mainFunc dping_main;
mainFunc acledit_main;
mainFunc2 authedit_main;
mainFunc sleep_main;
mainFunc3 sox_main;
mainFunc cksum_main;
mainFunc crc_main;
mainFunc crc8_main;
mainFunc credhy_main;
mainFunc creytest;
mainFunc authkey_main;
mainFunc printClientAddrId;
mainFunc pelcgb_main;
mainFunc pubkey_main;
mainFunc verify_main;
mainFunc any2fdif_main;
mainFunc2 cgi_delegate;
mainFunc2 poprelay_main;
mainFunc2 popdown_main;
mainFunc service_cuseeme;
mainFunc service_icp;
mainFunc service_dns;
mainFunc sslway_main;
mainFunc tsp_main;
mainFunc swft_main;
mainFunc pdft_main;
mainFunc Accepts;
mainFunc Connects;
mainFunc hosts_main;
mainFunc h2t_main;
mainFunc sort_main;
mainFunc touch_main;
mainFunc env_main;
mainFunc rsa_main;
mainFunc rsasign_main;
mainFunc rsavrfy_main;
mainFunc exesign_main;
mainFunc2 implant_main;
mainFunc argenc_main;
mainFunc argdec_main;
mainFunc trx_main;
mainFunc date_main;
mainFunc2 sudo_main;
mainFunc mysym_main;
mainFunc2 kill_main;
mainFunc more_main;
mainFunc owner_main;
mainFunc hostid_main;
mainFunc capsreq_main;
mainFunc capsgen_main;
mainFunc gendom_main;
mainFunc m17n_main;
mainFunc pilsner_main;
mainFunc spinach_main;
mainFunc sweepfiles_main;
mainFunc QStest_main;
mainFunc2 Y11_main;
mainFunc2 yymux_main;
mainFunc netsh_main;
mainFunc2 yysh_main;
mainFunc yycommand_main;
mainFunc dgForkpty_main;
mainFunc zlib_main;
mainFunc lsof_main;
mainFunc getpass_main;
mainFunc forkpty_main;
mainFunc seltest_main;

typedef struct {
	int	 f_type;
	int	 f_withAdmin;
	int	 f_withLog;
  const	char	*f_proto;
  const	char	*f_name;
       mainFunc *f_func;
  const	char	*f_desc;
	int	 f_stats;
} SubFunc;

#define MS	0	/* standalone function */
#define MN	1	/* function which uses network */
#define MV	2	/* server */
#define FC_DISABLE	0x00000001
#define FC_ASROOT	0x00000002 /* allow doing it as root */

static SubFunc subfuncs[] = {
{MS,0,0,"",	"help",	   help_main,	"show the list of functions"},
{MN,0,0,"",	"ver",	   myid_main,	"show the ver. and conf. of mine"},
{MV,0,0,"",	"cgi", (mainFunc*)cgi_delegate,"DeleGate as a cgi program"},
{MS,0,0,"",	"ssi", (mainFunc*)ssi_main,"SHTML interpreter"},
{MS,0,0,"",	"ccx",	   ccx_main,	"character code converter"},
{MS,0,0,"",	"urlccx",(mainFunc*)urlccx_main,"CCX for URL encoded text"},
{MS,0,0,"",	"dump",	   dump_main,	"dump configuration"},
{MS,0,0,"",	"sched",   sched_main,	"scheduler compatible with `crond'"},
{MS,0,0,"",	"star",    tar_main,	"simple tar"},
{MS,0,0,"",	"ssed",    sed_main,	"simple sed"},
{MS,0,0,"",	"deuu",    uudec_main,	"simple uudecode"},
{MS,0,0,"",	"urlenc",  urlescape_main,"escape URL with %XX encoding"},
{MS,0,0,"",	"urldec",  urlunescape_main,"unescape URL %XX encoding"},
{MS,0,0,"",	"dping",   dping_main,  "application level ping"},
{MN,0,0,"",	"dget",	   (mainFunc*)dget_main,	"download by URL"},
{MN,0,0,"",	"dput",	   (mainFunc*)dput_main,"upload to the URL"},
{MN,0,0,"",	"yy11",    (mainFunc*)Y11_main,"X client callback server"},
{MN,0,0,"",	"y11",     (mainFunc*)Y11_main,"X client callback server"},
{MN,0,0,"",	"yy",      (mainFunc*)yymux_main,"yyMux multiplexer"},
{MN,0,0,"",	"yysh",    (mainFunc*)yysh_main,"yyMux multiplexer"},
{MN,0,0,"",	"mirror",  (mainFunc*)mirror_main, "download by URL"},
{MN,0,0,"",	"poprelay",(mainFunc*)poprelay_main,"load from POP and relay to"},
{MN,0,0,"",	"popdown", (mainFunc*)popdown_main,"POP to SMTP gateway"},
{MS,0,0,"",	"urlfind", urlfind_main,"network wide find"},
{MS,0,0,"",	"thruwayd",thruwayd_main,"a circuit level proxy"},
{MN,0,0,"tcprelay","connect",(mainFunc*)connect_main,"connect to remote port"},
{MN,0,0,"",	"resolvy", resolvy_main,"host name resolver"},
{MN,0,0,"icp",	"icp",	   icp_client,	"ICP client"},
{MN,0,0,"http",	"htget",   htget_main,	"get by URL into HTML/HTTP format."},
{MS,0,0,"",	"system",  system_main,	"system commands"},
{MS,0,1,"",	"findu",   cafe_main,	"find + du"},
{MS,0,1,"",	"expire",  cafe_main,	"expire (alias of -Ffindu)"},
{MS,0,0,"",	"shio",    shio_main,	"shell I/O"},
{MS,0,0,"",	"ysh",     console_main,"vertual console script"},
{MS,0,0,"",	"console", console_main,"vertual console script"},
{MS,0,0,"",	"lpr",	   lpr_main,	"send to LPR"},
{MS,0,0,"",	"lpq",	   lpq_main,	"show status of LPR"},
{MS,0,0,"",	"ls",	   ls_main,	"unix like ls"},
{MS,0,0,"",	"ps",	   ps_main,	"unix like ps"},
{MS,0,0,"",	"backup",  backup_main,	"backup modified files"},
{MS,0,0,"",	"md5",     MD5_main,	"MD5 digest generator"},
{MS,0,0,"",	"binmd5",  binmd5_main,	"MD5 of this executable file"},
{MS,0,0,"",	"srcmd5",  srcmd5_main,	"MD5 of source code"},
{MS,0,0,"",	"enMime",  ENMIME_main,	"mime encoder"},
{MS,0,0,"",	"deMime",  DEMIME_main,	"mime decoder"},
{MN,0,0,"",	"sendmail",(mainFunc*)sendmail_main,"SMTP poster"},
{MS,0,0,"",	"alias",   alias_main,	"expand aliases of mail address"},
{MS,0,0,"",	"acle",    acledit_main,"edit ACL"},
{MS,0,0,"",	"auth",    (mainFunc*)authedit_main,"edit auth. for AUTHORIZER"},
{MS,0,0,"",	"hosts",   hosts_main,  "edit host-set"},
{MS,0,0,"",	"sleep",   sleep_main,  "sleep"},
{MV,0,0,"",	"sockmux", (mainFunc*)sox_main,	"Socket Multiplexer"},
{MS,0,0,"",	"cksum",   cksum_main,	"cksum command compatible"},
{MS,0,0,"",	"crc",     crc_main,	"CRC32 (32bits Cyclic Redundancy Code)"},
{MS,0,0,"",	"crc8",    crc8_main,   "CRC8 for debugging"},
{MS,0,0,"",	"credhy",  credhy_main,	"Credhy encryption/decription"},
{MS,0,0,"",	"creytest",creytest,	"Crey encryption/decryption test"},
{MS,0,0,"",	"authkey", authkey_main,"print Auth-Key"},
{MS,0,0,"",	"dcid",	   printClientAddrId,"print decrypted client id"},
{MS,0,0,"",	"pelcgb",  pelcgb_main,	"Pelcgb encryption/decription"},
{MS,0,0,"",	"pubkey",  pubkey_main,	"RSA Public Key of the Author"},
{MS,0,0,"",	"verify",  verify_main,	"Verify with the Key of the Author"},
{MS,0,0,"",	"any2fdif",any2fdif_main,"FDIF generator"},
{MS,0,0,"",	"h2t",     h2t_main,    "HTML to plain text converter"},
{MS,0,0,"",	"sort",    sort_main,   "sort"},
{MS,0,0,"",	"touch",   touch_main,  "make a file of specified size"},
{MS,0,0,"",	"env",     env_main,    "show environments"},
{MS,0,0,"",	"rsa",     rsa_main,    "RSA key"},
{MS,0,0,"",	"rsasign", rsasign_main,"RSA sign"},
{MS,0,0,"",	"rsavrfy", rsavrfy_main,"RSA verify"},
{MS,0,0,"",	"exesign", exesign_main,"sign/verify executable file"},
{MS,0,0,"",	"imp",     (mainFunc*)implant_main,"implant data into executable file"},
{MS,0,0,"",	"enc",     argenc_main,	"encrypt parameters to +=enc:"},
{MS,0,0,"",	"dec",     argdec_main,	"decrypt parameters from +=enc:"},
{MS,0,0,"",	"esign",   exesign_main,"sign/verify embedded RSA sign"},
{MS,0,0,"",	"trx",     trx_main,    "conv. bytes to/from editable one"},
{MS,0,0,"",	"sudo",    (mainFunc*)sudo_main,"do privileged ation"},
{MS,0,0,"",	"mysym",   mysym_main,	"get the address of the symbol"},
{MS,0,0,"",	"kill",    (mainFunc*)kill_main,"kill a DeleGate server"},

{MS,0,0,"",	"sslway",  sslway_main, "SSLway"},
{MS,0,0,"",	"swft",    swft_main,	"SWF translator"},
{MS,0,0,"",	"pdft",    pdft_main,	"PDF translator"},
{MS,0,0,"",	"tsp",     tsp_main,	"TIme Stamp Protocol Client"},
{MN,0,0,"",	"accepts", Accepts,	"TCP accept() benchmark"},
{MN,0,0,"",	"connects",Connects,	"TCP connect() benchmark"},
{MN,0,0,"",	"date",    date_main,	"date command"},
{MN,0,0,"",	"more",    more_main,	"more command"},
{MN,0,0,"",	"owner",   owner_main,	"show owner's identity"},

{MN,0,0,"",	"hostid",  hostid_main, "show host-id"},
{MN,0,0,"",	"capsreq", capsreq_main,"show capability request message"},
{MN,0,0,"",	"capsgen", capsgen_main,"generate a capability key"},
{MN,0,0,"",	"gendom",  gendom_main, "generic E-mail domain of the host"},
{MN,0,0,"",	"m17n",    m17n_main,   "m17n lib."},
{MS,0,0,"",	"pils",    pilsner_main,"pilsner"},
{MN,0,0,"",	"spin",    spinach_main,"spinach"},
{MS,0,0,"",	"sweepf",  sweepfiles_main,"sweep temp. files"},
{MS,0,0,"",	"QStest",  QStest_main, "test of Quarified String"},
{MN,0,0,"",	"netsh",   netsh_main,  "netsh"},
{MS,0,0,"",	"yycommand",yycommand_main,"yycommand"},
{MS,0,0,"",	"dgForkpty",dgForkpty_main,"dgForkpty"},
{MS,0,0,"",	"zlib",    zlib_main,   "zlib test"},
{MS,0,0,"",	"lsof",    lsof_main,   "list open files"},
{MS,0,0,"",	"getpass", getpass_main,"getpass"},
{MS,0,0,"",	"forkpty", forkpty_main,"forkpty"},
{MS,0,0,"",	"seltest", seltest_main,"select test"},
0
};

void lsFuncs(FILE *out){
	int fi;
	const char *name;
	for( fi = 0; name = subfuncs[fi].f_name; fi++ )
		fprintf(out,"F%-14s ",name);
}
int asFunc(PCStr(arg1)){
	CStr(name,128);
	refQStr(dp,name);
	int fi;
	const char *n1;

	strcpy(name,arg1);
	if( dp = strrpbrk(name,"\\/") )
		ovstrcpy(name,dp+1);
	if( dp = strtailstrX(name,".exe",1) )
		setVStrEnd(dp,0);
	for( fi = 0; n1 = subfuncs[fi].f_name; fi++ ){
		if( strcaseeq(name,n1) )
			return fi+1;
		if( strncaseeq(name,"dg",2) && strcaseeq(name+2,n1) )
			return fi+1;
	}
	return 0;
}
void enableFuncs(PCStr(func),int enable){
	int fi;
	int mask = 0;

	if( enable == 2 || enable == -2 ){
		enable = -enable;
		mask = FC_ASROOT;
	}else	mask = FC_DISABLE;

	/*
	if( streq(func,"*") ){
	*/
	if( streq(func,"*") || streq(func,"all") ){
		for( fi = 0; subfuncs[fi].f_name; fi++ ){
			if( 0 < enable )
				subfuncs[fi].f_stats &= ~mask;
			else	subfuncs[fi].f_stats |=  mask;
		}
	}else{
		if( fi = asFunc(func) ){
			fi--;
			if( 0 < enable )
				subfuncs[fi].f_stats &= ~mask;
			else	subfuncs[fi].f_stats |=  mask;
		}
	}
}
const void *funcFunc(PCStr(func)){
	int fi;
	if( strneq(func,"-F",2) )
		func += 2;
	if( fi = asFunc(func) )
		return (void*)subfuncs[fi-1].f_func;
	else	return 0;
}
const char *funcName(void *func){
	int fi;
	for( fi = 0; elnumof(subfuncs); fi++ ){
		if( func == subfuncs[fi].f_func ){
			return subfuncs[fi].f_name;
		}
	}
	return "";
}
int more_main(int ac,const char *av[]){
	FILE *in = stdin;
	FILE *out = stdout;
	IStr(line,1024);
	int opt_s = 1;
	int sql = 0;

	for(;;){
		if( fgets(line,sizeof(line),in) == 0 )
			break;
		if( opt_s ){
			if( *line == '\r' || *line == '\n' ){
				sql++;
				if( 1 < sql ){
					continue;
				}
			}else{
				sql = 0;
			}
		}
		fputs(line,out);
	}
	return 0;
}
extern const char *DELEGATE_pubkey;
int pubkey_main(int ac,const char *av[])
{
	fprintf(stdout,"%s",DELEGATE_pubkey);
	return 0;
}
int verify_main(int ac,const char *av[])
{	CStr(command,1024);
	CStr(s64,1024);
	CStr(kfile,1024);
	CStr(buf,1024);
	int len;
	FILE *in,*fp,*pp;

	in = 0;
	if( 2 <= ac ){
		in = fopen(av[1],"r");
		if( in == NULL ){
			fprintf(stderr,"Cannot open: %s\n",av[1]);
			return -1;
		}
	}
	if( in == NULL )
		in = stdin;

	sprintf(kfile,"${ACTDIR}/pubkey.pem");
	DELEGATE_substfile(AVStr(kfile),"",VStrNULL,VStrNULL,VStrNULL);
	if( fp = fopen(kfile,"w") ){
		fputs(DELEGATE_pubkey,fp);
		fclose(fp);
	}
	IGNRETP fread(s64,1,sizeof(s64),in);
	len = str_from64(s64,strlen(s64),AVStr(buf),sizeof(buf));
	sprintf(command,"openssl rsautl -verify -pubin -inkey %s",kfile);
	if( pp = popen(command,"w") ){
		fwrite(buf,1,len,pp);
		pclose(pp);
	}
	return 0;
}
int help_main(int ac,const char *av[])
{	int fi;
	const char *fname;

	printf("FUNCTIONS:\r\n");
	for( fi = 0; fname = subfuncs[fi].f_name; fi++ )
		printf("-F%-10s %s\r\n",fname,subfuncs[fi].f_desc);
	return 0;
}
static int replace_log(int ac,const char **avp[],int mac,const char *nav[],PVStr(nab))
{	FILE *lfp;
	int ai,nac;
	const char **av;

	if( DELEGATE_getEnv(P_LOGFILE) == 0 )
		return ac;

	if( (lfp = openLogFile(time(NULL))) == NULL )
		return ac;

	av = *avp;
	nac = 0;
	for( ai = 0; ai < ac; ai++ ){
		if( mac-3 <= nac ){
			break;
		}
		nav[nac++] = av[ai];
	}
	/* LOGFILE parameter from CRON-expire will be ignored with
	 * prefix "-ign" like -ign LOGFILE=path.
	 */

	nav[nac++] = "-log";
	sprintf(nab,"-%d",fileno(lfp));
	nav[nac++] = nab;
	nav[nac] = NULL;
	*avp = nav;
	return nac;
}

static void lprintf(PCStr(fmt),...){
	CStr(msg,1024);
	IStr(peer,MaxHostNameLen);
	IStr(host,MaxHostNameLen);
	VARGS(8,fmt);

	printf(fmt,VA8);
	getpairName(0,AVStr(host),AVStr(peer));
	sprintf(msg,"[%s][%s] ",peer,host);
	Xsprintf(TVStr(msg),fmt,VA8);
	daemonlog("F","%s",msg);
}
int FimpByOwner(PCStr(func));
int AuthFunc(DGC*Conn,void*faddr,PCStr(File),int Line){
	int fi;
	SubFunc *Sf;
	int found = 0;
	FILE *tty;

	for( fi = 0; fi < elnumof(subfuncs); fi++ ){
		Sf = &subfuncs[fi];
		if( (void*)Sf->f_func == faddr ){
			found = 1;
			break;
		}
	}
	if( !found ){
		lprintf("Unknown funciton: %X %s:%d\n",faddr,File,Line);
		Finish(-1);
	}
	if( Sf->f_stats & FC_DISABLE ){
		lprintf("Disabled funciton: %X %s:%d %s\n",faddr,File,Line,
			Sf->f_name);
		if( FimpByOwner(Sf->f_name) ){
		}else
		Finish(-1);
	}

	if( isWindows() )
		/* this failes always on Win32 by the specification.
		tty = fopen("con","rw");
		*/
		tty = fopen("con","r");
	else	tty = fopen("/dev/tty","rw");
	if( tty == NULL ){
		/* AUTHORIZER=as:imp::who@host ? */
		if( 1 /* if not authenticated */ ){
			lprintf("Forbidden remote function usage: %s:%d -F%s\n",
				File,Line,Sf->f_name);
			Finish(-1);
		}
	}else{
		fclose(tty);
	}
	return 0;
}

typedef int (*mainFUNCP)(int ac,const char *av[],...);
int DELEGATE_subfunc(DGC*Conn,int ac,const char *av[],PCStr(func),int Fopt,int type)
{	int fi;
	const char *fname;
	const char *sp;
	mainFUNCP ifunc;
	int ctype;
	const char *nav[64]; /**/
	CStr(nab,1024);
	const char **avx;
	int acx;
	int impok = 0;

	for( fi = 0; fname = subfuncs[fi].f_name; fi++ ){
		if( !strcaseeq(func,fname) )
		if( !strncaseeq(func,"dg",2) || !strcaseeq(func+2,fname) )
			continue;

		if( subfuncs[fi].f_stats & FC_DISABLE ){
			if( FimpByOwner(func) ){
				impok = 1;
			}else{
			fprintf(stderr,"Forbidden: %s\n",fname);
			Finish(-1);
			}
		}

		if( geteuid() == 0 && getuid() != 0 )
		if( (subfuncs[fi].f_stats & FC_ASROOT) == 0 )
		if( subfuncs[fi].f_func != (mainFunc*)implant_main )
		{
			/*
			fprintf(stderr,"Not allowed in root: %s\n",fname);
			*/
			seteuid(getuid());
		}

		ctype = subfuncs[fi].f_type;
		if( ctype == MS ){
			setIsFunc(Conn,1);
			LOG_type |= L_ISFUNC;
		}

		if( ctype == MV ){
			if( type != MV )
				return 1;
		}else
		if( ctype == MN ){
			if( type != MN )
				return 1;
			if( subfuncs[fi].f_proto[0] )
			DELEGATE_ScanGlobal(Conn,subfuncs[fi].f_proto);
		}

		ifunc = (mainFUNCP)subfuncs[fi].f_func;

		if( subfuncs[fi].f_withLog ){
			/* special case of "expire" */
			ac = replace_log(ac,&av,64,nav,AVStr(nab));
		}else
		if( ctype == MV ){
			/* already did arg_scan() */
			/* don't need config for any client */
		}else{
			if( ifunc == (mainFUNCP)argdec_main ){
				/* don't decrypt +=enc:... arg. */
			}else
			ac = DELEGATE_scan_args(ac,av);
			DELEGATE_config(Conn,-1);
		}

		if( subfuncs[fi].f_withAdmin )
		if( subfuncs[fi].f_proto[0] )
			checkADMIN(Conn,subfuncs[fi].f_proto);

		if( Fopt ){
			int ai;

			acx = ac - Fopt;
			avx = &av[Fopt];
			for( ai = 0; ai < acx; ai++ ){
				if( strcmp(avx[ai],"--") == 0 ){
					acx = ai;
					break;
				}
			}
		}else{
			acx = ac;
			avx = av;
		}

		if( getenv("DELEGATE_DEBUG") ){
			int ai;
			for(ai=0;ai<acx;ai++)
				fprintf(stderr,"##[%d] %s\n",ai,avx[ai]);
		}

		DELEGATE_ver(); /* set MyVer for debugging */
		(*ifunc)(acx,avx,Conn,ServSock(),SERVER_PORT());
		Finish(0);
	}
	if( Fopt ){
		printf("DeleGate: unknown function -F\"%s\"\r\n",func);
		help_main(ac,av);
		Finish(-1);
	}
	return 0;
}
int htget_main(int ac,const char *av[])
{
	if( ac < 2 ){
		fprintf(stderr,"Usage: %s URL\r\n",av[0]);
		return -1;
	}
	URLget(av[1],1,stdout);
	return 0;
}
int system_main(int ac,const char *av[])
{	const char *nav[256]; /**/
	CStr(nab,0x10000);
	int nac,ai;

	if( File_is(av[1]) /* should search in PATH ... */ ){
		Execvp("system",av[1],&av[1]);
	}else{
		nac = decomp_args(nav,256,av[1],AVStr(nab));
		for( ai = 2; ai < ac; ai++ ){
			if( elnumof(nav)-1 <= nac)
				break;
			nav[nac++] = av[ai];
		}
		nav[nac] = 0;
		Execvp("system",nav[0],nav);
	}
	return 0;
}
int ps_unix(FILE *out);
int ps_main(int ac,const char *av[]){
	ps_unix(stdout);
	return 0;
}
int sleep_main(int ac,const char *av[])
{
	if( 1 < ac ){
		sleep(atoi(av[1]));
	}
	return 0;
}
int makeAdminKey(PCStr(from),PVStr(key),int siz);
int authkey_main(int ac,const char *av[]){
	int ai;
	CStr(key,128);
	for( ai = 1; ai < ac; ai++ ){
		makeAdminKey(av[ai],AVStr(key),sizeof(key));
		printf("%s %s\n",key,av[ai]);
	}
	return 0;
}

void dumpFdsY(PCStr(what),FILE *outf,PCStr(types),int ffrom,int fto);
int lsof_main(int ac,const char *av[]){
	const char *types = NULL;
	dumpFdsY("lsof",stdout,types,0,512);
	return 0;
}
