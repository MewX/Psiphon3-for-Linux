/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1997-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2008 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	env.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970814	extracted from delegated.c
//////////////////////////////////////////////////////////////////////#*/
#include "config.h"
#include "delegate.h"
#include "param.h"
#include "fpoll.h"
#include "file.h"
#include <stdlib.h>

int  main_argc;
const char **main_argv;
extern char **environ;

scanPFUNCP param_scanner(PCStr(param));

typedef struct {
	int   ee_ext_argc;
  const	char *ee_ext_argv[MAX_ARGC]; /**/
	int   ee_extovw_argc;
  const	char *ee_extovw_argv[MAX_ARGC]; /**/
	int   ee_gen_envx;
  const	char *ee_gen_environ[32]; /**/
  const	char *ee_ext_environ[MAX_ARGC]; /**/
	int   ee_bin_argc;
  const char *ee_bin_argv[MAX_ARGC]; /**/
	int   ee_bin_argGot;
} Envs;
static Envs *envs;
#define ext_argc	envs->ee_ext_argc
#define ext_argv	envs->ee_ext_argv
#define extovw_argc	envs->ee_extovw_argc
#define extovw_argv	envs->ee_extovw_argv
#define gen_envx	envs->ee_gen_envx
#define gen_environ	envs->ee_gen_environ
#define ext_environ	envs->ee_ext_environ
#define bin_argc	envs->ee_bin_argc
#define bin_argv	envs->ee_bin_argv
#define bin_argGot	envs->ee_bin_argGot

void minit_envs(){
	if( envs == 0 )
		envs = NewStruct(Envs);
}

int getBconfig(int ac,const char *av[]);
const char *getEnvBin(PCStr(name)){
	if( bin_argGot == 0 ){
		bin_argGot = 1;
		bin_argc = getBconfig(elnumof(bin_argv),(const char**)bin_argv);
	}
	return getv(bin_argv,name);
}
void scan_DGPATH(PCStr(path));
void loadViaImp(Connection *Conn){
	int ai;
	const char *arg;
	const char *dgpath = 0;

	getEnvBin("");
	for( ai = 0; ai < bin_argc; ai++ ){
		arg = bin_argv[ai];
		if( strstr(arg,"+=") ){
			if( dgpath == 0 ){
				if( (dgpath = getv(bin_argv,P_DGPATH)) == 0 )
					dgpath = DELEGATE_DGPATH;
				scan_DGPATH(dgpath);
			}
			scan_arg1(Conn,NULL,arg);
		}
	}
}

int DELEGATE_EXTOVW;
void DELEGATE_clearEnv()
{
	extovw_argc = 0;
}
const char *DELEGATE_getEnv(PCStr(name))
{
	return DELEGATE_getEnvX(name,PARAM_ALL);
}
const char *DELEGATE_getEnvX(PCStr(name),int where)
{	const char *value;
	CStr(xname,64);

	if( where & PARAM_GENENV )
	if( value = getv(gen_environ,name) )
		return value;

	if( where & PARAM_EXTOVW)
	if( value = getv(extovw_argv,name) )
		return value;

	if( where & PARAM_MAINARG)
	if( value = getv(main_argv,name) )
		return value;

	if( where & PARAM_EXTARG)
	if( value = getv(ext_argv,name) )
		return value;

	sprintf(xname,"DG_%s",name);
	if( where & PARAM_DGENV)
	if( value = getenv(xname) )
		return value;

	if( where & PARAM_ENV)
	if( value = getenv(name) )
		return value;
	/*
	return getenv(name);
	*/

	if( value = getEnvBin(name) )
		return value;

	return 0;
}
const char *getEnvBin1st(PCStr(name)){
	const char *env;
	if( env = getEnvBin(name) )
		return env;
	return DELEGATE_getEnv(name);
}

const char *getMainArg(PCStr(where),PCStr(name)){
	return DELEGATE_getEnv(name);
}

void dumpEnv(){
	int ai;
	for( ai = 0; gen_environ[ai]; ai++ )
		printf("GEN[%d] %s\n",ai,gen_environ[ai]);
	for( ai = 0; ai < extovw_argc; ai++ )
		printf("OVW[%d] %s\n",ai,extovw_argv[ai]);
	for( ai = 0; ai < main_argc; ai++ )
		printf("MAI[%d] %s\n",ai,main_argv[ai]);
	for( ai = 0; ai < ext_argc; ai++ )
		printf("EXT[%d] %s\n",ai,ext_argv[ai]);
	for( ai = 0; environ[ai]; ai++ )
		printf("ENV[%d] %s\n",ai,environ[ai]);
}
int encrypt_argv(int ac,char *av[]);
void encrypt_args(){
	encrypt_argv(main_argc,(char**)main_argv);
	encrypt_argv(ext_argc,(char**)ext_argv);
}
static int findarg1(int ac,const char *av[],PCStr(pat),PVStr(arg)){
	int ai;
	int len = strlen(pat);
	for( ai = 0; ai < ac; ai++ ){
		if( strneq(av[ai],pat,len) ){
			if( arg ){
				strcpy(arg,av[ai]);
			}
			return ai;
		}
	}
	return -1;
}
int get_mainarg(PCStr(pat),PVStr(arg)){
	if( 0 <= findarg1(main_argc,main_argv,pat,BVStr(arg)) ) return 1;
	if( 0 <= findarg1(ext_argc,ext_argv,pat,BVStr(arg)) ) return 1;
	return 0;
}
int DELEGATE_copyEnv(int mac,const char *av[],int ac,PCStr(path),PVStr(abuff))
{	int ai;
	CStr(hosts,0x4000);
	CStr(port,PORTSSIZE);
	refQStr(ap,abuff); /**/

	if( mac-1 <= ac )
		goto EXIT;
	if( lVERB() ){
		av[ac++] = "-vv";
	}else{
		printServPort(AVStr(port),"",0);
		if( port[0] == 0 ){
			/* this can occur with -x option on Unix, port is
			 * not set yet, don't disable LOGFILE by this
			 */
		}else{
		sprintf(ap,"%s=%s",P_LOGFILE,port);
		av[ac++] = ap;  ap += strlen(ap) + 1;
		}
	}

	if( mac-1 <= ac )
		goto EXIT;
	sprintf(ap,"%s=%s",P_EXEC_PATH,path);
	av[ac++] = ap; ap += strlen(ap) + 1;

	for( ai = 0; ai < ext_argc; ai++ ){
		if( mac-1 <= ac )
			goto EXIT;
		av[ac++] = ext_argv[ai];
	}

	for( ai = 1; ai < main_argc; ai++ ){
		if( mac-1 <= ac )
			goto EXIT;
		if( main_argv[ai] )
			av[ac++] = main_argv[ai];
	}

	for( ai = 0; ai < extovw_argc; ai++ ){
		if( mac-1 <= ac )
			goto EXIT;
		av[ac++] = extovw_argv[ai];
	}

	for( ai = 0; ai < gen_envx; ai++ ){
		if( mac-1 <= ac )
			goto EXIT;
		av[ac++] = gen_environ[ai];
	}

	if( mac-1 <= ac )
		goto EXIT;
	if( dump_HOSTS(AVStr(hosts)) ){
		sprintf(ap,"%s=%s",P_HOSTS,hosts);
		Verbose("%s\n",ap);
		av[ac++] = ap; ap += strlen(ap) + 1;
	}
EXIT:
	return ac;
}
int DELEGATE_copyEnvPM(int mac,const char *dav[],PCStr(name))
{	int ac;

	ac = 0;
	ac += copy_param(name,mac-ac,&dav[ac],(const char**)environ);
	ac += copy_param(name,mac-ac,&dav[ac],ext_argv);
	ac += copy_param(name,mac-ac,&dav[ac],&main_argv[1]);
	ac += copy_param(name,mac-ac,&dav[ac],gen_environ);
	return ac;
}

int dump_main(int ac,const char *av[])
{	int ai;
	const char *nam;
	const char *val;
	CStr(valb,256);

	for( ai = 1; ai < ac; ai++ ){
		nam = av[ai];
		if( strcmp(nam,"DGROOT") == 0 ){
			val = DELEGATE_DGROOT;
		}else
		if( strcmp(nam,"OWNER") == 0 ){
			sprintf(valb,"#%d/#%d",getuid(),getgid());
			val = valb;
		}else
		if( strcmp(nam,"ADMIN") == 0 ){
			val = getADMIN();
		}else{
			val = DELEGATE_getEnv(nam);
		}
		printf("%s\n",val?val:"(none)");
	}
	exit(0);
	return 0;
}

/*
static const char *getEnvT(PCStr(name))
{	const char *body;
	if( body = getEnv(name) )
		if( body[-1] == '=' )
			return body - strlen(name) - 1;
		else	return body - strlen(name);
	return 0;
}
*/

void DELEGATE_addEnvExt(PCStr(env))
{
	if( lVERB() || lARGDUMP() ){
		if( DELEGATE_EXTOVW )
			fprintf(stderr,"<%d> %s\n",extovw_argc,env);
		else	fprintf(stderr,"<%d> %s\n",ext_argc,env);
	}
	if( DELEGATE_EXTOVW ){
		if( elnumof(extovw_argv) <= extovw_argc ){
			syslog_ERROR("too many args: %s\n",env);
		}else{
			extovw_argv[extovw_argc++] = StrAlloc(env);
		}
	}else{
		if( elnumof(ext_argv) <= ext_argc ){
			syslog_ERROR("too many args: %s\n",env);
		}else{
			ext_argv[ext_argc++] = StrAlloc(env);
		}
	}
}
void DELEGATE_pushEnv(PCStr(name),PCStr(value))
{	CStr(env,1024);

	sprintf(env,"%s=%s",name,value);
	if( elnumof(gen_environ) <= gen_envx ){
		syslog_ERROR("too many args: %s\n",env);
	}else{
		gen_environ[gen_envx++] = StrAlloc(env);
	}
}
typedef struct {
	Connection *sv_Conn;
	IFUNCP	sv_func;
  const char	*sv_arg;
	int	sv_ign_include;
} SvArg;
static int scanenv1(SvArg *sva,PCStr(val))
{
	if( strncmp(val,INC_SYM,INC_SYM_LEN) == 0 )
		return 0;
	if( strstr(val,":+=") || strstr(val,",+=") )
		return 0;
	else	return (*sva->sv_func)(sva->sv_Conn,val,sva->sv_arg);
}
int DELEGATE_scanEnv(Connection *Conn,PCStr(name),scanPFUNCP func,...)
{	int nhit;
	SvArg sva;
	const char *arg;
	VARGS(1,func);
	arg = va[0];

	nhit = 0;
	sva.sv_Conn = Conn;
	sva.sv_func = (IFUNCP)func;
	sva.sv_arg = arg;
	nhit += scanv((const char**)environ,name,(iFUNCP)scanenv1,(void*)&sva);
	nhit += scanv(ext_argv,name,(iFUNCP)scanenv1,(void*)&sva);
	nhit += scanv(main_argv,name,(iFUNCP)scanenv1,(void*)&sva);
	nhit += scanv(extovw_argv,name,(iFUNCP)scanenv1,(void*)&sva);
	nhit += scanv(gen_environ,name,(iFUNCP)scanenv1,(void*)&sva);
	nhit += scanv(bin_argv,name,(iFUNCP)scanenv1,(void*)&sva);
	return nhit;
}

const char *parameq(PCStr(param),PCStr(name));
static void svxlog(PCStr(fmt),int ai,PCStr(arg1)){
	const char *pv;
	if( lSECRET() ){
	}else{
		if( pv = parameq(arg1,"MYAUTH") ){ arg1 = "MYAUTH="; }
		if( pv = parameq(arg1,"PASSWD") ){ arg1 = "PASSWD="; }
		if( pv = parameq(arg1,"CRYPT" ) ){ arg1 = "CRYPT="; }
	}
	if( ai < 0 )
		sv0log(fmt,arg1);
	else	sv0log(fmt,ai,arg1);
}
#define CFput0(fp,fmt,msg) {\
	if( fp != NULL ) fprintf(fp,fmt,msg); else svxlog(fmt,-1,msg); \
	leng += strlen(msg); \
}
#define CFput(fp,fmt,ai,msg) {\
	if( fp != NULL ) fprintf(fp,fmt,ai,msg); else svxlog(fmt,ai,msg); \
	leng += strlen(msg); \
}
int DELEGATE_dumpEnvX(FILE *fp,int genalso,int imPM,int showidx);
int DELEGATE_dumpEnv(FILE *fp,int genalso,int imPM)
{
	return DELEGATE_dumpEnvX(fp,genalso,imPM,1);
}
int DELEGATE_dumpEnvX(FILE *fp,int genalso,int imPM,int showidx)
{	int ai;
	const char *env;
	int leng = 0;

	if( fp != NULL && !imPM ){
		CStr(port,PORTSSIZE);
		printServPort(AVStr(port),"-P",genalso);
		fprintf(fp,"%s\n",port);
	}

	for( ai = 0; env = environ[ai]; ai++ )
	if( 0 <= check_param(env,0) )
		if( !showidx ) CFput0(fp,"env %s\n",env) else
		CFput(fp,"env[%d] %s\n",ai,env);

	for( ai = 0; ai < ext_argc; ai++ )
		if( !showidx ) CFput0(fp,"ext %s\n",ext_argv[ai]) else
		CFput(fp,"ext[%d] %s\n",ai,ext_argv[ai]);

	for( ai = 1; ai < main_argc; ai++ )
	if( 0 <= check_param(main_argv[ai],0) )
		if( !showidx ) CFput0(fp,"arg %s\n",main_argv[ai]) else
		CFput(fp,"arg[%d] %s\n",ai,main_argv[ai]);

	if( genalso )
	for( ai = 0; gen_environ[ai]; ai++ )
		if( !showidx ) CFput0(fp,"gen %s\n",gen_environ[ai]) else
		CFput(fp,"gen[%d] %s\n",ai,gen_environ[ai]);

	return leng;
}


/*
 * inporting configuration parameters
 */
int param_file = -1;
int param_mtime = 0;

void new_param_file(PCStr(path))
{	FILE *fp;

	if( 0 <= param_file )
		return;
	fp = TMPFILE("PARAM_FILE");
	/*
	 * it should be a visible file under ETCDIR or ADMDIR ...
	 */
	param_file = dup(fileno(fp));
	fclose(fp);
	param_mtime = file_mtime(param_file);
}
int add_params(Connection *Conn,FILE *tc,PCStr(command))
{	FILE *fp;
	int pid;
	CStr(com,1024);
	CStr(param,1024);

	/*
	 * must check accees right here...
	 */

	if( param_file < 0 ){
		fprintf(tc,"500 no parameter file\r\n");
		return -1;
	}

	com[0] = param[0] = 0;
	Xsscanf(command,"%s %[^\r\n]",AVStr(com),AVStr(param));

	/*
	 * param may be +=URL
	 */

	if( com[0] == 0 || param[0] == 0 ){
		fp = fdopen(dup(param_file),"r");
		fseek(fp,0,0);
		fputs("200 list of inported parameters follows:\r\n",tc);
		copyfile1(fp,tc);
		fputs(".\r\n",tc);
		fclose(fp);
		return 0;
	}
	if( check_param(param,0) < 0 ){
		fprintf(tc,"500 unknown parameter: %s\r\n",param);
		return -1;
	}
	if( lock_exclusiveTO(param_file,2000,NULL) != 0 ){
		fprintf(tc,"500 cannot lock parameter file\r\n");
		return -1;
	}
	pid = getpid();
	fp = fdopen(dup(param_file),"w");
	fprintf(fp,"%d %s\r\n",pid,param);
	fclose(fp);

	sv1log("#### PARAM INPORTED: %d %s\n",pid,param);
	fprintf(tc,"200 ok.\r\n");
	return 0;
}
void load_params(Connection *Conn)
{	FILE *fp;
	CStr(line,1024);
	CStr(param,1024);
	int mtime,pid;

	if( param_file < 0 )
		return;
	mtime = file_mtime(param_file);
	if( mtime == param_mtime )
		return;
	param_mtime = mtime;
	sv1log("#### PARAM updated\n");

	fp = fdopen(dup(param_file),"r");
	fseek(fp,0,0);
	while( fgets(line,sizeof(line),fp) ){
		Xsscanf(line,"%d %[^\r\n]",&pid,AVStr(param));
		sv1log("#### %d %s\n",pid,param);
		if( strncmp(param,"MOUNT=",6) == 0 ){
			scan_MOUNT(Conn,param+6);
			init_mtab();
		}
	}
	fclose(fp);
}


extern int DELAY_REJECT_S;
extern int DELAY_UNKNOWN_S;
extern int DELAY_REJECT_P;
extern int DELAY_UNKNOWN_P;
extern int DELAY_ERROR;

static scanListFunc delay1(PCStr(dspec),Connection *Conn)
{	CStr(what,128);
	int delay;
	int *iaddr;

	delay = 0;
	Xsscanf(dspec,"%[^:]:%d",AVStr(what),&delay);

	iaddr = 0;
	if( strcaseeq(what,"reject")    ) iaddr = &DELAY_REJECT_S; else
	if( strcaseeq(what,"unknown")   ) iaddr = &DELAY_UNKNOWN_S; else
	if( strcaseeq(what,"reject_p")  ) iaddr = &DELAY_REJECT_P; else
	if( strcaseeq(what,"unknown_p") ) iaddr = &DELAY_UNKNOWN_P; else
	if( strcaseeq(what,"error")     ) iaddr = &DELAY_ERROR; else
	{
		sv1tlog("ERROR: unknown DELAY=%s\n",what);
	}
	if( iaddr ){
		xmem_push(iaddr,sizeof(int),"DELAY",NULL);
		*iaddr = delay;
	}
	return 0;
}
void scan_DELAY(Connection *Conn,PCStr(sdelay))
{
	scan_commaList(sdelay,0,scanListCall delay1,Conn);
}

extern int MAX_ERESTART;
/*
extern int MAX_DELEGATE;
*/
extern int MAX_DELEGATEsta;
#define MAX_DELEGATE MAX_DELEGATEsta
extern int MAX_SERVICE;
extern int STANDBY_MAX;
extern int FDSET_MAX;
extern int HTTP_CKA_MAXREQ;
extern int HTTP_CKA_PERCLIENT;
extern int MAX_CC;
extern int MAXCONN_PCH;
extern int MAX_BUFF_SOCKRECV;
extern int MAX_BUFF_SOCKSEND;
extern int MAX_BPS;
extern int RANDSTACK_RANGE;
extern int RANDSTACK_UNIT;
extern int RANDFD_RANGE;
extern int RANDENV_RANGE;
extern int UDPRELAY_MAXASSOC;
extern int CON_RETRY;
int SERVER_RESTART_SERNO;

static scanListFunc maxima1(PCStr(maxima),Connection *Conn)
{	CStr(name,128);
	IStr(unit,32);
	CStr(val,32);
	int num;
	int *addr;

	/*
	if( Xsscanf(maxima,"%[^:]:%d",AVStr(name),&num) != 2 ){
	*/
	if( Xsscanf(maxima,"%[^:]:%d%s",AVStr(name),&num,AVStr(unit)) < 2 ){
		ERRMSG("DeleGate/%s: ERROR syntax MAXIMA=%s\n",
			DELEGATE_ver(),maxima);
		return 0;
	}
	if( unit[0] ){
		sprintf(val,"%d%s",num,unit);
		num = kmxatoi(val);
	}

	addr = 0;
	if( streq(name,"erestart") )	addr = &MAX_ERESTART; else
	if( streq(name,"randstack") )	addr = &RANDSTACK_RANGE; else
	if( streq(name,"randfd") )	addr = &RANDFD_RANGE; else
	if( streq(name,"randenv") )	addr = &RANDENV_RANGE; else
	if( streq(name,"fdset") )	addr = &FDSET_MAX; else
	if( streq(name,"delegated") )	addr = &MAX_DELEGATE; else
	if( streq(name,"restart") )	addr = &SERVER_RESTART_SERNO; else
	if( streq(name,"standby") )     addr = &STANDBY_MAX; else
	if( streq(name,"ftpcc") )	addr = &MAX_CC; else
	if( streq(name,"nntpcc") )	addr = &MAX_CC; else
	if( streq(name,"svcc") )	addr = &MAX_CC; else
	if( streq(name,"listen") )	addr = &DELEGATE_LISTEN; else
	if( streq(name,"sockrecv") )	addr = &MAX_BUFF_SOCKRECV; else
	if( streq(name,"socksend") )	addr = &MAX_BUFF_SOCKSEND; else
	if( streq(name,"winmtu") )	addr = &WIN_MTU; else
	if( streq(name,"bps") )		addr = &MAX_BPS; else
	if( streq(name,"service") )	addr = &MAX_SERVICE; else
	if( streq(name,"conpch") )	addr = &MAXCONN_PCH; else
	if( streq(name,"contry") )	addr = &CON_RETRY; else
	if( streq(name,"http-cka") )	addr = &HTTP_CKA_MAXREQ; else
	if( streq(name,"http-ckapch") )	addr = &HTTP_CKA_PERCLIENT; else
	if( streq(name,"udprelay") )	addr = &UDPRELAY_MAXASSOC; else
	{

		ERRMSG("DeleGate/%s: ERROR unknown MAXIMA=%s\n",
			DELEGATE_ver(),maxima);
	}

	if( addr ){
		xmem_push(addr,sizeof(int),"MAXIMA",NULL);
		*addr = num;
	}
	return 0;
}
void scan_MAXIMA(Connection *Conn,PCStr(maxima))
{
	scan_commaList(maxima,0,scanListCall maxima1,Conn);
}

extern int SHUTOUT_TIMEOUT;
extern int DNS_TIMEOUT;
extern int ACC_TIMEOUT;
extern int CON_TIMEOUT;
extern int LIN_TIMEOUT;
extern int IO_TIMEOUT;
extern int CC_TIMEOUT;
extern int CC_TIMEOUT_FTP;
extern int CC_TIMEOUT_NNTP;
extern int CACHE_TAKEOVER;
extern int RSLV_INV_TIMEOUT;
extern int SILENCE_TIMEOUT; /* no transmission from server or client */
extern int HELLO_TIMEOUT;
extern int VSAP_TIMEOUT;
extern int ERROR_RESTART;
extern int SERVER_RESTART;
extern int SERVER_DEFREEZE;
extern int SERVER_TIMEOUT;
extern int STANDBY_TIMEOUT;
extern int SPAWN_TIMEOUT;
extern int NONCE_TIMEOUT;
extern double RES_NIS_TIMEOUT;
extern double HTTP_WAIT_REQBODY;
extern double HTTP_TOUT_IN_REQBODY;
extern double HTTP_TOUT_CKA;
extern double HTTP_TOUT_CKA_MARGIN;
extern double SVHELLO_TIMEOUT;
extern double IDENT_TIMEOUT;
extern double CFISTAT_TIMEOUT;
extern double AUTHORIZER_TIMEOUT;
extern double WAITCHILD_TIMEOUT;
extern double BINDENTER_TIMEOUT;
extern double BIND_TIMEOUT;
extern double MAX_HTMUXSKEW;

static scanListFunc timeout1(PCStr(to),Connection *Conn)
{	CStr(name,128);
	CStr(period,128);
	double secs;
	double *daddr;
	int *iaddr;

	if( Xsscanf(to,"%[^:]:%s",AVStr(name),AVStr(period)) == 2 ){
		secs = Scan_period(period,'s',(double)0);
		daddr = 0;
		iaddr = 0;

		if( streq(name,"shutout"))   iaddr = &SHUTOUT_TIMEOUT; else
		if( streq(name,"hello"))     iaddr = &HELLO_TIMEOUT; else
		if( streq(name,"login"))     iaddr = &LOGIN_TIMEOUT; else
		if( streq(name,"dns") )	     iaddr = &DNS_TIMEOUT; else
		if( streq(name,"dnsinv") )   iaddr = &RSLV_INV_TIMEOUT; else
		if( streq(name,"nis") )      daddr = &RES_NIS_TIMEOUT; else
		if( streq(name,"vsapacc"))   iaddr = &VSAP_TIMEOUT; else
		if( streq(name,"acc") )	     iaddr = &ACC_TIMEOUT; else
		if( streq(name,"con") )	     iaddr = &CON_TIMEOUT; else
		if( streq(name,"lin") )	     iaddr = &LIN_TIMEOUT; else
		if( streq(name,"greeting"))  daddr = &SVHELLO_TIMEOUT; else
		if( streq(name,"ident"))     daddr = &IDENT_TIMEOUT; else
		if( streq(name,"rident"))    daddr = &RIDENT_TIMEOUT; else
		if( streq(name,"authorizer"))daddr = &AUTHORIZER_TIMEOUT; else
		if( streq(name,"cfistat"))   daddr = &CFISTAT_TIMEOUT; else
		if( streq(name,"silence"))   iaddr = &SILENCE_TIMEOUT; else
		if( streq(name,"io") )	     iaddr = &IO_TIMEOUT; else
		if( streq(name,"idle"))	     iaddr = &IO_TIMEOUT; else
		if( streq(name,"restart"))   iaddr = &SERVER_RESTART; else
		if( streq(name,"waitchild")) daddr = &WAITCHILD_TIMEOUT; else
		if( streq(name,"bindenter")) daddr = &BINDENTER_TIMEOUT; else
		if( streq(name,"bind"))      daddr = &BIND_TIMEOUT; else
		if( streq(name,"defreeze"))  iaddr = &SERVER_DEFREEZE; else
		if( streq(name,"erestart"))  iaddr = &ERROR_RESTART; else
		if( streq(name,"daemon"))    iaddr = &SERVER_TIMEOUT; else
		if( streq(name,"standby")  ) iaddr = &STANDBY_TIMEOUT; else
		if( streq(name,"spawn"))     iaddr = &SPAWN_TIMEOUT; else
		if( streq(name,"dgnonce")  ) iaddr = &NONCE_TIMEOUT; else
		if( streq(name,"takeover"))  iaddr = &CACHE_TAKEOVER; else
		if( streq(name,"ftpcc"))     iaddr = &CC_TIMEOUT_FTP; else
		if( streq(name,"nntpcc"))    iaddr = &CC_TIMEOUT_NNTP; else
		if( streq(name,"cc") )	     iaddr = &CC_TIMEOUT; else
		if( streq(name,"htmuxskew")) daddr = &MAX_HTMUXSKEW; else

	if( streq(name,"http-wait-qbody"))   daddr = &HTTP_WAIT_REQBODY; else
	if( streq(name,"http-poll-qbody"))   daddr = &HTTP_TOUT_IN_REQBODY; else
	if( streq(name,"http-cka"))          daddr = &HTTP_TOUT_CKA; else
	if( streq(name,"http-ckamg"))        daddr = &HTTP_TOUT_CKA_MARGIN; else
		{
			sv1tlog("ERROR: unknown TIMEOUT=%s\n",name);
		}

		if( daddr ){
			xmem_push(daddr,sizeof(double),"TIMEOUT",NULL);
			*daddr = secs;
		}
		if( iaddr ){
			xmem_push(iaddr,sizeof(int),"TIMEOUT",NULL);
			*iaddr = (int)secs;
		}
	}
	if( SERVER_TIMEOUT )
	if( SERVER_TIMEOUT < ACC_TIMEOUT || ACC_TIMEOUT == 0 )
		ACC_TIMEOUT = SERVER_TIMEOUT;

	return 0;
}
void scan_TIMEOUT(Connection *Conn,PCStr(timeouts))
{
	scan_commaList(timeouts,0,scanListCall timeout1,Conn);
}

typedef struct {
	char	*m_addr; /**/
	int	 m_size;
	char	*m_save; /**/
  const char	*m_what;
	iFUNCP	 m_func;
} Memory;

#define MAXLEV 8
typedef struct {
	Memory	*s_mem;
	int	 s_siz;
	int	 s_top;
} Stack;

static Stack mstack[MAXLEV]; /**/

#define mdebug	!lMEMPUSH() ? 0 : putLog0

int mem_push(int lev,PCStr(addr),int size,PCStr(what),iFUNCP func)
{	Stack *St;
	Memory *Me;
	int siz,top,mi;

	St = &mstack[lev];
	if( St->s_siz <= St->s_top ){
		siz = St->s_siz = St->s_siz + 32;
		if( St->s_siz ){
			St->s_mem = (Memory*)realloc(St->s_mem,siz*sizeof(Memory));
			for( mi = St->s_top; mi < siz; mi++ )
				St->s_mem[mi].m_save = 0;
		}else	St->s_mem = (Memory*)calloc(siz,sizeof(Memory));
	}
	top = St->s_top++;
	Me = &St->s_mem[top];
	if( Me->m_save != 0 ){
		if( Me->m_size < size ){
			free(Me->m_save);
			Me->m_save = 0;
		}
	}
	if( Me->m_save == 0 )
		Me->m_save = (char*)malloc(size);
	Me->m_addr = (char*)addr;
	Me->m_size = size;
	Me->m_what = what;
	Me->m_func = func;
	bcopy(addr,Me->m_save,size); /**/

	mdebug("{m} PUSH[%d][%d] %X -> %X (%d) %s\n",lev,top,
		p2i(Me->m_addr),p2i(Me->m_save),Me->m_size,Me->m_what);
	return top;
}
void mem_pop1(int lev)
{	Stack *St;
	Memory *Me;
	int mi;
	iFUNCP func;
	int diff;

	St = &mstack[lev];
	for( mi = St->s_top-1; 0 <= mi; mi-- ){
		Me = &St->s_mem[mi];
		diff = bcmp(Me->m_save,Me->m_addr,Me->m_size);
		if( func = Me->m_func )
			(*func)(Me->m_save,Me->m_addr,Me->m_size,Me->m_what);
		else	bcopy(Me->m_save,Me->m_addr,Me->m_size);

		mdebug("{m} POP%s[%d][%d] %X <- %X (%d) %s\n",diff?"!":"=",
			lev,mi,p2i(Me->m_addr),p2i(Me->m_save),Me->m_size,Me->m_what);
	}
	St->s_top = 0;
}
void mem_pops(int lev)
{	int li;

	mdebug("{m} POPS[%d]\n",lev);
	for( li = MAXLEV-1; lev <= li; li-- ){
		mem_pop1(li);
	}
}

/*
 * "(" [srcHostList] [":"[dstHostList] [":"[protList]]] ")"argument
 * AMAP=[srcHostList]:[dstHostList]:[protoList]:argument
 * conditional argument
 */

const char *skip_argcond(PCStr(arg))
{
	if( strncmp(arg,"(",1) == 0 ){
		if( arg = strstr(arg,")") )
			arg++;
	}
	return arg;
}

typedef struct {
  const	char	*ca_cond;
  const	char	*ca_arg;
  scanPFUNCP	 ca_scan; /* function to interpret the argument */
	int	 ca_src;
	int	 ca_dst;
} CondArg;
static CondArg condArg[32]; /**/
static int condArgX;

int add_condarg(PCStr(arg))
{	const char *dp;
	CStr(cond,1024);
	int cai;
	CondArg *Cp;

	if( *arg != '(' )
		return 0;
	dp = wordscanY(arg+1,AVStr(cond),sizeof(cond),"^)");
	if( *dp++ != ')' )
		return 0;
	if( *dp == 0 )
		return 0;
	if( elnumof(condArg) <= condArgX ){
		return 0;
	}
	cai = condArgX++;
	Cp = &condArg[cai];
	Cp->ca_cond = stralloc(cond);
	Cp->ca_src = makePathList("condarg",cond);
	Cp->ca_arg = stralloc(dp);
	Cp->ca_scan = param_scanner(dp);

	mdebug("{m} INIT[%s](%d) %s\n",cond,Cp->ca_src,dp);
	return 1;
}

extern int BREAK_STICKY;
extern int (*evalarg_func)(const char*,const char*);
static Connection *evalarg_Conn;

static int exec_condarg(PCStr(base),PCStr(arg),scanPFUNCP func)
{	const char *dp;
	Connection *Conn = evalarg_Conn;

	if( func ){
		if( dp = strchr(arg,'=') ){
			(*func)(evalarg_Conn,dp+1);
		}
		return 1;
	}else
	if( strneq(arg,"-v",2)
	 || strneq(arg,"-d",2)
	 || strneq(arg,"-W",2)
	){
		xmem_push(&LOG_type,sizeof(LOG_type),"-vX",NULL);
		xmem_push(&LOG_VERBOSE,sizeof(LOG_VERBOSE),"-vv",NULL);
		scan_arg1(Conn,NULL,arg);
		return 1;
	}
	return 0;
}
static int scan1(PCStr(base),PCStr(arg))
{	scanPFUNCP func;

	func = param_scanner(arg);
	exec_condarg(base,arg,func);
	return 0;
}
void scan_condargs(Connection *Conn)
{	CondArg *Cp;
	const char *arg;
	int cai;
	int match;

	match = 0;
	for( cai = 0; cai < condArgX; cai++ ){
		Cp = &condArg[cai];
		arg = Cp->ca_arg;
		if( Cp->ca_src )
		{
		/*
		if( !matchPath1(Cp->ca_src,"-",Client_Host,Client_Port) )
		*/
			const char *us;
			if( ClientAuth.i_user[0] )
				us = ClientAuth.i_user;
			else	us = "-";
			if( !matchPath1(Cp->ca_src,us,Client_Host,Client_Port) )
			continue;
			mdebug("{m} [%d]MATCH [%s]%s\n",cai,us,arg);
		}

		if( strneq(arg,"+=",2) ){
			evalarg_func = scan1;
			evalarg_Conn = Conn;
			load_script(NULL,NULL,arg+2);
			evalarg_func = 0; 
			continue;
		}

		if( match == 0 ){
			const char **sp;
			xmem_push(&extovw_argc,sizeof(int),"ext_argc",NULL);
			sp = &extovw_argv[extovw_argc]; /* end of array */
			xmem_push(sp,sizeof(char*),"ext_argv",NULL);
		}
		mdebug("{m} [%d]MATCH [%s]%s\n",extovw_argc,Client_Host,arg);
		match++;
		if( elnumof(extovw_argv) <= extovw_argc )
			syslog_ERROR("too many extovw_arg\n");
		else	extovw_argv[extovw_argc++] = (char*)arg;

		if( exec_condarg(NULL,arg,Cp->ca_scan) ){
		}else{
			sv1log("{m} Not supported (%s)%s\n",
				Cp->ca_cond,Cp->ca_arg);
			BREAK_STICKY = 1;
		}
	}
}

enum { ENV_SORT, ENV_ALL, ENV_OUT };
#define setOpt(opts,opt1)	(opts |= (1<<opt1))
#define getOpt(opts,opt1)	(opts & (1<<opt1))

static int acmp(void *a1,void *a2){
	return strcmp(*(char**)a1,*(char**)a2);
}
char **sortv(char **ov){
	char **ev;
	char *e1;
	int ei;
	char *out = 0;

	for( ei = 0; ov[ei]; ei++ );
	ev = (char**)malloc(sizeof(char*)*(ei+1));
	for( ei = 0; e1 = ov[ei]; ei++ )
		ev[ei] = e1;
	ev[ei] = 0;
	qsort(ev,ei,sizeof(char*),(sortFunc)acmp);
	return ev;
}

int ttyuid(int fd);
int env_main(int ac,const char *av[]){
	int ai,ei;
	const char *a1;
	char *e1;
	char **ev;
	int opts = 0;
	FILE *outf = stdout;
	CStr(who,128);

	for( ai = 0; ai < ac; ai++ ){
		a1 = av[ai];
		if( *a1 == '-' ){
			switch( a1[1] ){
				case 'a': setOpt(opts,ENV_ALL); break;
				case 's': setOpt(opts,ENV_SORT); break;
				case 'o':
					if( ai+1 < ac ){
						outf = fopen(av[++ai],"w");
						if( outf == 0 ){
							outf = stderr;
						}else{
							setOpt(opts,ENV_OUT);
						}
					}
					break;
			}
		}
	}
	ev = environ;
	if( getOpt(opts,ENV_SORT) ){
		ev = sortv(ev);
	}
	for( ei = 0; e1 = ev[ei]; ei++ ){
		fprintf(outf,"%s\n",e1);
	}
	if( ev != environ )
		free(ev);

	if( getOpt(opts,ENV_ALL) ){
		CStr(tmp,1024);
		IGNRETS getcwd(tmp,sizeof(tmp));
		fprintf(outf,"TTY: %d\n",ttyuid(0));
		fprintf(outf,"UID: %d\n",getuid());
		fprintf(outf,"EUID: %d\n",geteuid());
		fprintf(outf,"PWD: %s\n",tmp);
		fprintf(outf,"PPID: %d\n",getppid());
		dumpFds(outf);
	}
	return 0;
}

/*
 * 9.8.2 extracted from delegated.c {([
 */
int SERNO_MINOR();
int ismainthread();
int incthreadreqno(int tid);
int Getpid();
int uGetpid();

int incRequestSerno(Connection *Conn)
{
	if( lMULTIST() ){
		incthreadreqno(0);
	}
	return REQUEST_SERNO = ++RequestSerno;
}
int incServReqSerno(Connection *Conn)
{
	return SERVREQ_SERNO = ++ServReqSerno;
}

extern int NUM_FNSV;
extern int NUM_THSV;
extern int lock_ext;

extern char TIMEFORM_mdHMS0[];
extern char TIMEFORM_mdHMSd[];
extern char TIMEFORM_mdHMSc[];
extern char TIMEFORM_mdHMSm[];
extern char TIMEFORM_mdHMS4[];
extern char TIMEFORM_mdHMS5[];
extern char TIMEFORM_mdHMS6[];
static const char *LOG_timefmts[8] = {
	TIMEFORM_mdHMSc,
	TIMEFORM_mdHMS0,
	TIMEFORM_mdHMSd,
	TIMEFORM_mdHMSm,
	TIMEFORM_mdHMS4,
	TIMEFORM_mdHMS5,
	TIMEFORM_mdHMS6,
	"",
};
const char *LOG_timefmt = TIMEFORM_mdHMSc;
void setLogTimeFmtL(int fx){
	if( 0 <= fx && fx < elnumof(LOG_timefmts) ){
		LOG_timefmt = LOG_timefmts[fx];
	}
}
void setLogTimeFmt(PCStr(fmt)){
	int lx = 0;
	switch( *fmt ){
		case '0': case 0:   lx = 1; break;
		case '1': case 'd': lx = 2; break;
		case '2': case 'c': lx = 0; break;
		case '3': case 'm': lx = 3; break;
		case '4':           lx = 4; break;
		case '5':           lx = 5; break;
		case '6': case 'u': lx = 6; break;
		case '%':           lx = 7; LOG_timefmts[7] = stralloc(fmt);
				    break;
		default: fprintf(stderr,"UNKNOWN: -vT%s\n",fmt); break;
	}
	LOG_timefmt = LOG_timefmts[lx];
	LOG_type2 |= lx;
}
int getSessionThreadInfo(int agid,int *serno,int *reqno,int *svreu,Connection **Conn);
int getthreadserno(int tid,int *reqno);
void LOG_makeTime(PVStr(buf),int now,int usec){
	refQStr(bp,buf);
	CStr(tms,64);

	if( lMEMUSAGE() ){
		CStr(mu,128);
		static CStr(prev,128);
		strfRusage(AVStr(mu),"(%d,%r)",3,NULL);
		if( !streq(prev,mu) ){
			sprintf(bp,"%s -- MEM.DIFF.\n",mu);
			bp += strlen(bp);
			strcpy(prev,mu);
		}
		strcpy(bp,mu);
		bp += strlen(bp);
	}
	StrftimeLocal(AVStr(tms),sizeof(tms),LOG_timefmt,now,usec);
	if( lSINGLEP() ){
		int sid,serno,reqno,svreu;
		sid = getSessionThreadInfo(0,&serno,&reqno,&svreu,0);
		if( sid == 0 && serno == 0 ){
			sid = getthreadserno(0,&reqno);
		}
		sprintf(bp,"%s [%04X] %d+%d",tms,
			PRTID(getthreadid()),sid,serno);
		bp += strlen(bp);
		if( reqno ){
			sprintf(bp,"/%d",reqno);
			bp += strlen(bp);
		}
		strcpy(bp,": ");
		return;
	}

	if( (0 < LOGLEVEL || lTHREAD() || lTHREADID() ) && !ismainthread() )
		sprintf(bp,"%s [%d.%X] %d+%d",tms,
			getpid(),getthreadid(),SERNO(),SERNO_MINOR());
	else	sprintf(bp,"%s [%d] %d+%d",tms,
			uGetpid(),SERNO(),SERNO_MINOR());
			/*
			Getpid(),SERNO(),SERNO_MINOR());
			*/
	bp += strlen(bp);
	if( deleGateEnv != NULL ){
		if( REQUEST_SERNO || SERVREQ_SERNO ){
			sprintf(bp,"/%d",REQUEST_SERNO);
			bp += strlen(bp);
		}
		if( SERVREQ_SERNO ){
			sprintf(bp,"/%d",SERVREQ_SERNO);
			bp += strlen(bp);
		}
	}
	strcpy(bp,": ");
}

static int LOG_type_got;
int acceptExclusive();
void setupForSolaris()
{
	/* LOG_type is given by the parent in private-MASTER in the av[] */
	if( LOG_type_got || lLOGSHARED() )
		return;

	if( acceptExclusive() ){
		Verbose("ACCEPT EXCLUSION is ON by default.\n");
		if( (LOG_type & (L_FORK|L_EXEC)) == 0 ){
			if( LOG_type & L_LOCK )
				LOG_type &= ~L_LOCK;
			else	LOG_type |=  L_LOCK;
		}
	}
}

static void dumpLC(FILE *lfp,PCStr(wh),LogControl *lc){
	fprintf(lfp,"--LogCtrl %s [%08X %08X %08X]\n",wh,
		lc->lc_flags[0],lc->lc_flags[1],lc->lc_flags[2]);
	fflush(lfp);
}
int setupPeeping(Connection *XConn,PCStr(peepf)){
      switch( peepf[0] ){
	case '-':
		LOG_type3 &= ~(L_PEEPSV | L_PEEPCL);
		break;
	case 0:	LOG_type3 |= L_PEEPSV | L_PEEPCL; break;
	case 'q':
	  switch( peepf[1] ){
	    case   0: LOG_type3 |= L_PEEPCLDG | L_PEEPDGSV;
		break;
	    case 'c':
	    case 't': LOG_type3 |= L_PEEPCLDG; break;
	    case 's': LOG_type3 |= L_PEEPDGSV; break;
	  }
	  break;
	case 'r':
	  switch( peepf[1] ){
	    case   0: LOG_type3 |= L_PEEPSVDG | L_PEEPDGCL;
		break;
	    case 'c':
	    case 't': LOG_type3 |= L_PEEPDGCL; break;
	    case 's': LOG_type3 |= L_PEEPSVDG; break;
	  }
	  break;
	case 's':
	  switch( peepf[1] ){
	    case   0: LOG_type3 |= L_PEEPSV; break;
	    case 'r': LOG_type3 |= L_PEEPSVDG; break;
	    case 'q': LOG_type3 |= L_PEEPDGSV; break;
	  }
	  break;
	case 'c':
	case 't':
	  switch( peepf[1] ){
	    case   0: LOG_type3 |= L_PEEPCL; break;
	    case 'q': LOG_type3 |= L_PEEPCLDG; break;
	    case 'r': LOG_type3 |= L_PEEPDGCL; break;
	  }
	  break;
	}
	return 0;
}
void setupLOGMD5(PCStr(arg)){
	int width;

	if( arg[0] == '-' )
	if( arg[1] == 'E' || arg[1] == 'D' )
	if( arg[2] == 'm' )
	if( arg[3] == 'i' || arg[3] == 'o' )
	{
		if( arg[4] )
			width = atoi(arg+4);
		else	width = 8;
		if( width < 0 || 32 < width )
			width = 8;
		switch( arg[3] ){
			case 'i': LOGMD5_IN = 1+width; break;
			case 'o': LOGMD5_OUT = 1+width; break;
		}
	}
}
void featuresED(PCStr(arg)){
	int dis = (arg[1] == 'D');
	int *addr = 0;
	int flag = 0;

	switch( arg[2] ){
	    case 'A':
	     switch( arg[3] ){
	      case 'P': addr = &LOG_type4; flag = L_NOAUTHPROXY; break;
		/*
	      case 'M': addr = &LOG_type4; flag = L_NOMITMAUTH; break;
		*/
	      case 'f': addr = &LOG_type4; flag = L_FORWPAUTH; dis = !dis;break;
	     }
	     break;
	    case 'C':
	     switch( arg[3] ){
	      case 'C': addr = &LOG_type4; flag = L_CCXCOOKIE; dis= !dis; break;
	      case 'S': addr = &LOG_type4; flag = L_UNSIGNEDCRC8; break;
	      default:	addr = &LOG_type3; flag = L_NOCACHE; break;
	     }
	     break;
	    case 'H':
	     switch( arg[3] ){
	      case 'a': addr = &LOG_bugs;  flag = L_ADDRMATCH;dis = !dis; break;
	     }
	     break;
	    case 'I':
	     switch( arg[3] ){
	      case 'd': addr = &LOG_bugs;  flag = L_NOIDENT; break;
		break;
	     }
	     break;
	    case 'R':
	     switch( arg[3] ){
	      case 'u': addr = &LOG_type4; flag = L_HOSTSUPD; dis = !dis; break;
	     }
	     break;
	    case 'S':
	     switch( arg[3] ){
	      case 'p': addr = &LOG_type4; flag = L_NOSIGPIPE; break;
	     }
	     break;
	    case 'a':
	     switch( arg[3] ){
	      case 'o': addr = &LOG_type4; flag = L_ORIGDST; dis = !dis; break;
	      case 'm': addr = &LOG_bugs;  flag = L_NOAUTOMAXIMA; break;
	     }
	     break;
	    case 'c':
	     switch( arg[3] ){
	      case 'c': addr = &ECC_svCtl; flag = ECC_ENABLE; dis = !dis; break;
	      case 'p': addr = &LOG_type4; flag = L_CONNPARA; dis = !dis; break;
	      case 'q': addr = &LOG_type4; flag = L_CONNQUE; dis = !dis; break;
	      case 'r': addr = &LOG_type4; flag = L_NOCONNRECYC; break;
	      case 's':	addr = &LOG_type4; flag = L_CONNSCAT; dis = !dis; break;
	     }
	     break;
	    case 'd':
	     switch( arg[3] ){
	      case 'r': addr = &LOG_bugs; flag = L_DONTROUTE_LOCAL; dis = !dis; break;
	     }
	     break;
	    case 'f':
	     switch( arg[3] ){
	      case 'b': addr = &LOG_bugs;  flag = L_FTPDATA_NOBIND; break;
	      case 'p': addr = &LOG_bugs;  flag = L_PASV_REUSE;dis= !dis; break;
	      default:
	      case 'q': addr = &LOG_type3; flag = L_FCLOSEQ; dis = !dis; break;
	     }
	     break;
	    case 'h':
	     switch( arg[3] ){
	      case 'a': addr = &LOG_type4; flag = L_HTTPACCEPT;dis= !dis; break;
	     }
	     break;
	    case 'i':
	     switch( arg[3] ){
	      case 'd': addr = &LOG_type4; flag = L_DOSOCKDUP;dis = !dis; break;
	      case 'c': addr = &LOG_type4; flag = L_COPYCLADDR;dis= !dis; break;
	      case 'p': addr = &LOG_type4; flag = L_SOCKPAIRNM;dis= !dis; break;
	      case 's': addr = &LOG_type4; flag = L_NOSOCKINH;
		if( dis )
			LOG_type4 &= ~L_DOSOCKINH;
		else	LOG_type4 |=  L_DOSOCKINH;
		break;
	      case 't': addr = &LOG_type4; flag = L_WOSOCKINH; break;
	     }
	     break;
	    case 'k':
	     switch( arg[3] ){
	      case 0:	addr = &LOG_type3; flag = L_NOSERVKA|L_NOCLNTKA; break;
	      case 's': case 'v':
			addr = &LOG_type3; flag = L_NOSERVKA; break;
	      case 'c': case 't':
			addr = &LOG_type3; flag = L_NOCLNTKA; break;
	     }
	     break;
	    case 'l':	addr = &LOG_type3; flag = L_NOMMAPLOG; break;
	    case 'm':
	     switch( arg[3] ){
	      case 'i': setupLOGMD5(arg); break;
	      case 'o': setupLOGMD5(arg); break;
	      default:
	      case 'm': addr = &LOG_type3; flag = L_NOMMAP; break;
	     }
	     break;
	    case 'n':
	     switch( arg[3] ){
	      case 'h': addr = &LOG_type4; flag = L_DONTHT; dis = !dis; break;
	      case 'i': addr = &LOG_bugs;  flag = L_NULSTDIN; dis = !dis;break;
	      case 's': addr = &LOG_bugs;  flag = L_DNS_SORT; dis = !dis;break;
	     }
	     break;
	    case 'p':
	     switch( arg[3] ){
	      case 'd': addr = &LOG_bugs;  flag = L_NOPAM_DYLIB; break;
	     }
	     break;
	    case 'r':
	     switch( arg[3] ){
	      case 'i': addr = &LOG_type4; flag = L_IMMREJECT; dis = !dis;break;
	      case 's': addr = &LOG_type4; flag = L_DOSRCREJECT;dis= !dis;break;
	     }
	     break;
	    case 's':
	     switch( arg[3] ){
	      case 'b': addr = &LOG_bugs;  flag = L_BLOCKNONSSL;dis= !dis;break;
	      case 'c': addr = &LOG_bugs;  flag = L_SCOUNTER; dis = !dis; break;
	      case 'f': addr = &LOG_bugs;  flag = L_SFTP_FILTER;dis= !dis;break;
	      case 'p': addr = &LOG_bugs;  flag = L_PEEKSSL;    dis= !dis;break;
	      case 's': addr = &LOG_bugs;  flag = L_HTTPSCLONLY;dis= !dis;break;
	      case 't': addr = &LOG_type3; flag = L_NOSSLCHECK; break;
	     }
	     break;
	    case 't':
	     switch( arg[3] ){
	      case 'c': addr = &LOG_bugs;  flag = L_THREADCFI;dis = !dis; break;
	      case 'i': addr = &LOG_bugs;  flag = L_THREADID; dis = !dis; break;
	      case 'l': addr = &LOG_bugs;  flag = L_THREADLOG;dis = !dis; break;
	      case 'm': addr = &LOG_bugs;  flag = L_MTSS_TMCONV;dis= !dis;break;
	      case 'e': addr = &LOG_bugs;  flag = L_MTSS_PUTENV;dis= !dis;break;
	      case 's': addr = &LOG_bugs;  flag = L_MTSS_NOSSIG; break;
	      case 'y': addr = &LOG_type4; flag = L_THFORKSYNC; dis= !dis;break;
	      case 'w': addr = &LOG_type4; flag = L_TSWATCHER; dis= !dis;break;
	       default: addr = &LOG_type2; flag = L_NOTHREAD; break;
	     }
	     break;
	    case 'u':	addr = &LOG_type3; flag = L_NOUDPLOG; break;
	    case 'z':	addr = &LOG_type3; flag = L_NOGZIP; break;
	    case 'w':   addr = &LOG_type3; flag = L_NOWIN; break;
	}
	if( addr != 0 && flag != 0 ){
		if( dis ){
			*addr |= flag;
		}else{
			*addr &= ~flag;
		}
	}
}
void setNumProcThread(PCStr(spec)){
	int nproc = 0;
	int nthread = 0;

	sscanf(spec,"%d+%d",&nproc,&nthread);
	if( nproc == 1 ){
		LOG_type3 |= L_SINGLEP;
		NUM_THSV = 1;
		if( 1 <= nthread ){
			NUM_THSV = nthread + 1;
			LOG_type3 |= L_MULTIST;
		}
	}else{
		LOG_type4 |= L_FXNUMSERV;
		NUM_FNSV = nproc;
	}
}

void setWinClassTitleStyle(PCStr(wclass),PCStr(wtitle),PCStr(wstyle));
int setDebugX(Connection *XConn,PCStr(arg),int force){
	const char *as;
	const char *val = &arg[2];
	int lev;
	LogControl olc;

	if( arg[0] != '-' )
		return 0;

	olc = *logControl;
	if( !force && lLOGSHARED() ){
	}else
	switch( arg[1] ){
	    case 'B':
		switch( arg[2] ){ 
		    case 'a': LOG_bugs |= L_SISALIVE; break;
		    case 'c':
			switch( arg[3] ){
			    case 's': LOG_bugs |= ENBUG_CONTLENG_304; break;
			}
			break;
		    case 'd': LOG_bugs |= ENBUG_NULLFP_DUPCLOSED; break;
		    case 'f': LOG_bugs |= ENBUG_NULLFP_FCLOSE; break;
		    case 'i':
			switch( arg[3] ){
			    case 's': LOG_type3 |= L_FGETSBB_IZ; break;
			}
			break;
		    case 'n': LOG_bugs |= ENBUG_WIN_NTFS_TIME; break;
		    case 'p':
			switch( arg[3] ){
			    case 'b': LOG_bugs |= ENBUG_POST_BUFF; break;
			}
			break;
		    case 's':
			switch( arg[3] ){
			    case 'e': LOG_bugs |= ENBUG_NOSTDERR; break;
			    case 'p': LOG_bugs |= ENBUG_STLS_BY_PROTO; break;
			}
			break;
		    case 't':
			switch( arg[3] ){
			    case 'w': LOG_bugs |= L_NOTHWAITBUG; break;
			    case 'i': LOG_bugs |= ENBUG_TID64; break;
			}
			break;
		    default:
			if( val[0] == '0' && val[1] == 'x' ){
				sscanf(val,"0x%x",&LOG_bugs);
			}else
		LOG_bugs |= (1 << atoi(&arg[2])-1);
				break;
		}
		break;
	    case 'D':
		featuresED(arg);
		break;
	    case 'E': /* enable optional features */
		featuresED(arg);
		break;
	    case 'R':
		RAND_TRACE = 1;
		LOG_type1 |= L_RAND_TRACE;
		break;
	    case 'L':
		LOG_type_got = 1;
		if( val[0] == '0' ){
			sscanf(val,"0x%x",&LOG_type1);
		}else
		if( val[0] == '2' ){
			/*
			sscanf(val,"20x%x",&LOG_type2);
			*/
			sscanf(val,"20x%x/%x",&LOG_type2,&LOG_bugs);
		}else
		if( val[0] == '3' ){
			sscanf(val,"30x%x/%x",&LOG_type3,&LOG_type4);
		}
		break;
	    case 'p':
		PEEK_CLIENT_REQUEST = 1;
		break;
	    case 't':
		LOG_type |= L_TTY;
		break;
	    case 'l':
		switch( arg[2] ){ 
		    case 's':
			LOG_type2 |= L_LOCKSHARED;
			lock_ext = 0;
			break;
		    default:
			LOG_type1 |= L_LOCK;
			break;
		}
		break;
	    case 'x':
		if( arg[2] == 's' )
			LOG_type1 |= L_FORK;
		else
		if( arg[2] == 'x' )
			LOG_type2 |= L_SEXEC;
		else
		if( arg[2] == 'f' )
			LOG_type4 |= L_EXECFILTER;
		else	LOG_type1 |= L_EXEC;
		break;

	    case 'w':
		if( arg[2] == 0 )
			LOG_type1 |= 1;
		else
		if( arg[2] == 'c' ){
			setWinClassTitleStyle(arg+3,0,0);
		}else
		if( arg[2] == 'i' || arg[2] == 'm' || arg[2] == 'n' ){
			setWinClassTitleStyle(0,0,arg+2);
		}else
		if( arg[2] == 't' ){
			setWinClassTitleStyle(0,arg+3,0);
		}else
		if( arg[2] == 'H' ){
			PollIn_HUP(0);
			fprintf(stderr,"POLLHUP disabled\n");
		}else
		if( '0' <= arg[2] && arg[2] <= '9' )
			LOG_type1 = (LOG_type1 & ~0xF) | (arg[2]-'0');
		break;
	    case 'n':
		setNumProcThread(arg+2);
		break;
	    case 'd':
		switch( arg[2] ){
		    case '0': LOG_type3 |= L_CURRENT; return 1;
		    case '1': case '2': case '3': case '4':
		    case '5': case '6': case '7': case '8': case '9':
			setNumProcThread(arg+2);
			return 1;
		    case 'c':
			if( arg[3] != '0' )
				LOG_type3 |= L_CONNECT;
			return 1;
		    case 'e':	LOG_type3 |= L_ENVIRON; return 1;
		    case 'g':	LOG_type3 |= L_THREADSIG; return 1;
		    case 'm':
			if( arg[3] ){
				LOG_type3 |= (L_MALLOC & atoi(&arg[3]));
			}else	LOG_type3 |= (L_MALLOC & 1);
			return 1;
		    case 'p':
			LOG_type4 |= L_PROCLOG;
			return 1;
		    case 'r':
			LOG_bugs |= L_RETERR;
			return -1;
		    case 'w':
			switch( arg[3] ){
			    case 's':
				LOG_type3 |= L_WINSOCK;
				break;
			}
			break;
		    case 'x': LOG_type3 |= L_TRANSMIT; return 1;
		    case 'z': LOG_type3 |= L_ZLIB; return 1;
		    case 'Z':
			if( arg[3] == 0 )
			      LOG_type3 |= L_NOGZIP;
			return 1;

		    case 'f': LOG_type1 |= L_FILETRACE; break;
		    case 'h': LOG_type1 |= L_HOSTMATCH; break;
		    case 's': LOG_type1 |= L_SOCKET; break;
		    case 't': LOG_type1 |= L_THREAD; break;
		    case 'M': LOG_type1 |= L_MOUNT; break;
		    case 'B': LOG_type2 |= L_COUNTER; break;
		    case 'C': LOG_type2 |= L_CHARSET; break;
		    case 'D': LOG_type2 |= L_DEBUGMSG; break;
		    case 'G': LOG_type2 |= L_GATEWAY; break;
		    case 'H': LOG_type2 |= L_HTMLGEN;
			if( arg[3] == '2' )
			      LOG_type2 |= L_HTMLGENV;
			break;
		    case 'L': LOG_type2 |= L_DEBUGLOCK; break;
		    case 'O': LOG_type2 |= L_FILEOPEN; break;
		    case 'P': LOG_type2 |= L_PATHFIND; break;
		    case 'S': LOG_type2 |= L_SECRET; break;
		    case 'T': LOG_type2 |= L_TLS; break;
		    case 'U': LOG_type2 |= L_URLFIND; break;
		    case 'W': LOG_type2 |= L_NO_WSOCKWA; break;
		    case 'F': LOG_type2 |= L_EMU_NOFORK; break;
		    case 'V': LOG_type2 |= L_NO_VSNPRINTF; break;
		    case 'A': LOG_type2 |= L_ACCESSCTL; break;
		    default:  LOG_type1 |= L_ARGDUMP;
			break;
		}
		break;

	    case 'v':
		if( arg[2] == 0 ){
			LOG_type1 |= L_FG | L_TTY;
		}else
		for( as = arg+2; *as; as++ ){
		    switch( *as ){
			case 'L': LOG_type3 |= L_LOGCTRL; break;
			case 'M': LOG_type3 |= L_MEMUSAGE; break;
			case 'F': LOG_type2 |= L_FILEDESC; break;
			case 'l': LOG_type2 |= L_DYLIB; break;
			case 'P': LOG_type2 |= L_POLL; break;
			case 'T': as += strlen(as)-1; break;
			case 'W': LOG_type2 |= L_SPAWNLOG; break;
			case 'S': LOG_type2 |= L_NOPROTOLOG; break;
			case 's': LOG_type1 |= L_SILENT; break;
			case 't': LOG_type1 |= L_TERSE; break;
			case 'u': /* usual */
				LOG_type1 &= ~(L_SILENT|L_TERSE|L_VERB);
				LOG_VERBOSE = 0;
				break;
			case 'v': LOG_type1 |= L_FG | L_TTY | L_VERB; break;
			case 'c': LOG_type1 |= L_CONSOLE; break;
			case 'd': LOG_type1 |= L_VERB; break;
			case 'a': LOG_type1 |= L_VERBABORT; break;
			case 'p': setupPeeping(XConn,as+1);
				as += strlen(as)-1; break;
			case 'Q': break; /* tmp. QUIET on loading self */
			case 'q': LOG_type4 |= L_QUIET; break;
			case 'r': LOG_type4 &= ~L_QUIET; break;
			case 'm': LOG_type1 |= L_MEMPUSH; break;
			case 'z': LOG_type3 |= L_ZLIB; break;
			case '2':
			case '3':
			case '4':
				lev = *as - '0';
				LOG_type1 = LOG_type1 & ~L_LEVEL | lev;
				break;
		    }
		}
		break;
	}

	switch( arg[1] ){
	    case 'v':
		if( arg[2] == 0 ){
		}else
		for( as = arg+2; *as; as++ ){
		    switch( *as ){
			case 'T': setLogTimeFmt(as+1);
				as += strlen(as)-1; break;
		    }
		}
		break;
	    case 'L':
		if( val[0] == '0' ){
		}else{
			setLogTimeFmtL(LOG_type2&L_TIMEFMT);
		}
		break;
	    case 'd':
		switch( arg[2] ){
		    case 'R': RES_debug(arg+3); break;
		}
		break;
	}

	if( lLOGCTRL() ){
		dumpLC(stderr,"OLD",&olc);
		dumpLC(stderr,"NEW",logControl);
	}
	return 0;
}
int setDebugForce(PCStr(arg)){
	return setDebugX(0,arg,1);
}
int setDebug(PCStr(arg)){
	return setDebugX(0,arg,0);
}

/* ])} */


#define DEF_NAMECONN	0x00010000 /* subst. name with Connection info. */
#define DEF_DATACONN	0x00020000 /* subst. data Connection info. */
#define DEF_DATAURL	0x00040000 /* subst. URL */

typedef struct {
	int dd_flags;
	const char *dd_name;
	const char *dd_data;
} DefData;
static DefData **defData;
#define NDGDEF 64
void scan_DGDEF(Connection *Conn,PCStr(defdata)){
	DefData *dd;
	int di;
	IStr(nametype,256);
	IStr(name,256);
	const char *data;
	const char *flags;

	data = wordScanY(defdata,nametype,"^:");
	if( *data == ':' )
		data++;
	flags = wordScanY(nametype,name,"^,");
	InitLog("DGDEF=%s[%s]:%s\n",name,flags,data);
	if( *flags == ',' )
		flags++;
	if( defData == 0 ){
		defData = (DefData**)malloc(NDGDEF*sizeof(DefData*));
		bzero(defData,sizeof(defData));
	}
	for( di = 0; di < NDGDEF; di++ ){
		dd = defData[di];
		if( dd == 0 ){
			dd = (DefData*)malloc(sizeof(DefData));
			bzero(dd,sizeof(DefData));
			defData[di] = dd;
			break;
		}
		if( streq(dd->dd_name,name) ){
			break;
		}
	}
	if( NDGDEF <= di ){
		return;
	}
	if( strchr(name,'%') )       dd->dd_flags |= DEF_NAMECONN;
	if( isinList(flags,"conn") ) dd->dd_flags |= DEF_DATACONN;
	if( isinList(flags,"url")  ) dd->dd_flags |= DEF_DATAURL;
	if( isinList(flags,"ei")   ) dd->dd_flags |= DGD_EVAL_ONINIT;
	if( isinList(flags,"si")   ) dd->dd_flags |= DGD_SUBST_ONINIT;
	dd->dd_name = (char*)stralloc(name);
	dd->dd_data = (char*)stralloc(data);
}
int evalDGDEF(Connection *Conn,PCStr(nametype),PVStr(data),int dz,int opts){
	DefData *dd;
	int di;
	IStr(xname,128);

	if( defData == 0 ){
		return 0;
	}
	for( di = 0; di < NDGDEF; di++ ){
		dd = defData[di];
		if( dd == 0 ){
			return 0;
		}
		if( opts & DGD_EVAL_ONINIT ){
		}
		if( dd->dd_flags & DEF_NAMECONN ){
			strfConnX(Conn,nametype,AVStr(xname),sizeof(xname));
		}else	strcpy(xname,nametype);
		if( streq(dd->dd_name,xname) ){
			if( dd->dd_flags & DEF_DATACONN )
				strfConnX(Conn,dd->dd_data,BVStr(data),dz);
			else	strcpy(data,dd->dd_data);
			return 1;
		}
	}
	return 0;
}
char *substDGDEF(Connection *Conn,PCStr(pat),PVStr(data),int dz,int opts,int encoding){
	const char *pp;
	const char *ep;
	int pc;
	refQStr(dp,data);
	IStr(nametype,256);
	refQStr(np,nametype);
	int subst = 0;

	if( defData == 0 ){
		return (char*)pat;
	}
	for( pp = pat; pc = *pp; pp++ ){
	  if( pp[0] == '_' && pp[1] == '{' ){
	    np = nametype;
	    for( ep = pp+2; *ep; ep++ ){
		if( ep[0] == '}' && ep[1] == '_' ){
			setVStrPtrInc(np,0);
			if( evalDGDEF(Conn,nametype,AVStr(dp),dz,opts) ){
				if( encoding & DGD_ESC_QUOTE ){
					strsubst(AVStr(dp),"\\","\\\\");
					strsubst(AVStr(dp),"\"","\\\"");
				}
				pp = ep+1;
				dp += strlen(dp);
				subst++;
				goto NEXTCH;
			}
		}
		setVStrPtrInc(np,*ep);
	    }
	  }
	  setVStrPtrInc(dp,pc);
	NEXTCH:;
	}
	if( subst ){
		setVStrPtrInc(dp,0);
		return (char*)data;
	}else{
		return (char*)pat;
	}
}

/*
 * 9.9.8 DYCONF like conditional argutmets "(cond)arg"
 *       DYCONF=[options]file:file.conf
 *       DYCONF=cgi:file.cgi
 *       DYCONF=cfi:file.cfi
 *       DYCONF=pat/pattern,arg:{argList}
 * DYCONF=reqpat:type:value
 */
#define lxDYCONF() (dyconf_debug || 2<=LOGLEVEL || LOG_VERBOSE)
int systemFilter(PCStr(command),FILE *in,FILE *out);
int NoHangWait();
int recvPEEK(int sock,PVStr(buf),int size);
int execGeneralist(Connection *Conn,int fromC,int toC,int svsock);
void clearAdhocSERVER(Connection *Conn);
int makePathList(PCStr(what),PCStr(path));
void *Regcomp(const char *pat,int flag);
int Regexec(void *re,const char *str,int nm,int so,int eo,int flag);

enum _SkipType {
	SK_PEEKED = 1, /* all peeked */
	SK_BYTES  = 2, /* number of octets */
	SK_LINES  = 3, /* number of LF */
	SK_HEADER = 4, /* till CR-LF */
} SkipType;
typedef struct _DYConf {
     const char	*dc_arg;
     const char	*dc_cgi;
     const char	*dc_file;
	int	 dc_exclusive; /* exclusive alternative (1 - 32) */
	double	 dc_poll;    /* timeout of request polling */
	int	 dc_peek;    /* size of peeked request */
	int	 dc_from;    /* hostlist to filter client host */
	int	 dc_clif;    /* hostlist to filter incoming interface */
     const char	*dc_qstr;    /* filtering request by string */
	void	*dc_qrex;    /* filtering request by rex. pattern */
	int	 dc_skiphow; /* SkipType: bytes, lines, head */
	int	 dc_skip;    /* skip size */
	int	 dc_debug;   /* detailed debugging for this entry ? */
} DYConf;
static DYConf *DYCONFv[16];
static int DYCONFx;
static int dyconf_done;
static int dyconf_regex;
static int dyconf_debug;

/*
 * CGI-Headers:
 *   DYCONF-Control: skip           ... purge peeked input
 *   DYCONF-Control: skip/N         ... N bytes
 *   DYCONF-Control: skip/Nlines    ... Nlines
 *   DYCONF-Control: skip/head      ... until CRLF
 */
typedef struct _CLArg {
	double	 da_poll;    /* the mak of dc_poll */
	int	 da_peek;    /* the max of dc_peek */
	int	 da_dopoll;  /* to do poll(ClientSock) */
	int	 da_dopeek;  /* to do peek request */
	int	 da_nosticky; /* DYCONF-Control: nosticky */
	int	 da_withcgi; /* with CGI */
	int	 da_pid;     /* CGI process ID */
	int	 da_peeked;  /* peeked request byte count */
	int	 da_toskip;  /* request to be skipped */
} CLArg;

static struct {
	int	sc_nrst;
	int	sc_argc;
	MStr(	sc_proto,32);
	MStr(	sc_host,256);
	int	sc_port;
} savconf;
static void restoreConf(Connection *Conn){
	if( savconf.sc_argc == 0 ){
		savconf.sc_argc = ext_argc;
		strcpy(savconf.sc_proto,DFLT_PROTO);
		strcpy(savconf.sc_host,DFLT_HOST);
		savconf.sc_port = DFLT_PORT;
	}else{
		savconf.sc_nrst++;
		ext_argc = savconf.sc_argc;
		ext_argv[ext_argc] = 0;
		strcpy(DFLT_PROTO,savconf.sc_proto);
		strcpy(DFLT_HOST,savconf.sc_host);
		DFLT_PORT = savconf.sc_port;
clearAdhocSERVER(Conn);
	}
}

static int scanDCControl(Connection *Conn,PCStr(line),CLArg *CA){
	IStr(arg,URLSZ);
	IStr(v,32);
	int rcc;

	if( strneq(line,"Content-Type:",13) ){
		return 1;
	}
	if( strneq(line,"DYCONF-Control:",15) ){
		lineScan(line+15,arg);
		if( strneq(arg,"skip",4) ){
			if( getParam(AVStr(arg),"bytes",AVStr(v),sizeof(v),1) ){
				CA->da_toskip = atoi(v);
			}else{
				CA->da_toskip = CA->da_peeked;
			}
		}
		return 2;
	}
	return 0;
}
static int evalDYCONF1(Connection *Conn,PCStr(iline),CLArg *CA){
	IStr(line,URLSZ);
	const char *vp;

	if( lxDYCONF() ){
		sv1log("--DYCONF (add) %s\n",iline);
	}
	strcpy(line,iline);
	if( vp = parameq(line,"SERVER") ){
		IStr(proto,32);
		Xsscanf(vp,"%[^:]",AVStr(proto));
		Conn->no_dstcheck_proto = serviceport(proto);
		if( strstr(line,":-:") == 0 ){
			/* to force re-init. of SERVER */
			strcat(line,":-:*");
		}
	}else
	if( parameq(line,"REMITTABLE")
	){
	}else{
		BreakSticky = 1;
	}
	scan_arg1(Conn,"",line);
	return 0;
}
static int scanArg1(PCStr(arg1),Connection *Conn,CLArg *CA){
	evalDYCONF1(Conn,arg1,CA);
	return 0;
}
static void scanArgs(Connection *Conn,DYConf *DA,CLArg *CA,PCStr(args)){
	scan_ListL(args,';',STR_ALLOC,scanListCall scanArg1,Conn,CA);
}
static int evalCGIOUT(Connection *Conn,FILE *cfp,CLArg *CA){
	IStr(line,URLSZ);

	for(;;){
		if( Fgets(AVStr(line),sizeof(line),cfp) == NULL ){
			break;
		}
		if( *line == 0 || *line == '\r' || *line == '\n' ){
			break;
		}
		sv1log("----DYCONF head %s\n",line);
		scanDCControl(Conn,line,CA);
	}
	for(;;){
		if( Fgets(AVStr(line),sizeof(line),cfp) == NULL ){
			break;
		}
		sv1log("----DYCONF body %s\n",line);
		if( scanDCControl(Conn,line,CA) ){
		}else{
			evalDYCONF1(Conn,line,CA);
		}
	}
	return 0;
}
static char *bin_escape(PCStr(src),int len,PVStr(dst),int siz){
	refQStr(dp,dst);
	int ch;
	int li;

	for( li = 0; li < len; li++ ){
		ch = 0xFF & src[li];
		if( ch < 0x20 || 0x7F <= ch ){
			sprintf(dp,"%%%02X",ch);
			dp += strlen(dp);
		}else{
			setVStrPtrInc(dp,ch);
		}
	}
	setVStrPtrInc(dp,0);
	return (char*)dp;
}
static int peekREQ(Connection *Conn,int clsock,CLArg *CA,PVStr(req),int qsz){
	int rdy;
	int psiz;
	int qrcc;
	double St = Time();

	rdy = PollIn(clsock,(int)(1000*CA->da_poll));
	if( rdy <= 0 ){
		sv1log("##DYCONF [%d] rdy=%d\n",clsock,rdy);
		return -2;
	}
	if( qsz < CA->da_peek )
		psiz = qsz;
	else	psiz = CA->da_peek;
	qrcc = recvPEEK(clsock,AVStr(req),psiz);
	if( qrcc <= 0 ){
		sv1log("##DYCONF [%d] rdy=%d rcc=%d\n",clsock,rdy,qrcc);
		return -3;
	}
	if( lxDYCONF() ){
		sv1log("--DYCONF peekd %d (%.3f)\n",qrcc,Time()-St);
	}
	return qrcc;
}
static void cumArg(Connection *Conn,CLArg *CA){
	int cx;
	DYConf *DC;
	double poll = -9;
	int peek = -9;

	bzero(CA,sizeof(CLArg));
	for( cx = 0; cx < DYCONFx; cx++ ){
		DC = DYCONFv[cx];
		if( DC->dc_poll && poll < DC->dc_poll ){
			poll = DC->dc_poll;
		}
		if( DC->dc_peek && peek < DC->dc_peek ){
			peek = DC->dc_peek;
		}
		if( DC->dc_qstr || DC->dc_qrex
		 || DC->dc_cgi /* req. to be tested in the CGI */
		 ){
			CA->da_dopoll = 1;
			CA->da_dopeek = 1;
		}
		if( DC->dc_cgi ){
			CA->da_withcgi++;
		}
	}
	if( peek < -1 ){
		peek = 4*1024;
	}
	CA->da_peek = peek;
	if( poll < -1 ){
		poll = 15;
	}
	CA->da_poll = poll;
}
static void confFile(Connection *Conn,DYConf *DC,CLArg *CA){
	FILE *cfp;
	if( cfp = fopen(DC->dc_file,"r") ){
		evalCGIOUT(Conn,cfp,CA);
		fclose(cfp);
	}else{
		sv1log("----DYCONF FATAL cannot load: %s\n",DC->dc_file);
	}
}
static void confCGI(Connection *Conn,DYConf *DC,CLArg *CA,FILE *reqin,PCStr(ereq)){
	IStr(command,1024);
	IStr(esock,32);
	FILE *confout;

	fseek(reqin,0,0);
	sprintf(command,"%s",DC->dc_cgi);
	if( *ereq ){
		putenv(ereq);
	}
	if( 0 <= esock ){
		sprintf(esock,"CLSOCK=%d",ClientSock);
		putenv(esock);
	}
	confout = TMPFILE("DYCONF-Out");
	/* should push and pop CGI env */
	CA->da_pid = systemFilter(command,reqin,confout);
	putenv("CLSOCK=");
	putenv("CLREQ=");
	fseek(confout,0,0);
	if( CA->da_pid < 0 ){
		sv1log("----DYCONF FATAL failed: %s\n",command);
	}
	evalCGIOUT(Conn,confout,CA);
	fclose(confout);
}
static int matchDYCONF(Connection *Conn,CLArg *CA,DYConf *DC,int clsock,PCStr(ereq)){
	int match;
	if( DC->dc_from ){
		VA_getClientAddr(Conn);
		match = matchPath1(DC->dc_from,"-",Client_Host,Client_Port);
		if( !match ){
			return 0;
		}
	}
	if( DC->dc_clif ){
		if( CLIF_PORT == 0 ){
			CLIF_PORT = gethostAddr(clsock,AVStr(CLIF_HOST));
		}
		HL_setClientIF(CLIF_HOST,CLIF_PORT,1);
		match = matchPath1(DC->dc_clif,"-",CLIF_HOST,CLIF_PORT);
		HL_setClientIF(NULL,0,1);
		if( !match ){
			return 0;;
		}
	}
	if( DC->dc_qstr ){
		if( strstr(ereq,DC->dc_qstr) == 0 ){
			return 0;;
		}
	}
	if( DC->dc_qrex ){
		if( Regexec(DC->dc_qrex,ereq,0,0,0,0) != 0 ){
			return 0;;
		}
	}
	return 1;
}
int load_DYCONF(Connection *Conn,int clsock){
	IStr(breq,URLSZ);
	IStr(ereq,URLSZ*3+1);
	CLArg CLb,*CA = &CLb;
	DYConf *DC;
	int cx;
	int pqrcc;
	int added = 0;
	int exclusive = 0;
	FILE *reqin = 0;

	if( DYCONFx <= 0 ){
		return 0;
	}

	cumArg(Conn,CA);
	if( CA->da_dopeek ){
		pqrcc = peekREQ(Conn,clsock,CA,AVStr(breq),sizeof(breq));
		if( pqrcc <= 0 ){
			return pqrcc;
		}
	}else{
		pqrcc = -9;
	}
	CA->da_peeked = pqrcc;
	restoreConf(Conn);

	if( CA->da_withcgi ){
		reqin = TMPFILE("DYCONF-In");
	}
	if( 0 < pqrcc ){
		if( reqin ){
			fwrite(breq,1,pqrcc,reqin);
			fflush(reqin);
		}
		strcpy(ereq,"CLREQ=");
		bin_escape(breq,pqrcc,TVStr(ereq),sizeof(ereq));
	}

	for( cx = 0; cx < DYCONFx; cx++ ){
		DC = DYCONFv[cx];
		if( !matchDYCONF(Conn,CA,DC,clsock,ereq) ){
			continue;
		}
		if( DC->dc_exclusive ){
			int mask;
			mask = 1 << (DC->dc_exclusive-1);
			if( exclusive & mask ){
				continue;
			}else{
				exclusive |= mask;
			}
		}

		if( DC->dc_skip ){
			CA->da_toskip = pqrcc;
		}
		if( DC->dc_arg ){
			scanArgs(Conn,DC,CA,DC->dc_arg);
			added |= 1;
		}
		if( DC->dc_file ){
			confFile(Conn,DC,CA);
			added |= 2;
		}
		if( DC->dc_cgi ){
			confCGI(Conn,DC,CA,reqin,ereq);
			added |= 4;
		}
	}
	if( 0 < CA->da_toskip ){
		int kqrcc;
		kqrcc = read(ClientSock,ereq,CA->da_toskip);
		Verbose("----DYCONF-skip: %d/%d\n",kqrcc,CA->da_toskip);
	}
	if( 0 < CA->da_pid ){ 
		int xpid;
		xpid = NoHangWait();
	}
	if( reqin ){
		fclose(reqin);
	}
	return added;
}

/*
 * DYCONF="control"
 * DYCONF="control?arg1;arg2"  ... if control then arg1 else arg2
 * DYCONF="[control,]type:value"
 *   DYCONF="arg:{A=B;C=D}"
 *   DYCONF="cgi:path.cgi"
 *   DYCONF="file:path.txt"
 * options:
 *   default | otherwise | stopother | finished | radio/N | exclusive/N
 *   class/N | depend/N
 *   ConfigraionSet N ... for HostList, ConnMap and Routing
 *     config. version A.B.C.D  (A + B + C + D)
 *   poll/Ts
 *   peek/{Nbytes,Nlines,head}
 *   skep/{Nbytes,Nlines,head}
 *   {qstr/String}
 *   {qrex/Pattern}
 * possibly interaction with client, possibly with prompting.
 * possibly as an extension of MASTER
 */
static int scanOpt1(PCStr(opt1),Connection *Conn,DYConf *DC){
	IStr(name,32);
	IStr(del,32);
	IStr(value,1024);

	Xsscanf(opt1,"%[^/{:]%[/{:]%[^\n]",AVStr(name),AVStr(del),AVStr(value));
	if( strtailchr(del) == '{' && strtailchr(value) == '}' ){
		setVStrEnd(value,strlen(value)-1);
	}
	if( streq(name,"debug") ){
		dyconf_debug = 1;
		DC->dc_debug = 1;
	}
	if( lxDYCONF() ){
		sv1log("--DYCONF <%s> <%s> <%s>\n",name,del,value);
	}
	if( streq(name,"poll") ){
		DC->dc_poll = (int)Scan_period(value,'s',(double)0);
	}
	if( streq(name,"peek") ){
		DC->dc_peek = kmxatoi(value);
	}
	if( streq(name,"excl") ){
		DC->dc_exclusive = atoi(value);
		if( DC->dc_exclusive <= 0 ){
			DC->dc_exclusive = 1;
		}
	}
	if( streq(name,"qstr") ){
		DC->dc_qstr = stralloc(value);
	}
	if( streq(name,"qrex") ){
		DC->dc_qrex = Regcomp(value,0);
		dyconf_regex = 1;
	}
	if( streq(name,"from") ){
		DC->dc_from = makePathList("DYCONF-from",value);
	}
	if( streq(name,"clif") ){
		DC->dc_clif = makePathList("DYCONF-clif",value);
	}
	if( streq(name,"skip") ){
		DC->dc_skip = 1;
		DC->dc_skiphow = SK_PEEKED;
	}
	if( streq(name,"arg") ){
		DC->dc_arg = stralloc(value);
	}
	if( streq(name,"cgi") ){
		DC->dc_cgi = stralloc(value);
	}
	if( streq(name,"file") ){
		DC->dc_file = stralloc(value);
	}
	return 0;
}
void scan_DYCONF(Connection *Conn,PCStr(dyconf)){
	DYConf *DC;

	if( dyconf_done ){
		return;
	}
	if( lxDYCONF() ){
		sv1log("--DYCONF (%d) %s\n",DYCONFx,dyconf);
	}
	if( streq(dyconf,"(done)") ){
		if( DYCONFx == 0 ){
			return;
		}
		dyconf_done = 1;
		if( dyconf_regex ){
			/* if no static library is linked */
			/* regex_lib_init() */
		}
		return;
	}
	DC = (DYConf*)malloc(sizeof(DYConf));
	bzero(DC,sizeof(DYConf));
	scan_ListL(dyconf,',',STR_ALLOC,scanListCall scanOpt1,Conn,DC);
	DYCONFv[DYCONFx++] = DC;
}
