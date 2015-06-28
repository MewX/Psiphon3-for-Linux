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
Program:	admin.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

	- control DeleGate server from remote client via HTTP
	- dynamic MOUNT from a remote client via HTTP
	- public DeleGate tree (share log and consistency info. ?)

History:
	941009	extracted from http.c
	990716	extracted from httpd.c
//////////////////////////////////////////////////////////////////////#*/
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "vsocket.h" /* send() and recv(), must before delegate.h (?) */
#include "delegate.h"
#include "fpoll.h"
#include "proc.h"
#include "file.h"
#include "auth.h"
#include "url.h"
#include "http.h"
#define SVSTATDIR	"svstats9"

#include "htadmin.h"
static AdminCtx *adminCtx;
AdminCtx *myAdminCtx(Connection *Conn){
	if( lMULTIST() ){
		if( STX_adminCtx == 0 ){
			STX_adminCtx = calloc(sizeof(AdminCtx),1);
		}
		return (AdminCtx*)STX_adminCtx;
	}else{
		if( adminCtx == 0 ){
			adminCtx = (AdminCtx*)calloc(sizeof(AdminCtx),1);
		}
		return adminCtx;
	}
	return 0;
}

#define rename(old,new) renameRX(old,new) /* for Win32 */

int setSoftBreak(Connection *Conn,PCStr(port));
int toSafeFileName(PCStr(name),PVStr(xname));

#define FPRINTF		leng += Fprintf
extern int START_TIME;
extern const char *TIMEFORM_HTTPD;
int HTML_scan1(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(val));
int HTML_ccxput1s(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(val));
int HTML_put1sX(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(val));
#define put1sX HTML_put1sX

int putBuiltinPageX(Connection *Conn,int vno,FILE *tc,PCStr(what),PCStr(upath),PCStr(desc),iFUNCP func,PCStr(arg),int flags);
#define BP_NOCLENG	1

int dump_confdata(PVStr(msg),Connection *Conn,FILE *fp,PCStr(fmt));

const char *config_self = "_self_";
int get_serverinitlog(FILE *tmp);

static int pushgenv(Connection *Conn,PCStr(env)){
	int sp;
	if( elnumof(admin_genv)+1 < admin_genc ){
		return -1;
	}
	sp = admin_genc++;
	admin_genv[sp] = stralloc(env);
	admin_genv[sp+1] = 0;
	return sp;
}
static int popgenv(Connection *Conn,int sp){
	const char *env;
	if( sp < 0 || elnumof(admin_genv)+1 <= sp ){
		return -1;
	} 
	if( env = admin_genv[sp] ){
		free((char*)env);
	}
	admin_genv[sp] = 0;
	admin_genc = sp;
	return sp;
}

int upath_off_limit(PCStr(path),PVStr(npath));
int StrSubstDateX(PVStr(str),PVStr(cur));
FILE *dgfopen(PCStr(what),PCStr(base),PCStr(rpath),PCStr(mode));

int strfSocket(PVStr(desc),int size,PCStr(fmt),int fd);
int file_statX(int fd,int *sizp,int *mtmp,int *atmp,int *uidp,int *ftype);
int foreachfile(FILE *fp,PCStr(pm1),PCStr(pm2)){
	int fx = 0;
	int fd;
	int size,mtime,atime,uid,off,ft;
	CStr(desc,1024);
	CStr(tmp,1024);
	const char *ftype;

	fprintf(fp,"<PRE>");
	for( fd = 0; fd < 256; fd++ ){
		ftype = NULL;
		strcpy(desc,"");
		if( 0 < file_issock(fd) ){
			ftype = "socket";
			strfSocket(AVStr(desc),sizeof(desc),"%A",fd);
		}else
		if( 0 < file_isfifo(fd) ){
			ftype = "fifo";
		}else
		if( isatty(fd) ){
			ftype = "tty";
		}else
		if( file_statX(fd,&size,&mtime,&atime,&uid,&ft) == 0 ){
			switch( ft ){
				case 'd': ftype = "dir"; break;
				case 'l': ftype = "link"; break;
				case '-': ftype = "file"; break;
				case 'p': ftype = "fifo"; break;
				default:  ftype = "dir?"; break;
			}
			if( uid == 0 )
				strcpy(desc,"root,");
			else
			if( uid == getuid() )
				strcpy(desc,"mine,");
			else	strcpy(desc,"others,");
			Xsprintf(TVStr(desc),"size=%d",size);
			if( ft == '-' ){
				Xsprintf(TVStr(desc),",off=%d",ll2i(Lseek(fd,0,1)));
			}
		}
		if( ftype == NULL )
			continue;
		fprintf(fp,"%2d [%2d] %-6s %s\n",fx++,fd,ftype,desc);
	}
	fprintf(fp,"</PRE>\n");
	return 1;
}


#define A_IDENT			0x00F
#define A_EVALED_IDENT		0x001
#define A_WITH_IDENTD		0x002	/* with identd, thus authenticated */
#define A_OK_IDENTAUTHOR	0x004	/* authorized */
#define A_PASS			0xFF0
#define A_EVALED_PASS		0x010
#define A_WITH_PASSAUTH		0x020	/* with password auth. */
#define A_OK_PASSAUTHEN		0x040	/* authenticated */
#define A_OK_PASSAUTHOR		0x080	/* authorized */
#define A_REJ_PASSAUTHEN	0x100	/* not authenticated */
#define A_REJ_PASSAUTHOR	0x200	/* not authenticated */

static struct {
	FILE	*m_Fp;
	int	 m_FpPid;
  const	char	*m_lastset;
} Mtab;
#define MtabFp		Mtab.m_Fp
#define MtabFpPid	Mtab.m_FpPid
#define lastset		Mtab.m_lastset

void MtabFileName(PCStr(user),PVStr(path));
static FILE *MtabFile(PCStr(user),int create)
{	CStr(path,1024);
	FILE *fp;

	if( lSINGLEP() ){
		return 0;
	}
	if( lFXNUMSERV() ){
		return 0;
	}
	Verbose("MtabFile(%s,%d) init=[%d] Fp=%x\n",
		user,create,MtabFpPid,p2i(MtabFp));

	if( MtabFpPid == getpid() )
		goto EXIT;

	if( MtabFp != NULL )
		fclose(MtabFp);

	MtabFileName(user,AVStr(path));
	MtabFp = dirfopen("MTAB",AVStr(path),"r+");

	if( MtabFp == NULL && create )
		MtabFp = dirfopen("MTAB",AVStr(path),"w+");

	if( MtabFp != NULL ){
		MtabFpPid = getpid();
		if( create )
			setCloseOnExec(fileno(MtabFp));
	}
EXIT:
	if( MtabFp != NULL ){
		fp = fdopen(dup(fileno(MtabFp)),"r+");
		if( fp == NULL ){
			sv1log("#### ERROR! MtabFile cannot fdopen(%d/%X)\n",
				fileno(MtabFp),p2i(MtabFp));
			return NULL;
		}
		fseek(fp,0,0);
		return fp;
	}
	return NULL;
}

int DHTML_printMount(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(name),PCStr(param))
{	FILE *mfp;
	CStr(iline,1024);
	CStr(line,1024);
	CStr(vpat,256);
	CStr(rpat,1024);
	CStr(opts,256);
	CStr(vurl,256);
	CStr(rurl,1024);
	CStr(uurl,256);
	const char *dp;
	CStr(xline,1024);

	mfp = MtabFile("anybody",0);
	if( mfp == NULL )
		return 0;

	while( fgets(iline,sizeof(iline),mfp) != NULL ){
		strsubst(AVStr(iline),"&","%26");
		encodeEntitiesY(iline,AVStr(line),sizeof(line),"&\"<>",1);
		opts[0] = 0;
		Xsscanf(line,"%s %s %[^\r\n]",AVStr(vpat),AVStr(rpat),AVStr(opts));

		if( streq(param,"mtab") ){
			strcpy(vurl,vpat);
			if( dp = strrchr(vurl,'*') ) if( dp[1] == 0 ) truncVStr(dp);
			if( !streq(iSERVER_PROTO,CLNT_PROTO) ){
				CStr(tmp,256);
				CStr(hp,MaxHostNameLen);
				int port;
				strcpy(tmp,vurl);
				if( 0 < (port = Conn->clif._userPort) ){
					HTTP_ClientIF_H(Conn,AVStr(hp));
					Xsprintf(TVStr(hp),":%d",port);
				}else
				if( 0 <= getUserPort1(NULL,&port) ){
					HTTP_ClientIF_H(Conn,AVStr(hp));
					Xsprintf(TVStr(hp),":%d",port);
				}else	HTTP_ClientIF_HP(Conn,AVStr(hp));
				sprintf(vurl,"%s://%s%s",iSERVER_PROTO,hp,tmp);
			}
			strcpy(rurl,rpat);
			if( dp = strrchr(rurl,'*') ) if( dp[1] == 0 ) truncVStr(dp);
			sprintf(uurl,"/-/admin/unmount?%s",vpat);
			strsubst(AVStr(vpat),"%26","&amp;");
			strsubst(AVStr(rpat),"%26","&amp;");

 sprintf(xline,
"<A HREF=\"%s\">U</A> <A HREF=\"%s\">%-24s</A> <A HREF=\"%s\">%-40s</A> %s\r\n",
uurl,vurl,vpat,rurl,rpat,opts);
 HTML_scan1(Conn,fp,fmt,xline);
		}
	}

	fclose(mfp);
	return 1;
}
int putBuiltinPage(Connection *Conn,int vno,FILE *tc,PCStr(what),PCStr(upath),PCStr(desc),iFUNCP func,PCStr(arg));
static int putMount(Connection *Conn,int vno,FILE *tc,PCStr(fromp))
{
	return putBuiltinPage(Conn,vno,tc,"Mount","admin/MountForm.dhtml",
		NULL,(iFUNCP)DHTML_printConn,fromp);
}
void sort_file(FILE *src,FILE *dst,int rev);
int form2v(PVStr(form),int maxargc,const char *argv[]);

static void unMount(Connection *Conn)
{	FILE *mfp,*tmp;
	CStr(line,1024);
	CStr(vpat,256);
	const char *vurl;

	if( Form_argc < 0 ){
		return;
	}
	vurl = Form_argv[0];

	mfp = MtabFile("anybody",0);
	if( mfp == NULL )
		return;

	tmp = TMPFILE("UNMOUNT");
	while( fgets(line,sizeof(line),mfp) != NULL ){
		wordScan(line,vpat);
		if( strcmp(vurl,vpat) != 0 )
			fputs(line,tmp);
	}
	fflush(tmp);
	fseek(tmp,0,0);
	fseek(mfp,0,0);

	lock_exclusiveNB(fileno(mfp));
	copyfile1(tmp,mfp);
	lock_unlock(fileno(mfp));

	fclose(tmp);
	Ftruncate(mfp,0,1);
}
static int mountControl(Connection *Conn,int vno,PCStr(method),FILE *fc,FILE *tc,PCStr(who))
{	const char *action;
	const char *user;
	const char *fromp;
	const char *tol;
	const char *comment;
	const char *val;
	CStr(froms,256);
	CStr(tos,256);
	const char *bp;
	CStr(line,1024);
	CStr(froma,1024);
	FILE *mfp = NULL;
	CStr(msg,1024);
	int leng;
	FILE *tmp;

	if( strncmp(method,"POST",4) != 0 ) /* and not GET /action'?'args... */
	if( Form_argc <= 1 )
	{
		leng = putMount(Conn,vno,tc,"");
		return leng;
	}

	action  = getv(Form_argv,"action");
	fromp   = getv(Form_argv,"vurl-path");
	tol     = getv(Form_argv,"rurl-login");
	user    = getv(Form_argv,"user");
	comment = getv(Form_argv,"comment");

	sv1log("MOUNT: [%s] from=[%s] to=[%s] src=[%s]\n",
		action?action:"", fromp?fromp:"",tol?tol:"",user?user:"");

	if( action == 0 ){
		sprintf(msg,"Missing action specification.\n");
		goto error;
	}

	if( fromp == 0 || fromp[0] == 0 ){
		sprintf(msg,"Missing left hand part.\n");
		goto error;
	}

	mfp = MtabFile("anybody",1);
	if( mfp == NULL ){
		sprintf(msg,"Cannot open MTAB file\n");
		goto error;
	}

	if( streq(action,"mount") ){
		if( fromp[0] == '/' )
			froms[0] = 0;
		else	strcpy(froms,"/");
		if( val = getv(Form_argv,"vurl-path") ) strcat(froms,val);
		if( strtailchr(froms) != '*' )
			if( val = getv(Form_argv,"vurl-tail") )
							strcat(froms,val);

		if( tol == NULL || tol[0] == 0 ){
			sprintf(msg,"Missing right hand part.\n");
			goto error;
		}
		tos[0] = 0;
		if( val = getv(Form_argv,"rurl-proto") ) strcat(tos,val);
		if( val = getv(Form_argv,"rurl-login") ) strcat(tos,val);
		if( val = getv(Form_argv,"rurl-tail") )  strcat(tos,val);

		/*
		if( file_size(fileno(mfp)) == 0 ){
			fprintf(mfp,"/-*\t=\t.delegate\n");
			fflush(mfp);
			fseek(mfp,0,0);
		}
		*/

		while( fgets(line,sizeof(line),mfp) != NULL ){
			wordScan(line,froma);
			if( strcmp(froms,froma) == 0 ){
				sprintf(msg,"Duplicate MOUNT for '%s'\n",froms);
				goto error;
			}
		}

		lock_exclusiveNB(fileno(mfp));
		fprintf(mfp,"%s\t%s\towner=%s\n",froms,tos,who);
		fflush(mfp);
		fseek(mfp,0,0);
		sort_file(mfp,mfp,1);
		lock_unlock(fileno(mfp));

		lastset = froms;
	}else
	if( streq(action,"unmount") ){
		tmp = TMPFILE("UNMOUNT");
		while( fgets(line,sizeof(line),mfp) != NULL ){
			int ai;
			const char *from1;
			int match = 0;

			wordScan(line,froma);
			for( ai = 0; from1 = Form_argv[ai]; ai++ ){
				if( strncmp(from1,"vurl-path=",10) == 0 )
					if( strcmp(from1+10,froma) == 0 ){
						match = 1;
						break;
					}
			}
			if( !match )
				fputs(line,tmp);
		}
		fflush(tmp);
		fseek(tmp,0,0);
		fseek(mfp,0,0);

		lock_exclusiveNB(fileno(mfp));
		copyfile1(tmp,mfp);
		lock_unlock(fileno(mfp));

		fclose(tmp);
		Ftruncate(mfp,0,1);
	}else
	if( streq(action,"jump") ){
		CStr(myhp,MaxHostNameLen);
		CStr(url,1024);

		ClientIF_HP(Conn,AVStr(myhp));
		sprintf(url,"http://%s%s",myhp,fromp);
		leng = putMovedTo(Conn,tc,url);
		goto EXIT;
	}else{
 fprintf(stderr,"-- no MOUNT action [%s]\n",action);
	}
	fclose(mfp);

	lastset = 0;
	leng = putMovedTo(Conn,tc,"/-/admin/mount");
	goto EXIT;

error:
	if( mfp != NULL )
		fclose(mfp);
	fprintf(tc,"%s",msg);
	leng = 1;
EXIT:
	return leng;
}
void dynamic_config(Connection *Conn)
{	FILE *fp;
	CStr(line,1024);

	fp = MtabFile("anybody",0);
	if( fp == NULL )
		return;

	/* if( "/-*" is not mounted )
		scan_MOUNT(Conn,"/-* ="); */

	while( fgets(line,sizeof(line),fp) )
		scan_MOUNT(Conn,line);
	fclose(fp);
	init_mtab();
}

int popenx(PCStr(command),PCStr(mode),FILE *io[2]);
int fpopenx(PVStr(msg),PCStr(com),PCStr(mode),FILE *fpv[2]){
	int pid;
	int xpid;
	FILE *fp;
	int ch;

	if( 0 < (pid = popenx(com,mode,fpv)) ){
		fp = fpv[0];
		if( streq(mode,"r") ){
			if( fPollIn(fp,8*1000) <= 0 ){
				sprintf(msg,"-No response from '%s'\n",com);
				fclose(fpv[0]);
				NoHangWait();
				pid = -1;
			}else{
				/*
				waiting the process discards the buffer for pipe
				xpid = NoHangWait();
				if( xpid == pid ){
					pid = 0;
				}
				*/
				/*
				ch = getc(fp);
				if( ch == EOF ){
					xpid = NoHangWait();
					if( xpid == pid ){
						pid = -1;
					}
				}else{
					ungetc(ch,fp);
				}
				*/
			}
		}
		return pid;
	}
	return -1;
}

int admin_getvuniqX(Connection *Conn,PCStr(name));
#define admin_getvuniq(nm) admin_getvuniqX(Conn,nm)
int copyFileAndStat(PCStr(src),PCStr(dst));
int copyFileAndStatX(PCStr(src),PCStr(dst),PCStr(mode));
static void dumpfile(FILE *in,FILE *out,PCStr(ctype),int toHTML,PCStr(putln),int seln,int deln,PCStr(repl),int txmax,int bimax,int bicol);

#define setLastSSLout(out) setLastSSLoutX(Conn,out)
static void setLastSSLoutX(Connection *Conn,PCStr(out)){
	CStr(path,1024);
	int ai;
	const char *dp;

	sprintf(path,"cert-lastout=%s",out);
	if( dp = strtailstr(path,".pem") )
		truncVStr(dp);
	for( ai = 0; ai < admin_genc; ai++ ){
		if( strncmp(admin_genv[ai],"cert-lastout=",13) == 0 ){
			admin_genv[ai] = strdup(path);
			return;
		}
	}
	admin_genv[admin_genc++] = strdup(path);
}
#define setCertError(arg) setCertErrorX(Conn,arg)
static void setCertErrorX(Connection *Conn,PCStr(arg)){
	CStr(err,128);
	sprintf(err,"cert-error=%s",arg);
	admin_genv[admin_genc++] = strdup(err);
}

static void newCA(Connection *Conn,PVStr(rmsg)){
	FILE *fp;

	rename("dgca.cnf","dgca.cnf.sav");
	if( fp = fopen("dgca.cnf","w") ){
		CStr(conf,2048);
		CStr(xurl,1024);
		const char *url = "/-/builtin/config/dgca.cnf";
		if( 0 < getBuiltinData(Conn,"DGCA",url,
			AVStr(conf),sizeof(conf),AVStr(xurl)) ){
			fputs(conf,fp);
		}else{
			Xsprintf(TVStr(rmsg),"- Cannot create dgca.cnf\n");
		}
		fclose(fp);
	}

	rename("dgca.pem","dgca.pem.sav");
	rename("dgcaidx.txt","dgcaidx.txt.sav");
	if( fp = fopen("dgcaidx.txt","w") ){
		fclose(fp);
	}
	rename("dgcaidx.txt.attr","dgcaidx.txt.attr.sav");
	if( fp = fopen("dgcaidx.txt.attr","w") ){
		fprintf(fp,"unique_subject = no\n");
		fclose(fp);
	}

	rename("serial","serial.sav");
	if( fp = fopen("serial","w") ){
		fprintf(fp,"00\n");
		fclose(fp);
	}
	mkdirRX("certs");
	mkdirRX("emcerts");
}

static int OpenSSL(PVStr(rmsg),Connection *Conn,FILE *fp,PCStr(args)){
	CStr(path,1024);
	CStr(file,128);
	CStr(sslcom,1024);
	CStr(com,1024);
	const char *arg;
	FILE *fpv[2];
	int pid;
	CStr(resp,16*1024);
	int rcc;
	CStr(cwd,1024);
	const char *a1;
	FILE *conf;
	FILE *newconf;
	const char *out;
	const char *email = 0;
	const char *capass = 0;
	static CStr(env,64);
	CStr(sdate,128);

	if( rmsg == NULL ){
		sv1log("FATAL: admin:OpenSSL called without rmsg\n");
		return 0;
	}

	arg = wordScan(args,com);
	if( streq(args,"isCA") ){
		int isCA;
		sprintf(path,"${ADMDIR}/dgca/dgca.pem");
		Substfile(path);
		isCA = File_is(path);
		return isCA;
	}

	IGNRETS getcwd((char*)cwd,sizeof(cwd));
	sprintf(path,"${ADMDIR}/dgca");
	Substfile(path);

	if( streq(com,"req") ){
		if( !File_is(path) ){
			mkdirRX(path);
		}
	}
	if( chdir(path) != 0 ){
		Xsprintf(TVStr(rmsg),"- Cannot chdir to ADMDIR/dgca\n");
		return 0;
	}
	if( streq(com,"resetCA") ){
		int ok;
		if( (a1 = admin_getv("cert-capass")) == 0 || *a1 == 0 ){
			Xsprintf(TVStr(rmsg),"- enter the CA passphrase\n");
			setCertError("cert-capass");
			goto EXIT;
		}
		ok = SignRSA("dgca.pem",NULL,a1,NULL,0,VStrNULL,NULL);
		if( AdminPass && ok == 0 ){
			CStr(md5,128);
			toMD5(a1,md5);
			if( strcaseeq(AdminPass+4,md5) )
				ok = 1;
		}
		if( ok == 0 ){
			Xsprintf(TVStr(rmsg),"- bad CA passphrase\n");
			setCertError("cert-capass");
			goto EXIT;
		}
		newCA(Conn,BVStr(rmsg));
		goto EXIT;
	}
	if( (a1 = admin_getv("com")) && streq(a1,"setupCA") ){
		if( admin_getvuniq("cert-capass") < 2 ){
			Xsprintf(TVStr(rmsg),"- enter the same passphrase twice\n");
			setCertError("cert-capass");
			goto EXIT;
		}
		if( !File_is("dgca.cnf") ){
			newCA(Conn,BVStr(rmsg));
		}
	}
	if( streq(args,"lastout") ){
		FILE *ofp;
		if( (a1 = admin_getv("cert-lastout")) && *a1 ){
			toSafeFileName(a1,AVStr(file));
			Strins(AVStr(file),"emcerts/");
			ofp = dgfopen("CA",".",file,"r");
			if( ofp == NULL && strtailstr(file,".pem") == 0 ){
				strcat(file,".pem");
				ofp = dgfopen("CA",".",file,"r");
			}
			if( ofp ){
		dumpfile(ofp,fp,"text/plain",1,0,0,0,NULL,32*1024,512,64);
				copyfile1(ofp,fp);
				fclose(ofp);
			}else{
				fprintf(fp,"- Cannot open %s\n",a1);
			}
		}
		goto EXIT;
	}
	if( streq(com,"download") ){
		FILE *cfp;
		const char *lastout;

		lastout = admin_getv("cert-lastout");
		if( lastout && *lastout ){
			toSafeFileName(lastout,AVStr(file));
			cfp = dgfopen("CA","emcerts",file,"r");
			if( cfp == NULL ){
				strcat(file,".pem");
				cfp = dgfopen("CA","emcerts",file,"r");
			}
		}else{
			lastout = "newreq.pem";
			cfp = fopen("newreq.pem","r");
		}
		if( cfp != NULL ){
			copyfile1(cfp,fp);
			fclose(cfp);
		}else{
			fprintf(fp,"Nonexistent: %s\n",lastout);
		}
		goto EXIT;
	}
	if( (a1 = admin_getv("cert-capass")) && *a1 ){
		capass = a1;
	}

	sprintf(sslcom,"openssl %s",args);
	Xsprintf(TVStr(sslcom)," -config new.cnf");
	if( (a1 = admin_getv("cert-days")) && 0 < atoi(a1) ){
		Xsprintf(TVStr(sslcom)," -days %d",atoi(a1));
	}else{
		Xsprintf(TVStr(sslcom)," -days %d",365);
	}
	if( streq(com,"req") ){
		if( (a1 = admin_getv("com")) && streq(a1,"setupCA") ){
			if( capass == NULL )
				capass = AdminPass;
			sprintf(env,"CAPASS=%s",capass);
			putenv(env);
			Xsprintf(TVStr(sslcom)," -passout env:CAPASS");
		}else
		if( (a1 = admin_getv("cert-dodes")) && streq(a1,"on") ){
			a1 = admin_getv("cert-pass");
			if( a1 == 0 || *a1 == 0 ){
			Xsprintf(TVStr(rmsg),"- enter the passphrase twice\n");
				setCertError("cert-pass");
				goto EXIT;
			}
			if( admin_getvuniq("cert-pass") < 2 ){
			Xsprintf(TVStr(rmsg),"- inconsistent passphrases\n");
				setCertError("cert-pass");
				goto EXIT;
			}
			Xsprintf(TVStr(sslcom)," -passout pass:%s",a1);
		}else{
			Xsprintf(TVStr(sslcom)," -nodes");
		}

		if( (a1 = admin_getv("cert-notext")) && streq(a1,"on") ){
		}else{
			Xsprintf(TVStr(sslcom)," -text");
		}
		if( (a1 = admin_getv("cert-nopubkey")) && streq(a1,"on") ){
		}else{
			Xsprintf(TVStr(sslcom)," -pubkey");
		}
		if( (a1 = admin_getv("cert-selfsign")) && streq(a1,"on") ){
			Xsprintf(TVStr(sslcom)," -x509");
		}
		out = "newreq.pem";
		Xsprintf(TVStr(sslcom)," -keyout %s",out);
		Xsprintf(TVStr(sslcom)," -out %s",out);
	}else
	if( streq(com,"ca") ){
		if( AdminPass ){
			if( capass == NULL )
				capass = AdminPass;
			if( capass == NULL ){
				capass = "";
			}
			sprintf(env,"CAPASS=%s",capass);
			putenv(env);
			Xsprintf(TVStr(sslcom)," -passin env:CAPASS");
		}
		if( (a1 = admin_getv("cert-notext")) && streq(a1,"on") ){
			Xsprintf(TVStr(sslcom)," -notext");
		}else{
		}
		if( (a1 = admin_getv("cert-startdate")) && 0 < atoi(a1) ){
			strcpy(sdate,a1);
			strsubst(AVStr(sdate)," ","");
			Xsprintf(TVStr(sslcom)," -startdate %s",sdate);
		}
		if( (a1 = admin_getv("cert-enddate")) && 0 < atoi(a1) ){
			strcpy(sdate,a1);
			strsubst(AVStr(sdate)," ","");
			Xsprintf(TVStr(sslcom)," -enddate %s",sdate);
		}
		out = "newcert.pem";
		Xsprintf(TVStr(sslcom)," -out %s",out);
		Xsprintf(TVStr(sslcom)," -infiles newreq.pem");
	}else{
		out = 0;
	}
	if( out ){
		unlink(out);
		setLastSSLout(out);
	}

	newconf = fopen("new.cnf","w");
	if( newconf == NULL ){
		Xsprintf(TVStr(rmsg),"- Cannot create ADMDIR/dgca/new.cnf\n");
		return 0;
	}
	if( conf = fopen("dgca.cnf","r") ){
		copyfile1(conf,newconf);
		fclose(conf);
	}else{
		Xsprintf(TVStr(rmsg),"- Cannot open ADMDIR/dgca/dgca.cnf\n");
	}
	if( (a1 = admin_getv("com")) && streq(a1,"setupCA") ){
		email = DELEGATE_ADMIN;
		fprintf(newconf,"commonName=%s\n","Administrator of DeleGate");
	}else
	if( (a1 = admin_getv("cert-email")) && *a1 != 0 ){
		email = a1;
	}else{
		Xsprintf(TVStr(rmsg),"- Specify an emailAddress\n");
		setCertError("cert-email");
		goto EXIT;
	}

	/* in [ CA_default ] */
	if( (a1 = admin_getv("cert-issuer")) && *a1 != 0 ){
		CStr(em,128);
		wordScan(a1,em);
		fprintf(newconf,"private_key=emcerts/%s.pem\n",em);
		fprintf(newconf,"certificate=emcerts/%s.pem\n",em);
	}else{
		fprintf(newconf,"private_key=dgca.pem\n");
		fprintf(newconf,"certificate=dgca.pem\n");
	}
	fprintf(newconf,"\n");
	fprintf(newconf,"[ req_distinguished_name ]\n");
	if( streq(com,"req") ){
		int ai;
		for( ai = 0; a1 = Form_argv[ai]; ai++ ){
			if( strneq(a1,"cert--",6) ){
				CStr(nam,64);
				CStr(val,256);
				scan_namebody(a1+6,AVStr(nam),sizeof(nam),
					"=",AVStr(val),sizeof(val),"\r\n");
				if( 2 < strlen(val) )
					fprintf(newconf,"%s=%s\n",nam,val);
			}
		}
	}

	if( email ){
		const char *ep;
		if( (ep = strchr(email,'@')) == 0
		 || ep == email
		 || ep[1] == 0
		){
			Xsprintf(TVStr(rmsg),"- Invalid emailAddress\n");
			setCertError("cert-email");
			goto EXIT;
		}
		fprintf(newconf,"emailAddress=%s\n",email);
	}
	fclose(newconf);

	Xsprintf(TVStr(rmsg),"$ %s\n\n",sslcom);
	Substfile(sslcom);
	fflush(fp); /* not to inherit (duplicate) buff. to the command */
	pid = fpopenx(BVStr(rmsg),sslcom,"rR",fpv);

	if( 0 < pid ){
		if( 0 < (rcc = fread(resp,1,sizeof(resp)-1,fpv[0])) ){
			setVStrEnd(resp,rcc);
			Xsprintf(TVStr(rmsg),"%s\n",resp);
			if( strstr(resp,":error:") ){
				setCertError("openssl");
			}
			if( strstr(resp,"invalid,") ){
				if( strstr(resp,"start date") )
					setCertError("cert-startdate");
				if( strstr(resp,"end date") )
					setCertError("cert-enddate");
			}
			if( strstr(resp,":bad decrypt:") ){
				setCertError("cert-capass");
			}
		}
		fclose(fpv[0]);
		NoHangWait();
		if( (a1 = admin_getv("com")) && streq(a1,"setupCA") ){
			if( out ){
			copyFileAndStat(out,"dgca.pem");
			}
			setLastSSLout("dgca.pem");
		}
		if( email && out ){
			CStr(ofile,128);
			sprintf(ofile,"%s.pem",email);
			toSafeFileName(ofile,AVStr(file));
			Strins(AVStr(file),"emcerts/");
			if( streq(com,"req") ){
				copyFileAndStat(out,file);
				setLastSSLout(ofile);
			}
			if( streq(com,"ca") ){
				copyFileAndStatX(out,file,"a");
				setLastSSLout(ofile);
			}
		}
	}
EXIT:
	IGNRETZ chdir(cwd);
	return 1;
}

static int system_df(PVStr(msg),PCStr(apath),PVStr(out),int size){
	CStr(path,1024);
	CStr(comd,1024);
	int pid;
	int rcc;
	int percent;
	int leng = 0;
	FILE *fpv[2];
	FILE *fp;
	const char *dp;

	strcpy(path,"${VARDIR}");
	if( apath ){
		CStr(param,32);
		CStr(upath,1024);
		strcpy(param,"DGROOT");
		strcpy(upath,"/");
		Xsscanf(apath,"%[^/]%[^${}]",AVStr(param),AVStr(upath));
		sprintf(path,"${%s}%s",param,upath);
	}

	Substfile(path);
	sprintf(comd,"df \"%s\"",path);
	sv1log("## system.df = %s\n",comd);
	setVStrEnd(out,0);

	if( 0 < (pid = fpopenx(BVStr(msg),comd,"r",fpv)) ){
		fp = fpv[0];
		if( fPollIn(fp,8*1000) <= 0 ){
			leng = sprintf(out,"-No response from df\n");
			rcc = 0;
		}else{
			if( fgets(out,size,fp) != NULL )
				rcc = fread((char*)out,1,QVSSize(out,size),fp);
			else	rcc = -1;
			if( 0 < rcc ){
			    setVStrEnd(out,rcc);
			    if( dp = strchr(out,'%') ){
				for( dp--; out <= dp; dp-- )
					if( dp[-1] < '0' || '9' < dp[-1] )
						break;
				percent = atoi(dp);
				sprintf(out,"Disk Usage: %d%%\n",percent);
				leng = strlen(out);
			    }
			}
		}
		fclose(fp);
		NoHangWait();
	}
	return leng;
}

static int systemStatus(PVStr(msg),Connection *Conn,PCStr(com),FILE *tc){
	const char *dp;
	int leng = 0;
	int rcc;
	CStr(path,1024);
	CStr(comd,1024);
	CStr(out,16*1024);
	refQStr(op,out);
	const char *ox = &out[sizeof(out)-1];
	CStr(line,1024);
	int pid = -1;
	FILE *fpv[2];
	FILE *fp;

	fflush(tc); /* not to inherit (duplicate) buff. to the command */
	if( com == 0 || *com == 0 ){
		fprintf(tc,"select a command\n");
	}else
	if( streq(com,"uptime") ){
		if( 0 < (pid = fpopenx(BVStr(msg),"uptime","r",fpv)) ){
			fp = fpv[0];
			if( fgets(out,sizeof(out),fp) != NULL ){
				CStr(up,32);
				CStr(la,32);
				truncVStr(up);
				truncVStr(la);
				if( dp = strcasestr(out,"up ") )
					wordScanY(dp+3,up,"^,");
				if( dp = strcasestr(out,"load ") ){
					if( dp = strchr(dp,':') )
						lineScan(dp+1,la);
				}
				if( up[0] == 0 ){
					Xsscanf(out,"%*s %*s %s",AVStr(up));
				}
				if( la[0] == 0 ){
					if( dp = strrchr(out,':') ){
						lineScan(dp+1,la);
					}
				}
			leng = fprintf(tc,"Uptime: %s\r\nLoad Average: %s\r\n",
					up,la);
			}
			fclose(fp);
			NoHangWait();
		}
	}
	else
	if( streq(com,"netstat")
	 || streq(com,"route")
	 || streq(com,"ifconfig")
	){
		CStr(syscom,128);
		strcpy(syscom,com);
		if( streq(com,"netstat") ){
			strcpy(syscom,"netstat -an");
		}else
		if( streq(com,"route") ){
			strcpy(syscom,"netstat -rn");
		}else
		if( streq(com,"ifconfig") && isWindows() ){
			strcpy(syscom,"ipconfig");
		}

		if( 0 < (pid = fpopenx(BVStr(msg),syscom,"r",fpv)) ){
			int li;
			fp = fpv[0];
			for( li = 0;; li++ ){
				if( fgets(line,sizeof(line),fp) == NULL )
					break;
				leng += fprintf(tc,"%s",line);
			}
			fclose(fp);
			NoHangWait();
		}
	}
	else
	if( streq(com,"ps") ){
		const char *filt = admin_getv("filter");
		if( filt && atoi(filt) < 100 ){
			Xsprintf(BVStr(msg),"bad process filter\n");
		}else
		if( 0 < (pid = fpopenx(BVStr(msg),"ps gl","r",fpv)) ){
			int li;
			int uidoff = 0;
			const char *tp;
			fp = fpv[0];
			for( li = 0;; li++ ){
				if( fgets(line,sizeof(line),fp) == NULL )
					break;
				/* skip uid */
				if( li == 0 ){
					if( tp = strstr(line,"UID") ){
						uidoff = tp-line + 3;
					}
				}
				if( uidoff ){
					int ui;
					tp = line;
					for( ui = 0; ui<uidoff && *tp!=0; ui++ )
						tp++;
				}else{
				for( tp = line; *tp == ' '; tp++ );
				for(; *tp != ' '; tp++ );
				}

				if( 0 < li ){
					if( filt ){
						if( strstr(tp,filt) == 0 )
							continue;
					}else
					if( strcasestr(tp,"delegate") == 0 )
						continue;
				}
				leng += fprintf(tc,"%s",tp);
			}
			fclose(fp);
			NoHangWait();
		}
	}
	else
	if( streq(com,"df") ){
		leng = system_df(BVStr(msg),NULL,AVStr(out),sizeof(out));
		fputs(out,tc);
	}
	if( com && *com && leng <= 0 )
	{
		leng =
		fprintf(tc,"Error\r\n");
	}
	return leng;
}

FILE *fopen_authlog(PCStr(proto),PCStr(clhost),PCStr(mode));
void put_authlog(Connection *Conn,PCStr(proto),PCStr(clhost),AuthInfo *ident,int lerr,PCStr(reason)){
	CStr(stime,32);
	CStr(line,1024);
	FILE *fp;
	const char *host;
	CStr(addr,128);
	const char *user = ident->i_user;

	host = Client_Host;
	VA_inetNtoah(Client_VAddr,AVStr(addr));
	if( fp = fopen_authlog(proto,host,"a") ){
		StrftimeLocal(AVStr(stime),sizeof(stime),"%y%m%d-%H%M%S",
			time(0),0);
		sprintf(line,"%s %s %d %s/%s %s/%d \"%s\" \"%s\"",
			stime,proto,lerr,
			host,addr,
			CLNT_PROTO,Conn->clif._acceptPort,
			user,reason);
		sv1log("## AUTHLOG %s\n",line);
		fprintf(fp,"%s\n",line);
		fclose(fp);
		if( fp = fopen_authlog(proto,"ALL","a") ){
			fprintf(fp,"%s\n",line);
			fclose(fp);
		}
	}
}
FILE *freverse(FILE *ofp,int size){
	char *buff;
	char *sp;
	FILE *rfp;
	int rcc;

	rfp = TMPFILE("authlog");
	buff = (char*)malloc(size);
	rcc = fread(buff,1,size,ofp); /**/
	if( 0 < rcc ){
		buff[rcc] = 0;
		for( sp = buff+rcc-1; buff <= sp; sp-- ){
			if( *sp == '\n' || sp == buff ){
				if( sp[1] ){
					if( sp == buff )
						fputs(buff,rfp);
					else	fputs(sp+1,rfp);
					fputc('\n',rfp);
				}
				*sp = 0;
			}
		}
		fflush(rfp);
		fseek(rfp,0,0);
	}
	free(buff);
	return rfp;
}
int ftail(FILE *fp,int off){
	CStr(line,256);
	fseek(fp,-off,2);
	fgets(line,sizeof(line),fp);
	return ftell(fp);
}
FILE *get_authlog(Connection *Conn,PCStr(proto),PCStr(clhost),int size,int rv){
	const char *host;
	CStr(addr,128);
	FILE *fp;

	if( clhost )
		host = clhost;
	else	host = Client_Host;
	VA_inetNtoah(Client_VAddr,AVStr(addr));
	if( fp = fopen_authlog(proto,host,"r") ){
		if( size < file_size(fileno(fp)) ){
			ftail(fp,size);
		}
		if( rv ){
			FILE *rfp;
			rfp = freverse(fp,size);
			fclose(fp);
			fp = rfp;
		}
	}
	return fp;
}

int strCRC32(PCStr(str),int len);
static void filter_authlog(Connection *Conn,FILE *log,FILE *out){
	CStr(line,1024);
	CStr(host,1024);
	CStr(date,64);
	CStr(proto,64);
	CStr(iport,64);
	CStr(user,64);
	CStr(reason,64);
	int code;
	int hostcrc;
	int ni;

	if( AuthStat & A_OK_PASSAUTHOR ){
	}else{
		fprintf(out,"(hidden partially)\n");
	}
	for(;;){
		if( fgets(line,sizeof(line),log) == NULL )
			break;
		ni = Xsscanf(line,"%s %s %d %s %s %s %s",
			AVStr(date),AVStr(proto),&code,AVStr(host),
			AVStr(iport),AVStr(user),AVStr(reason));
		if( ni == 7 ){
			if( AuthStat & A_OK_PASSAUTHOR ){
			}else{
				hostcrc = strCRC32(host,strlen(host));
				sprintf(host,"(%08X)",hostcrc);
				if( code == 0 )
					strcpy(user,"()");
			}
			fprintf(out,"%s %s %2d %s %s %s %s\n",
				date,proto,code,host,iport,user,reason);
		}
	}
}

static int showdir(Connection *Conn,PCStr(dir),FILE *fc,FILE *tc,int vno){
	int cleng;
	const char *com;

	com = admin_getv("com");
	if( com && streq(com,"up") ){
		CStr(upath,1024);
		refQStr(dp,upath);
		/*
		sprintf(upath,"/-/admin/showdir/%s",dir);
		*/
		extbase(Conn,AVStr(upath),"/-/admin/showdir/%s",dir);
		if( dp = strrchr(upath,'/') ){
			if( dp[1] != 0 ){
				setVStrEnd(dp,1);
			}else{
				setVStrEnd(dp,0);
				if( dp = strrchr(upath,'/') )
					setVStrEnd(dp,1);
				if( strchr(upath,'/') == 0 )
					strcpy(upath,"DGROOT/");
			}
		}
		return putMovedTo(Conn,tc,upath);
	}
	sd_dir = dir;
	sd_fc = fc;
	admin_admcom = "showdir";

	cleng = putBuiltinPage(Conn,vno,tc,"Admin-Directory",
		"admin/Directory.dhtml",NULL,(iFUNCP)DHTML_printConn,NULL);

	sd_dir = 0;
	return cleng;
}
static char insertln[1];
static void dumpfile(FILE *in,FILE *out,PCStr(ctype),int toHTML,PCStr(putln),int seln,int deln,PCStr(repl),int txmax,int bimax,int bicol){
	int ch;
	int ci;
	int bi = 0;
	int bs = 0;
	int col;
	int ln = 0;
	int insn = 0;
	const char *vs;

	if( repl == insertln ){
		insn = deln;
		deln = 0;
	}

	col = 0;
	for( ci = 0; ; ci++ ){
		ch = getc(in);
		if( ch == EOF )
			break;
		if( col == 0 ){
			ln++;
			if( insn ){
				if( ln == insn ){
					putc('\n',out);
				}
			}
			if( putln )
			col += fprintf(out,"<A HREF=%s%d>%04d</A> ",putln,ln,ln);
		}
		if( seln ){
			if( ln != seln ){
				if( ch == '\n' ){
					col = 0;
				}else	col++;
				continue;
			}
		}
		if( deln ){
			if( ln == deln ){
				if( ch == '\n' ){
					if( repl ){
						fputs(repl,out);
						if( strtailchr(repl) != '\n' )
							fputc('\n',out);
					}
					col = 0;
				}else	col++;
				continue;
			}
		}
		if( ch == 0 ){
			if( bi == 0 )
				bs = ci;
			bi++;
			fputs("\\x00",out);
			col += 4;
		}else
		if( 0 < bi ){
			fprintf(out,"\\x%02X",ch);
			col += 4;
		}else
		switch( ch ){
			case 033: /* if in ISO-2022- */
				putc(ch,out);
				break;
			case '\t':
				putc(ch,out);
				col++;
				break;
			case '\n':
				putc(ch,out);
				col = 0;
				break;
			case '\r':
				break;
			default:
				if( toHTML ){
					vs = 0;
					switch( ch ){
					    case '&': vs = "&amp;"; break;
					    case '<': vs = "&lt;"; break;
					    case '>': vs = "&gt;"; break;
					    case '"': vs = "&quot;"; break;
					}
					if( vs ){
						fputs(vs,out);
						col += strlen(vs);
						break;
					}
				}
				if( ch < 0x20 || 0x7F <= ch ){
					fprintf(out,"\\x%02X",ch);
					col += 4;
				}else{
					putc(ch,out);
					col++;
				}
		}
		if( 0 < bi && bicol < col ){
			if( bimax <= (ci-bs) ){
				fputs(" ...\n",out);
				break;
			}
			putc('\n',out);
			col = 0;
		}
		if( txmax < ci ){
			fputs(" ...\n",out);
			break;
		}
	}
	if( putln ){
		fprintf(out,"<A HREF=%s%d>%04d</A> \n",putln,ln+1,ln+1);
	}
	if( insn ){
		if( insn == ln+1 ){
			fputc('\n',out);
		}
	}
	if( 0 < bi ){
		putc('\n',out);
	}
}
static int showfile1(PCStr(name),Connection *Conn,PCStr(fmt),PCStr(iconbase),FILE *tc,int *n,PCStr(type),FileSize fsize,PCStr(utime)){
	CStr(pname,256);
	CStr(aname,256);
	CStr(sizek,32);
	CStr(xutime,64);
	CStr(line,1024);
	CStr(icon,256);
	const char *iconsrc;
	const char *iconalt;
	CStr(alt,32);
	const char *sp;
	int ch;

/*
should be put with HTML_scan1() with ${} evaluation
*/
	encodeEntitiesY(name,AVStr(pname),sizeof(pname),"&\"'<>",0);
	if( type[0] == 'd' )
		sprintf(aname,"%s/",pname);
	else	strcpy(aname,pname);
	strsubst(AVStr(aname),":","%3A");
	strsubst(AVStr(aname),"#","%23"); /* not to be URL#label */

	iconsrc = filename2icon(aname,&iconalt);
	sprintf(icon,"%s%s ALT=[%s]",iconbase,iconsrc,iconalt);
	sprintf(sizek,"%lld",fsize);
	if( *n % 2 )
		sprintf(alt,"E0E0E0");
	else	sprintf(alt,"F0F0F0");

	strcpy(xutime,utime);
	strsubst(AVStr(xutime)," ","&nbsp;");

	for( sp = fmt; ch = (0xFF & *sp); sp++ ){
		if( ch == '\\' && sp[1] == 'n' ){
			fprintf(tc,"\n");
			sp++;
			continue;
		}
		if( ch != '%' ){
			putc(ch,tc);
			continue;
		}
		ch = *(++sp);
		switch( ch ){
			case 'a': fprintf(tc,"%s",alt); break;
			case 'N': fprintf(tc,"%s",pname);
				if( *type == 'l' ){
					fprintf(tc," (symlink)");
				}
				break;
			case 'A':
				if( GatewayFlags & GW_NO_ANCHOR )
					fprintf(tc,"%s","DGROOT/");
				else
				if( *type == 'l' )
					fprintf(tc,"");
				else
				fprintf(tc,"%s",aname); break;
				break;
			case 'T': fprintf(tc,"%s",xutime); break;
			case 'S': fprintf(tc,"%s",sizek); break;
			case 'I': fprintf(tc,"%s",icon); break;
			default: putc('%',tc); putc(ch,tc); break;
		}
	}
	*n += 1;
	return 0;
}
int foreach_file(Connection *Conn,FILE *tc,PCStr(path),PCStr(sort),PCStr(fmt)){
	FILE *fp;
	const char *opt;
	CStr(lsfmt,128);
	CStr(iconbase,256);
	int fn = 0;
	CStr(line,1024);
	CStr(type,3);
	CStr(mode,16);
	FileSize fsize;
	CStr(udate,64);
	CStr(adate,64);
	CStr(name,1024);

	getCERNiconBase(Conn,AVStr(iconbase));
	fp = TMPFILE("Showdir");

	if( streq(sort,"date") ) opt = "-at"; else
	if( streq(sort,"size") ) opt = "-az"; else
				 opt = "-a";

	strcpy(lsfmt,"%T %M %S %D\t%U\t%N");
	ls_unix(fp,opt,AVStr(lsfmt),path,NULL);
	fflush(fp);
	fseek(fp,0,0);
	for(;;){
		int xn;
		if( fgets(line,sizeof(line),fp) == NULL )
			break;
		xn = Xsscanf(line,"%s %s %lld %[^\t]\t%[^\t]\t%[^\r\n]",
			AVStr(type),AVStr(mode),&fsize,
			AVStr(udate),AVStr(adate),AVStr(name)
		);
		if( xn != 6 ){
			continue;
		}
		showfile1(name,Conn,fmt,iconbase,tc,&fn,type,fsize,udate);
	}
	fclose(fp);
	return 0;
}

#define SHOW_DIR	1
#define SHOW_ISDIR	2
#define SHOW_FILE	3
#define SHOW_REMOVE	4
#define SHOW_CREATE	5

int myfile_path(PCStr(path),PVStr(apath)){
	CStr(base,128);
	const char *rpath;
	CStr(rpathb,1024);
	CStr(npath,1024);
	const char *ipath;

	ipath = path;
	if( strneq(ipath,"file::",6) ){
		ipath += 6;
	}
	rpath = wordScanY(ipath,base,"^/");
	strcpy(rpathb,rpath);
	if( *base == 0 )
		strcpy(base,"DGROOT");
	/*
	fprintf(stderr,"------- BASE[%s] RPATH[%s]\n",base,rpath);
	*/

	if( upath_off_limit(apath,AVStr(npath)) ){
		sv1log("### myfile_path(%s) Path Off Limit (%s)\n",path,npath);
		return -1;
	}else{
		sprintf(apath,"${%s}%s",base,rpathb);
		Substfile(apath);
		if( path < ipath ){
			Strins(AVStr(apath),"file:");
		}
	/*
	fprintf(stderr,"### myfile_path(%s%s) -> %s\n",base,rpathb,apath);
	*/
		return 0;
	}
}

static int filePageSize = 8*1024;
static int setFilePos(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(path)){
	int withSSL = (ClientFlags & PF_STLS_ON);
	const char *com = admin_getv("com");
	const char *soff = admin_getv("filepos");
	FileSize ooff = 0;
	FileSize fsize = file_sizeX(fileno(fp));
	FileSize noff;
	CStr(skip,1024);
	IStr(fcom,128);
	IStr(farg,128);
	int rcode = 0;

	if( com ){
		Xsscanf(com,"%[^.].%s",AVStr(fcom),AVStr(farg));
	}
	if( soff ){
		Xsscanf(soff,"%lld",&ooff);
	}
	fileHead = ooff;

	if( streq(fcom,"show_file") ){
		if( streq(farg,"prev") )
			noff = ooff - filePageSize;
		else	noff = ooff + filePageSize;
		if( !withSSL ){
			if( admin_respmssg ){
				set_conferror("without-SSL");
				sprintf(admin_respmssg,
					"%s -- forbidden without SSL",com);
			}
			Fseeko(fp,ooff,0);
			rcode = -1;
		}else
		if( noff < 0 ){
			Fseeko(fp,ooff,0);
		}else
		if( fsize <= noff ){
			Fseeko(fp,ooff,0);
			fgets(skip,sizeof(skip),fp);
		}else{
			Fseeko(fp,noff,0);
			fileHead = Ftello(fp);
			fgets(skip,sizeof(skip),fp);
		}
	}else
	if( streq(fmt,"tail") ){
		Fseeko(fp,-filePageSize,2);
		fgets(skip,sizeof(skip),fp);
		fileHead = Ftello(fp);
	}else{
		fileHead = Ftello(fp);
	}
	sv1log("##setFilePos[%s]=%llu %s[%s] %s\n",
		withSSL?"SSL":"",fileHead,com,fmt,path);
	return rcode;
}

static int showdir1(PVStr(msg),Connection *Conn,FILE *tc,int com,PCStr(opt),PCStr(fmt)){
	int cleng;
	CStr(param,32);
	CStr(upath,512);
	CStr(url,1024);
	CStr(npath,1024);
	int st;
	CStr(req,1024);

	if( sd_dir == 0 )
		return -1;

	if( com == SHOW_FILE ){
		if( fmt != NULL && streq(fmt,"filepos") ){
			fprintf(tc,"%llu",fileHead);
			return 0;
		}
	}

	fflush(tc); /* flush before fork() for putLocal() */

	strcpy(param,"DGROOT");
	strcpy(upath,"/");
	cleng = 0;
	Xsscanf(sd_dir,"%[^/]%[^\377]",AVStr(param),AVStr(upath));
	strsubst(AVStr(upath),"$","%24"); /* to escape ${} interpretation ? */
	sprintf(url,"file:%s",upath);

	if( upath_off_limit(url,AVStr(npath)) ){
		fprintf(tc,"Path Off Limit\n");
	}else
	if( 0 < strlen(param) ){
		const char *mod;
		CStr(line,256);
		CStr(xu,256);
		CStr(lpath,1024); /* local path */
		CStr(dpath,1024); /* [date+format] expansion */
		CStr(xlpath,1024);
		FILE *sfp;

		strcpy(xu,upath);
		url_unescape(AVStr(xu),AVStr(xu),sizeof(xu),":=%@*#:");
		if( mod = strchr(param,'-') ){
			if( streq(mod,"-current") ){
				truncVStr(mod);
				mod++;
			}
		}
		sprintf(lpath,"${%s}%s",param,upath);
		DELEGATE_substfile(AVStr(lpath),"",VStrNULL,VStrNULL,VStrNULL);
		StrSubstDateX(AVStr(lpath),AVStr(dpath));
		if( !streq(lpath,dpath) ){
			if( !streq(mod,"current") ){
				strcpy(lpath,dpath);
			}
		}
		sprintf(url,"file://localhost/%s",lpath);
		strsubst(DVStr(url,strlen("file://localhost")),"//","/");

		fflush(tc); /* flush stream before possible fork() in URLget */
		if( *sd_dir == 0 )
			GatewayFlags |= GW_NO_ANCHOR;

		URL_unescape(lpath,AVStr(xlpath),0,0);
		if( com != SHOW_DIR ){
			FILE *fp;
			CStr(spath,1024);

			strcpy(spath,xlpath);
			if( com == SHOW_ISDIR ){
				return fileIsdir(xlpath);
			}
			if( com == SHOW_FILE ){
				CStr(scom,128);
				CStr(sarg,128);
				truncVStr(scom);
				truncVStr(sarg);
				Xsscanf(fmt,"%[^.].%s",AVStr(scom),AVStr(sarg));

				fp = dirfopen("Showdir",AVStr(xlpath),"r-"); 
				if( fp != NULL ){
					int rcode;
					rcode = setFilePos(Conn,fp,fmt,xlpath);
					if( rcode == 0 )
			dumpfile(fp,tc,"text/html",1,0,0,0,NULL,8*1024,512,64);
					fclose(fp);
					return 1;
				}else{
					return 0;
				}
			}

			if( strtailchr(xlpath) != '/' ){
				putMssg(BVStr(msg),"@ADM - not in a directory(%s)\n",
					opt);
				return 0;
			}
			if( fmt == 0 || *fmt == 0 ){
				putMssg(BVStr(msg),"@ADM - no file to remove\n");
				return 0;
			}
			if( strpbrk(fmt,"/\\") ){
				putMssg(BVStr(msg),"@ADM - bad file name\n");
				return 0;
			}
			strcat(xlpath,fmt);
			fp = fopen(xlpath,"r+"); 
			if( com == SHOW_REMOVE ){
				if( fp != NULL ){
					int rcode;
					strcat(spath,".SAV./");
					strcat(spath,fmt);
					rcode = renameRX(xlpath,spath);
					if( rcode == 0 )
				putMssg(BVStr(msg),"@ADM + removed '%s'\n",fmt);
					else{
				putMssg(BVStr(msg),"@ADM - cannot remove '%s'\n",fmt);
					}
				}else{
				putMssg(BVStr(msg),"@ADM - cannot remove '%s'\n",fmt);
				}
				return 0;
			}
			if( fp != NULL ){
				putMssg(BVStr(msg),"@ADM - exists already\n");
				fclose(fp);
				return 0;
			}
			fp = fopen(xlpath,"w"); 
			if( fp == NULL ){
				putMssg(BVStr(msg),"@ADM - cannot create\n");
			}else{
				putMssg(BVStr(msg),"@ADM + created\n");
				fclose(fp);
			}
			return 0;
		}

		if( fmt == NULL ){
			fprintf(tc,"[<B>%s%s</B>]",param,xu);
		}
		if( !fileIsdir(xlpath) && (sfp = fopen(xlpath,"r")) ){
		}else
		if( fmt != NULL ){
			foreach_file(Conn,tc,xlpath,opt,fmt);
			return 0;
		}else{
			sfp = CTX_URLget(Conn,1,url,1,NULL);
		}

		if( sfp == NULL ){
			fprintf(tc,"cannot open: %s\n",sd_dir);
		}else
		if( 0 < ftell(sfp) ){
			/* with HTTP header, not a plain file,
			 * that is directory
			 */
			fputs("\n",tc);
			copyfile1(sfp,tc);
			fputs("</PRE><HR>\n",tc);
		}else{
			const char *ctype;
			if( ctype = filename2ctype(url) ){
				fprintf(tc,"[%s]\n",ctype);
			}else{
				fprintf(tc,"\n",ctype);
			}
/*
			dumpfile(sfp,tc,ctype,1,0,0,0,NULL,8*1024,512,64);
*/
		}
		if( sfp != NULL )
			fclose(sfp);
	}
	return 0;
}

int restart_server(FILE *tmp);
int getConfig(PCStr(name),PVStr(path));
int putConfig(PCStr(name),PCStr(mode),PCStr(conf));
int dgconfigFile(PCStr(what),PCStr(name),PVStr(path));
extern int DELEGATE_LastModified;
int get_mainarg(PCStr(arg),PVStr(port));

char *getConfigData(Connection *Conn,PCStr(serv),PCStr(pfx),int *datep){
	CStr(path,1024);
	defQStr(conf);
	int msize;
	int fsize;
	int pxlen;
	int rcc;
	FILE *cfp = NULL;
	pxlen = strlen(pfx);

	if( streq(serv,config_self) ){
		CStr(port,256);
		CStr(buff,16*1024);
		if( User_Port == Admin_Port )
			sprintf(port,"-P%d/admin",User_Port);
		else	sprintf(port,"-P%d,%d/admin",User_Port,Admin_Port);
		if( datep ) *datep = DELEGATE_LastModified;
		sprintf(buff,"%sSERVER=%s\n%s\nADMIN=%s",
			pfx,iSERVER_PROTO,port,DELEGATE_ADMIN);
		conf = stralloc(buff);
		return (char*)conf;
	}
	getConfig(serv,AVStr(path));
	cfp = fopen(path,"r");
	if( cfp == 0 ){
		return 0;
	}
	fsize = file_size(fileno(cfp));
	if( datep ){
		*datep = file_mtime(fileno(cfp));
	}
	msize = pxlen + fsize + 1;
	setQStr(conf,(char*)malloc(msize),msize);
	strcpy(conf,pfx);
	rcc = fread((char*)conf+pxlen,1,fsize,cfp); /**/
	fclose(cfp);
	if( 0 < rcc ){
		setVStrEnd(conf,pxlen+rcc);
	}
	return (char*)conf;
}
int printServPort(PVStr(port),PCStr(prefix),int whole);

int fromSafeFileName(PCStr(name),PVStr(xname));
static scanDirFunc scanfile1(PCStr(name),PCStr(dir),PCStr(pat),PCStr(neg),int mac,int *acp,const char *av[]){
	const char *mp;
	const char *dp;
	CStr(xname,1024);

	if( mac <= *acp ){
		return -1;
	}
	if( *name == '.' )
		return 0;
	if( pat ){
		if( strtailstr(name,pat) == 0 )
			return 0;
	}
	if( neg ){
		if( strtailstr(name,neg) != 0 )
			return 0;
	}

	fromSafeFileName(name,AVStr(xname));
	mp = stralloc(xname);
	if( pat ){
		if( dp = strtailstr(mp,pat) )
			truncVStr(dp);
	}
	av[*acp] = mp;
	*acp += 1;
	return 0;
}
int getConfigList(int mac,const char *av[],PCStr(neg)){
	CStr(path,1024);
	int ac = 0;

	if( dgconfigFile("List",NULL,AVStr(path)) == 0 ){
		CStr(xpat,32);
		sprintf(xpat,".%s",neg);
		strsubst(AVStr(xpat),"-",".");
		Scandir(path,scanDirCall scanfile1,path,".cnf",xpat,mac,&ac,av);
	}
	return ac;
}
int getServerList(int mac,const char *av[],PCStr(neg)){
	CStr(path,1024);
	int ac = 0;

	sprintf(path,"${ADMDIR}/%s",SVSTATDIR);
	Substfile(path);
	Scandir(path,scanDirCall scanfile1,path,NULL,NULL,mac,&ac,av);
	return ac;
}
static int config_editln;
static int dispconfig(Connection *Conn,FILE *tc,int toHTML,PCStr(putln),int seln,int deln,PCStr(repl)){
	CStr(path,1024);
	FILE *cfp;

	if( getConfig("default",AVStr(path)) ){
		if( cfp = fopen(path,"r") ){
			dumpfile(cfp,tc,"text/html",toHTML,putln,seln,deln,repl,0x10000,1,64);
			fclose(cfp);
			return 1;
		}
	}
	return 0;
}
int fcrc32(FILE *cfp);
static int crc32config(){
	CStr(path,1024);
	FILE *cfp;
	int crc = 0;

	if( getConfig("default",AVStr(path)) ){
		if( cfp = fopen(path,"r") ){
			crc = fcrc32(cfp);
			fclose(cfp);
		}
	}
	return crc;
}
static void editconfig(Connection *Conn,PCStr(which),PCStr(com),int ln,PCStr(edata),PVStr(msg)){
	FILE *tmp;
	CStr(path,1024);
	int replace = 0;

	tmp = TMPFILE("editconfig");
	if( strcaseeq(com,"delete") ){
		dispconfig(Conn,tmp,0,0,0,ln,NULL);
		replace = 1;
	}else
	if( strcaseeq(com,"replace") ){
		if( edata ){
			dispconfig(Conn,tmp,0,0,0,ln,edata);
			replace = 1;
		}
	}else
	if( strcaseeq(com,"next") ){
		config_editln++;
	}else
	if( strcaseeq(com,"prev") ){
		if( 0 < config_editln )
			config_editln--;
	}else
	if( strcaseeq(com,"insert") ){
		dispconfig(Conn,tmp,0,0,0,ln,insertln);
		replace = 1;
	}
	if( replace ){
		fflush(tmp);
		fseek(tmp,0,0);
		if( getConfig("default",AVStr(path)) ){
			FILE *cfp;
			if( cfp = fopen(path,"w") ){
				copyfile1(tmp,cfp);
				fclose(cfp);
			}else{
			}
		}
	}
	fclose(tmp);
}


int dgconfigSaveFile(PCStr(what),PVStr(path)){
	if( dgconfigFile(what,"",BVStr(path)) == 0 ){
		strcat(path,".sav");
		return 0;
	}else	return -1;
}
static void saveConfig(Connection *Conn,PVStr(msg)){
	FILE *tmp;
	CStr(path,1024);
	FILE *sfp;

	tmp = TMPFILE("Admin.sav");
	dispconfig(Conn,tmp,0,0,0,0,NULL);
	fflush(tmp);
	strcpy(msg,"Save Error");
	if( 0 < file_size(fileno(tmp)) ){
		fflush(tmp);
		fseek(tmp,0,0);
		dgconfigSaveFile("save",AVStr(path));
		if( sfp = fopen(path,"w") ){
			copyfile1(tmp,sfp);
			fclose(sfp);
			strcpy(msg,"OK: Made Backup");
		}else{
			strcpy(msg,"-ERROR: Cannot Backup");
		}
	}else{
		strcpy(msg,"-ERROR: Cannot Open Current");
	}
	fclose(tmp);
}
static void restoreConfig(Connection *Conn,PVStr(msg)){
	FILE *sfp;
	CStr(path,1024);
	CStr(confb,16*1024);
	int rcc;

	strcpy(msg,"Restore Error");
	dgconfigSaveFile("rest",AVStr(path));
	if( sfp = fopen(path,"r") ){
		rcc = fread(confb,1,sizeof(confb)-2,sfp);
		if( 0 <= rcc ){
			setVStrEnd(confb,rcc);
			putConfig("default","w",confb);
			sprintf(msg,"OK: Restored Configuration");
		}else{
			strcpy(msg,"-ERROR: Cannot Get Saved Config.");
		}
		fclose(sfp);
	}else{
		strcpy(msg,"-ERROR: Cannot Open Saved Configuration.");
	}
}

FILE *fopenDGfile(PCStr(what),PVStr(path),PCStr(mode)){
	FILE *fp;

	Substfile(path);
	if( streq(mode,"r") ){
		fp = dirfopen(what,AVStr(path),mode);
	}else
	if( strchr(mode,'a') ){
		fp = dirfopen(what,AVStr(path),mode);
	}else
	if( fp = dirfopen(what,AVStr(path),"r+") ){
		Ftruncate(fp,0,0);
	}else
	if( fp = dirfopen(what,AVStr(path),mode) ){
	}

	if( fp == NULL && streq(mode,"r+") ){
		fp = dirfopen(what,AVStr(path),"w+");
if( fp != NULL )
 fprintf(stderr,"---------- CREATED for %s by w+, %s\n",mode,path);
	}
	if( fp == NULL && !streq(mode,"r") ){
		if( fp = TMPFILE(what) ){
			daemonlog("E","cannot create %s %s\n",what,path);
		}else{
			daemonlog("E","cannot create TMPFILE %s %s\n",what,path);
		}
	}
	if( fp ){
		clearCloseOnExec(fileno(fp));
	}
	return fp;
}
/*
 * InitLog also recoreds Finish ?
 * should not be inherited to child process
 */
typedef FILE *(*fileFunc)(PCStr(port),PCStr(mode));
int getpidof(PCStr(name));
FILE *fopenInitLog(PCStr(name),PCStr(mode)){
	extern int LOG_initFd;
	CStr(path,1024);
	FILE *fp;

	if( 0 <= LOG_initFd )
	if( streq(name,config_self) || getpidof(name) == serverPid() ){ 
		if( fp = fdopen(dup(LOG_initFd),mode) ){
			fseek(fp,0,0);
			return fp;
		}
	}
	strcpy(path,"${ADMDIR}/initlog/");
	toSafeFileName(name,TVStr(path));
	return fopenDGfile("InitLog",AVStr(path),mode);
}
FILE *fopenSvstats(PCStr(serv),PCStr(mode)){
	CStr(path,1024);
	FILE *fp;

	sprintf(path,"${ADMDIR}/%s/",SVSTATDIR);
	toSafeFileName(serv,TVStr(path));
	fp = fopenDGfile("SvStats",AVStr(path),mode);
	return fp;
}

FILE *fopenXDGfile(Connection *Conn,PCStr(serv),PCStr(mode),fileFunc func){
	CStr(path,1024);
	int date;
	const char *conf;
	const char *cv[128];
	const char *dgroot;
	const char *dp;
	int cc,ci;
	FILE *fp = NULL;

if( lHTMLGENV() )
 fprintf(stderr,"--1 fopenXSvstats(%s)\n",serv);
	if( func == fopenInitLog && streq(serv,config_self) ){
		extern int LOG_initFd;
		fp = fdopen(dup(LOG_initFd),mode);
		fseek(fp,0,0);
if( lHTMLGENV() )
 fprintf(stderr,"--2 fopenXSvstats(%s) %d %X OFF=%d/%d\n",serv,LOG_initFd,p2i(fp),iftell(fp),file_size(LOG_initFd));
		return fp;
	}

	conf = getConfigData(Conn,serv,"",&date);
	if( conf != NULL ){
		cc = list2vect(conf,'\n',elnumof(cv),cv);
		for( ci = 0; ci < cc; ci++ ){
			if( dp = strchr(cv[ci],'\r') )
				truncVStr(dp);
		}
		for( ci = 0; ci < cc; ci++ ){
			if( strneq(cv[ci],"-P",2) ){
				if( dp = strchr(cv[ci],',') ) truncVStr(dp);
				if( dp = strchr(cv[ci],'/') ) truncVStr(dp);

				fp = (*func)(cv[ci]+2,"r");

if( lHTMLGENV() )
 fprintf(stderr,"--3 fopenXSvstats(%s) %s %X\n",serv,cv[ci],p2i(fp));
				break;
			}
		}
		free((char*)conf);
	}
	return fp;
}

static int volrestart(Connection *Conn,FILE *tmp);
void printPrimaryPort(PVStr(port));
static int admin_auth(Connection *Conn,PCStr(user),PCStr(pass));
char *strfLoadStatX(PVStr(str),int size,PCStr(fmt),int now,int fd);

static void waitStartup(PCStr(serv),int timeout,PVStr(initlog),int isize){
	int locked;
	int elapsed;
	int rcc;
	FILE *lfp;

if( lHTMLGEN() )
 fprintf(stderr,"****** waitStartup(%s)...\n",serv);
	sleep(1);
	lfp = fopenInitLog(serv,"r");
	if( lfp == NULL ){
	}else{
		locked = lock_sharedTO(fileno(lfp),timeout*1000,&elapsed);
if( lHTMLGEN() )
 fprintf(stderr,"****** shlocked(%d)=%d elapsed=%d\n",fileno(lfp),locked,elapsed);
		if( initlog )
		if( 0 < (rcc = fread((char*)initlog,1,QVSSize(initlog,isize-1),lfp)) ){
			setVStrEnd(initlog,rcc);
		}
if( lHTMLGEN() )
 fprintf(stderr,"****** InitLog SIZE(%d)=%d -> %d\n",
fileno(lfp),file_size(fileno(lfp)),rcc);
		fclose(lfp);
	}
if( lHTMLGEN() )
 fprintf(stderr,"****** waitStartup(%s)...END\n",serv);
}

#define SERV_START	1
#define SERV_STOP	2
#define SERV_RESTART	4
#define SERV_VRESTART	8

int getpidof(PCStr(name)){
	FILE *stfp;
	CStr(st,32);
	int pid;

	stfp = fopenSvstats(name,"r");
	if( stfp ){
		strfLoadStatX(AVStr(st),sizeof(st),"%p",time(0),fileno(stfp));
		pid = atoi(st);
		fclose(stfp);
		return pid;
	}
	return -1;
}

int rejectMethod(Connection *Conn,PCStr(proto),PCStr(method),PCStr(dsthost),int dport,PCStr(srchost),int sport);
static int forbidden(Connection *Conn,PCStr(com),PCStr(arg),FILE *tc){
	CStr(methodb,1024);
	const char *method;

	if( arg && *arg ){
		sprintf(methodb,"%s.%s",com,arg);
		method = methodb;
	}else	method = com;

	if( rejectMethod(Conn,"admin",method,"",0,Client_Host,Client_Port) ){
		sv1log("#### REJECTED admin %s\n",com);
		if( tc ){
			fprintf(tc,"HTTP/1.0 403 Forbidden\r\n");
			fprintf(tc,"Content-Type: text/plain\r\n");
			fprintf(tc,"\r\n");
			fprintf(tc,"*** Forbidden ***\r\n");
		}
		return 1;
	}
	return 0;
}
static int startstop1(Connection *Conn,PVStr(msg),PCStr(serv),int ns,int com){
	int pid;
	CStr(args,256);
	CStr(argb,256);
	CStr(cpath,1024);
	const char *av[8];
	int ac = 0;
	CStr(servp,MaxHostNameLen);
	const char *conf;
	int date;
	FILE *scfp;
	FILE *ilfp;
	FILE *stfp;
	CStr(scfparam,256);
	CStr(params,1024);
	refQStr(pp,params);
	CStr(Port,128);
	const char *coms;
int ai;
refQStr(ap,args);

if( lHTMLGEN() )
 fprintf(stderr,"######A##### startstop [%d]%s\n",com,serv);

	if( serv == 0 || *serv == 0 ){
		putMssg(BVStr(msg),"@ADM - no configuration is specified\n");
		set_conferror("conf-checked");
		return -1;
	}

	coms = "?";
	switch( com ){
		case SERV_STOP: coms = "stop"; break;
		case SERV_START: coms = "start"; break;
		case SERV_RESTART: coms = "restart"; break;
	}
	if( forbidden(Conn,coms,serv,NULL) ){
		putMssg(BVStr(msg),"@ADM - forbidden stop '%s'\n",serv);
		set_conferror("serv-ERROR");
		return -1;
	}

	ac = 0;
	scfp = NULL;
	conf = NULL;
	ilfp = NULL;
	stfp = NULL;
	truncVStr(Port);

	if( com == SERV_RESTART ){
		if( streq(serv,config_self) || getpidof(serv) == serverPid() ){
			setSoftBreak(Conn,"");
			Xsprintf(TVStr(msg),"+ restarting '%s'\n",serv);
		}else{
			setSoftBreak(Conn,serv);
			Xsprintf(TVStr(msg),"+ initiated restart '%s'\n",serv);
		}
		return 0;
	}
	if( streq(serv,config_self) || getpidof(serv) == serverPid() ){
		const char *user;
		const char *pass;
		user = getv(Form_argv,"conf-admuser");
		pass = getv(Form_argv,"conf-admpass");

		printPrimaryPort(AVStr(servp));
		strcpy(Port,servp);
		Strins(AVStr(servp),"-P");

		if( com == SERV_STOP ){
			if( user && pass && admin_auth(Conn,user,pass) == 0 ){
				putMssg(BVStr(msg),"@ADM + stop %s\n",serv);
			}else{
				putMssg(BVStr(msg),"@ADM - don't stop %s (%s)\n",
					config_self,serv);
				set_conferror("serv-ERROR");
				return -1;
			}
		}else{
			volrestart(Conn,NULL);
			putMssg(BVStr(msg),"@ADM + voluntary restart %s\n",serv);
			waitStartup(Port,5,VStrNULL,0);
			return getppid();
		}
		av[ac++] = servp;
	}else{
		if( getConfig(serv,AVStr(cpath)) == 0 ){
			putMssg(BVStr(msg),"@ADM - cannot open %s\n",serv);
			return -1;
		}
		scfp = fopen(cpath,"r");
		if( scfp == NULL ){
			putMssg(BVStr(msg),"@ADM - cannot open %s\n",serv);
			return -1;
		}
		if( com == SERV_START && isWindows() /* && the same DGROOT */ ){
			sprintf(scfparam,"+=%s",serv);
			av[ac++] = scfparam;
		}else{
			sprintf(scfparam,"+=fd:%d",fileno(scfp));
			av[ac++] = scfparam;
if( lHTMLGEN() )
 fprintf(stderr,"---- scfd=%d %s\n",fileno(scfp),cpath);
		}

		conf = getConfigData(Conn,serv,"",&date);
		if( conf != NULL ){
			const char *cv[128];
			const char *dgroot;
			const char *dp;
			int cc,ci;
			cc = list2vect(conf,'\n',elnumof(cv),cv);
			cv[cc] = 0; /*list2vect() doesn't terminate with NULL*/
			for( ci = 0; ci < cc; ci++ ){
				if( dp = strchr(cv[ci],'\r') )
					truncVStr(dp);
			}
			if( dgroot = getv(cv,"DGROOT") ){
				av[ac++] = dgroot-7;
			}
			if( dp = getv(cv,"CHROOT") ){
				av[ac++] = pp;
				strcpy(pp,dp-7);
				pp += strlen(pp) + 1;
			}

			if( com == SERV_START && !isWindows() ){
				if( ilfp = fopenInitLog(serv,"r+") ){
					av[ac++] = pp;
					sprintf(pp,"-II%d",fileno(ilfp));
					pp += strlen(pp) + 1;
				}
				if( stfp = fopenSvstats(serv,"r+") ){
					av[ac++] = pp;
					sprintf(pp,"-IS%d:%s",fileno(stfp),serv);
					pp += strlen(pp) + 1;
				}
			}
		}
	}

if( lHTMLGEN() )
 fprintf(stderr,"######B##### startstop [%d]%s\n",com,serv);
	if( com == SERV_STOP ){
		av[ac++] = "-vd";
		av[ac++] = "-Fkill";
	}else
	if( com == SERV_RESTART ){
		av[ac++] = "-Fkill-hup";
	}else{
		av[ac++] = "-r";
		if( lFG() )
			av[ac++] = "-f";
		if( lVERB() )
			av[ac++] = "-v";
	}
	av[ac++] = "-s";
	av[ac] = 0;

	for( ai = 0; ai < ac; ai++ ){
if( lHTMLGEN() )
 fprintf(stderr,"---[%d] %s\n",ai,av[ai]);
		sprintf(ap,"%s ",av[ai]);
		ap += strlen(ap);
	}

	stopStickyServer("NotToInheritTo_spawn_self");
	closeServPorts(); /* should be like closeOnFork/Spawn */
if( lHTMLGEN() )
 fprintf(stderr,"------###### closed server ports [%s]\n",args);
	pid = spawnv_self1(ac,av);

	if( com != SERV_START ){
		putMssg(BVStr(msg),"@ADM + [%d] stopped %s\n",ns,serv);
	}else{
		putMssg(BVStr(msg),"@ADM + [%d] started %s\n",ns,serv);
		putMssg(BVStr(msg),"@ADM + pid: %d\n",pid);
	}
	putMssg(BVStr(msg),"+ command: delegated %s\n",args);

	if( conf )
		free((char*)conf);
	if( scfp != NULL )
		fclose(scfp);

	if( ilfp != NULL ){
		fclose(ilfp);
	}
	waitStartup(serv,5,VStrNULL,0);
	if( stfp != NULL ){
		CStr(st,128);
		const char *fmt = "PID=%p STARTED=[%s] STATUS=%t";
		strfLoadStatX(AVStr(st),sizeof(st),fmt,time(0),fileno(stfp));
		putMssg(BVStr(msg),"@ADM + status: %s\n",st);
		fclose(stfp);
	}
	return pid;
}
static int serv_showinit(Connection *Conn,PVStr(msg),PCStr(names),PCStr(arg),FILE *tc){
	const char *name;
	FILE *ilfp;
	name = admin_getv(names);
	if( name == 0 || *name == 0 ){
		putMssg(BVStr(msg),"@ADM - no name for '%s'\n",names);
		return 0;
	}
	ilfp = fopenInitLog(name,"r");
	if( ilfp ){
		dumpfile(ilfp,tc,"text/html",1,0,0,0,0,0x10000,1,64);
		fclose(ilfp);
		return 1;
	}
	return 0;
}
static int serv_startstop(Connection *Conn,PVStr(msg),PCStr(name),PCStr(opts),int com){
	const char *serv;
	int ci;
	int pid;
	int pids[32];
	int ns = 0;

	for( ci = 0; ci < Form_argc; ci++ ){
		const char *a1;
		a1 = Form_argv[ci];
		if( strneq(a1,"conf-checked=",13) ){
			if( a1[13] ){
				pid = startstop1(Conn,BVStr(msg),a1+13,ns,com);
				pids[ns++] = pid;
			}
		}
	}
	serv = admin_getv(name);
if( lHTMLGEN() )
 fprintf(stderr,"-- startstop%d: +%d %s\n",com,ns,serv?serv:"NONE");

	if( serv == 0 || *serv == 0 ){
		if( ns == 0 ){
			putMssg(BVStr(msg),"@ADM - No configuration is selected\n");
			set_conferror("conf-checked");
		}
	}else{
		pid = startstop1(Conn,BVStr(msg),serv,ns,com);
		pids[ns++] = pid;
	}
	if( com == SERV_STOP ){
		/* wait unlocked  */
	}else{
		/* wait locked  */
	}

	if( 0 < ns ){
		sleep(1);
		for(;;){
			pid = NoHangWait();
if( lHTMLGENV() )
 fprintf(stderr,"-- startstop=%d wait pid = %d\n",com,pid);
			if( pid <= 0 )
				break;
		}
	}
	return ns;
}
static int load_servconf(Connection *Conn,PVStr(msg),PCStr(name),PCStr(opts)){
	const char *serv;
	const char *conf;
	int mdate;
	CStr(stime,64);

	serv = admin_getv(name);
	if( serv == 0 || *serv == 0 ){
		putMssg(BVStr(msg),"@ADM - no server name\n");
		set_conferror("conf-servname");
		return -1;
	}
	conf = getConfigData(Conn,serv,"confdata=",&mdate);
	if( conf == 0 ){
		putMssg(BVStr(msg),"@ADM - unknown configuration name: %s\n",serv);
		set_conferror("com-loadconf");
		return -1;
	}
	rsctime(mdate,AVStr(stime));
	putMssg(BVStr(msg),"@ADM + loaded %s, last update:%s\n",serv,stime);
	admin_genv[admin_genc++] = conf;
	admin_genv[admin_genc] = 0;
	conf2form(BVStr(msg),conf+9,elnumof(admin_genv)-1,admin_genv+1);
	form2conf(BVStr(msg),NULLFP(),0,-1);
/*
	free((char*)conf);
*/
	return 0;
}
FILE *fopen_lockconfX(Connection *Conn,PVStr(msg),PCStr(name),PCStr(mode),PVStr(path),int create){
	FILE *fp;
	int rcode;
	int writing;

	if( streq(name,config_self) ){
		if( msg )
		putMssg(BVStr(msg),"@ADM - cannot open '%s'\n",name);
		return NULL;
	}

/*
 fprintf(stderr,"---1a--- fol [%s][%s]\n",name,mode);
*/
	if( dgconfigFile("List",name,AVStr(path)) != 0 ){
		if( msg )
		putMssg(BVStr(msg),"@ADM - cannot find %s\n",name);
/*
 fprintf(stderr,"---2---- fol [%s][%s][%s]\n",name,mode,path);
*/
		return 0;
	}
	writing = strchr(mode,'+') || strchr(mode,'w');
	if( writing ){
		if( create && !File_is(path) ){
			mode = "w";
		}
	}else{
		if( getConfig(name,BVStr(path)) == 0 ){
			if( msg )
			putMssg(BVStr(msg),"@ADM - cannot find %s\n",name);
			return 0;
		}
	}
	fp = dirfopen("lockConf",AVStr(path),mode);
/*
	fp = fopenDGfile("lockConf",AVStr(path),mode);
*/

/*
 fprintf(stderr,"---3---- fol [%s][%s][%s] FP=%X\n",name,mode,path,fp);
*/
	if( fp == NULL ){
		if( msg )
		putMssg(BVStr(msg),"@ADM - cannot open %s\n",name);
		return 0;
	}

	if( writing )
		rcode = lock_exclusiveNB(fileno(fp));
	else	rcode = lock_sharedNB(fileno(fp));

	if( rcode != 0 ){
		if( msg )
		putMssg(BVStr(msg),"@ADM - cannot lock %s\n",name);
		fclose(fp);
		return 0;
	}
	if( isWindows() ){
		lock_unlock(fileno(fp));
	}
	return fp;
}
static int writable(Connection *Conn,PVStr(msg),PCStr(name)){
	CStr(path,1024);
	FILE *lfp;

	if( streq(name,config_self) )
		return 0;

	lfp = fopen_lockconf(BVStr(msg),name,"r+",AVStr(path),0);
if( lHTMLGEN() )
 fprintf(stderr,"---------- writable ? [%s][%s]\n",name,path);
	if( lfp == NULL ){
		return 0;
	}
	fclose(lfp);
	return 1;
}
static int remove1(Connection *Conn,PVStr(msg),PCStr(name)){
	CStr(path,1024);
	CStr(save,1024);
	refQStr(dp,save);
	int rcode;
	FILE *lfp;

	lfp = fopen_lockconf(BVStr(msg),name,"r+",AVStr(path),0);
	if( lfp == NULL ){
		return -1;
	}
	fclose(lfp);
	if( strtailstr(name,".sav") == 0 ){
		strcpy(save,path);
		if( dp = strtailstr(save,".cnf") )
			strcpy(dp,".sav.cnf");
		unlink(save);
		if( rename(path,save) == 0 ){
		putMssg(BVStr(msg),"@ADM + removed '%s' (backup as %s.sav)\n",
				name,name);
			return 0;
		}else{
		putMssg(BVStr(msg),"@ADM + cannot remove '%s', errno=%d\n",
			name,errno);
		}
	}
	if( unlink(path) == 0 ){
		putMssg(BVStr(msg),"@ADM + removed '%s'\n",name);
	}else{
		putMssg(BVStr(msg),"@ADM + cannot remove '%s', errno=%d\n",
			name,errno);
	}
	return 0;
}
static int copyConfig(Connection *Conn,PVStr(msg),PCStr(from),PCStr(to)){
	const char *conf;
	const char *oconf;
	int date;
	int odate;
	int eq;
	int rcode;

	conf = getConfigData(Conn,from,"",&date);
	if( conf == 0 ){
		putMssg(BVStr(msg),"@ADM - can't get '%s'\n",from);
		return -1;
	}

	if( oconf = getConfigData(Conn,to,"",&odate) ){
		eq = streq(oconf,conf);
		free((char*)oconf);
	}else{
		eq = 0;
	}
	if( eq ){
		putMssg(BVStr(msg),"@ADM - not copied, identical '%s' and '%s'\n",
			from,to);
		rcode = -1;
	}else{
		putConfig(to,"w",conf);
		rcode = 0;
	}
	free((char*)conf);
	return rcode;
}
static int saveconf(Connection *Conn,PVStr(msg),PCStr(serv),PCStr(conf)){
	const char *mode;
	FILE *fp;
	CStr(path,1024);
	CStr(save,256);
	const char *back;
	int date;

	if( streq(serv,config_self) ){
		putMssg(BVStr(msg),"@ADM - cannot write '%s'\n",serv);
		set_conferror("conf-newservname");
		return 0;
	}

	back = getConfigData(Conn,serv,"",&date);
	if( back )
		mode = "r+";
	else	mode = "w";
	if( fp = fopen_lockconf(BVStr(msg),serv,mode,AVStr(path),1) ){
		fclose(fp);
		if( back && streq(back,conf) ){
	putMssg(BVStr(msg),"@ADM + not saved, nothing changed '%s'\n",serv);
		}else{
			if( back ){
			sprintf(save,"%s.sav",serv);
			putConfig(save,"w",back);
			putMssg(BVStr(msg),"@ADM + made backup as %s\n",save);
			}
			putConfig(serv,"w",conf);
			putMssg(BVStr(msg),"@ADM + saved as %s\n",serv);
		}
	}else{
		set_conferror("conf-newservname");
		set_conferror("com");
	}
	if( back )
		free((char*)back);
	return 0;
}
static int backup1(Connection *Conn,PVStr(msg),PCStr(name)){
	CStr(path,1024);
	CStr(save,1024);
	FILE *lfp;

	if( strtailstr(name,".sav") != 0 ){
		putMssg(BVStr(msg),"@ADM + is backaup '%s'\n",name);
		return -1;
	}
	lfp = fopen_lockconf(BVStr(msg),name,"r",AVStr(path),0);
	if( lfp == NULL ){
		return -1;
	}
	fclose(lfp);
	sprintf(save,"%s.sav",name);
	lfp = fopen_lockconf(BVStr(msg),name,"r+",AVStr(path),1);
	if( lfp == NULL ){
		putMssg(BVStr(msg),"@ADM - can't backup to '%s' (locked)\n",name);
		return -1;
	}
	if( copyConfig(Conn,BVStr(msg),name,save) == 0 ){
		putMssg(BVStr(msg),"@ADM + backed up to '%s'\n",save);
	}
	fclose(lfp);
	return 0;
}
static int restore1(Connection *Conn,PVStr(msg),PCStr(name)){
	CStr(path,1024);
	CStr(orig,256);
	refQStr(dp,orig);
	CStr(origpath,1024);
	int rcode;
	FILE *lfp;

	lfp = fopen_lockconf(BVStr(msg),name,"r",AVStr(path),0);
	if( lfp == NULL ){
		return -1;
	}
	fclose(lfp);
	if( strtailstr(name,".sav") == 0 ){
		putMssg(BVStr(msg),"@ADM + is not backaup '%s'\n",name);
		return -1;
	}
	strcpy(orig,name);
	if( dp = strtailstr(orig,".sav") )
		truncVStr(dp);
	lfp = fopen_lockconf(BVStr(msg),orig,"r+",AVStr(origpath),1);
	if( lfp == NULL ){
		return -1;
	}
	if( copyConfig(Conn,TVStr(msg),name,orig) == 0 ){
		putMssg(BVStr(msg),"@ADM + restored '%s'\n",orig);
	}
	fclose(lfp);
	return 0;
}

#define CONF_SAVE	0x01
#define CONF_BACKUP	0x02
#define CONF_REMOVE	0x04
#define CONF_RESTORE	0x08
static int conf_removerestore(Connection *Conn,PVStr(msg),int com){
	int ai;
	const char *a1;
	int ncheck = 0;

	for( ai = 0; a1 = Form_argv[ai]; ai++ ){
		if( strneq(a1,"conf-checked=",13) ){
			ncheck++;
			switch( com ){
				case CONF_BACKUP:
					backup1(Conn,BVStr(msg),a1+13);
					break;
				case CONF_REMOVE:
					remove1(Conn,BVStr(msg),a1+13);
					break;
				case CONF_RESTORE:
					restore1(Conn,BVStr(msg),a1+13);
					break;
			}
		}
	}
	if( ncheck == 0 ){
		putMssg(BVStr(msg),"@ADM - nothing checked\n");
		set_conferror("conf-checked");
	}
	return ncheck;
}
static int conf_rename(Connection *Conn,PVStr(msg),PCStr(from),PCStr(to)){
	CStr(pathfrom,1024);
	CStr(pathto,1024);
	FILE *fp;

	if( from == NULL || *from == 0 )
		return 0;
	if( to == NULL || *to == 0 )
		return 0;

	getConfig(from,AVStr(pathfrom));
	getConfig(to,AVStr(pathto));

	if( File_is(pathfrom) && !writable(Conn,BVStr(msg),from) ){
		putMssg(BVStr(msg),"@ADM - can't rename from '%s' (locked)\n",from);
	}else
	if( File_is(pathto) && !writable(Conn,BVStr(msg),to) ){
		putMssg(BVStr(msg),"@ADM - can't rename to '%s' (locked)\n",to);
	}else
	if( rename(pathfrom,pathto) == 0 ){
		putMssg(BVStr(msg),"@ADM - renamed '%s' to '%s'\n",from,to);
	}else{
		putMssg(BVStr(msg),"@ADM - cannot rename '%s' to '%s'\n",from,to);
	}
	return 0;
}
static int conf_new(Connection *Conn,PVStr(msg),PCStr(name)){
	CStr(path,1024);
	FILE *fp;

	if( name == 0 || *name == 0 ){
		putMssg(BVStr(msg),"@ADM - enter a name to be created\n");
		return 0;
	}else
	if( *name == '_' && strtailchr(name) == '_' ){
		putMssg(BVStr(msg),"@ADM - cannot create, reserved name '%s'\n",
			name);
		return 0;
	}else
	if( getConfig(name,AVStr(path)) ){
		putMssg(BVStr(msg),"@ADM - cannot create, already exist '%s'\n",
			name);
		return 0;
	}else
	if( fp = fopen_lockconf(BVStr(msg),name,"r+",AVStr(path),1) ){
		putMssg(BVStr(msg),"@ADM + created new '%s'\n",name);
		fclose(fp);
		return 1;
	}else{
		putMssg(BVStr(msg),"@ADM - cannot create new '%s'\n",name);
		return 0;
	}
}
static int decompose(Connection *Conn,PVStr(msg),PCStr(conf)){
if( lHTMLGEN() )
 fprintf(stderr,"############ decompose [%s]\n",conf?conf:"");
	conf2form(BVStr(msg),conf,elnumof(admin_genv),admin_genv);
	form2conf(BVStr(msg),NULLFP(),0,-1);
	return 0;
}
static int conf_store(Connection *Conn,PVStr(msg),PCStr(dst),PCStr(src)){
	const char *newserv;
	const char *serv;
	const char *conf;

	newserv = getv(Form_argv,"conf-newservname");
	serv = getv(Form_argv,"conf-servname");
	conf = getv(Form_argv,"confdata");

	if( newserv && *newserv )
		serv = newserv;

	if( serv && *serv != 0 && conf != NULL ){
		saveconf(Conn,BVStr(msg),serv,conf);
		return 1;
	}else{
		set_conferror("conf-newservname");
		Xsprintf(BVStr(msg),"- no destination name specified");
		return 0;
	}
}

static int download(Connection *Conn,FILE *tc,int vno,PCStr(name),PCStr(type)){
	CStr(path,1024);
	int cleng;
	FILE *cfp = NULL;
	const char *localfile;

	if( type == 0 || *type == 0 )
		type = "text/plain";
	localfile = admin_getv("localfile");

if( lHTMLGEN() )
 fprintf(stderr,"--------- download %s to [%s]\n",name,localfile?localfile:"");

	if( getConfig(name,AVStr(path)) ){
		cfp = fopen(path,"r");
if( lHTMLGEN() )
 fprintf(stderr,"--------- download %s %s\n",name,path);
	}
	if( cfp != NULL ){
		if( localfile && *localfile )
sprintf(addRespHeaders,"Content-Disposition: attachment; filename=%s\r\n",localfile);
		cleng = file_size(fileno(cfp));
		cleng = HTTP_putHeader(Conn,tc,vno,type,cleng,-1);
		copyfile1(cfp,tc);
		fclose(cfp);
	}else{
		CStr(path,128);
		extbase(Conn,AVStr(path),"/-/admin/servers");
		cleng = putMovedTo(Conn,tc,path);
		/*
		cleng = putMovedTo(Conn,tc,"/-/admin/servers");
		*/
	}
	return cleng;
}

static int configControl(Connection *Conn,PCStr(url),int vno,FILE *fc,FILE *tc,int argc,const char *argv[]){
	int cleng;
	const char *com;
	const char *conf;
	const char *act;
	const char *prevact;
	CStr(path,1024);
	defQStr(msg);
	cpyQStr(msg,admin_respmssg);

	act = admin_act;
	if( act == 0 )
		goto EXIT;
	prevact = admin_prevact;

	if( strcaseeq(act,"APPEND") )
		conf = getv(argv,"confdata.add");
	else	conf = getv(argv,"confdata");

	if( !IsAdmin ){
		putMssg(AVStr(msg),"- ERROR: MUST be from admin port (%d)\n",
			Conn->clif._adminPort);
	}else
	if( strcaseeq(act,"CANCELL") ){
		cleng = putMovedTo(Conn,tc,"/-/admin/config");
		goto EXIT2;
	}else
	if( strcaseeq(act,"GET") ){
		if( getConfig("default",AVStr(path)) ){
			sprintf(msg,"Current Configuration is as follows");
		}else{
			sprintf(msg,"No configuration data");
		}
	}else
/*
	if( strcaseeq(act,"NEWSERV") ){
	}else
*/
	if( strcaseeq(act,"FORM2CONF") ){
/*
		Form2Conf(argc,argv,AVStr(msg));
*/
	}else
	if( strcaseeq(act,"QUITEDITLINE") ){
	}else
	if( strcaseeq(act,"EDITLINE") ){
		const char *ln;
		const char *com;
		const char *edata;
		if( ln = getv(argv,"ln") ){
			config_editln = atoi(ln);
			edata = getv(argv,"editdata");
			if( com = getv(argv,"com") ){
		editconfig(Conn,"default",com,config_editln,edata,AVStr(msg));
		sprintf(msg,"editing line#%04d [%s]",config_editln,com);
			}else{
				com = "";
				sprintf(msg,"editing line#%04d",config_editln);
			}
		}else	sprintf(msg,"Click the line to be edited");
	}else
	if( strcaseeq(act,"ADD") ){
		sprintf(msg,"Enter the following text and push <B>Add</B>");
	}else
	if( strcaseeq(act,"APPEND") ){
		if( conf[0] == 0 ){
			sprintf(msg,"-ERROR: empty data");
		}else{
			saveConfig(Conn,AVStr(msg));
			putConfig("default","a",conf);
		sprintf(msg,"OK: push <B>Restart</B> to refect the configuration");
		}
	}else
	if( strcaseeq(act,"EDIT") ){
		sprintf(msg,"Edit the following text and push <B>Set</B>");
	}else
	if( strcaseeq(act,"UNDO") ){
		restoreConfig(Conn,AVStr(msg));
	}else
	if( strcaseeq(act,"DOWNLOAD") ){
	    const char *name;
	    if( name = admin_getv("confname") ){
		return download(Conn,tc,vno,name,admin_getv("content-type"));
	    }
	    if( strcaseeq(prevact,"DOWNLOAD") ){
		CStr(path,1024);
		FILE *cfp = NULL;
		if( getConfig("default",AVStr(path)) ){
			cfp = fopen(path,"r");
		}
		if( cfp != NULL ){
			cleng = file_size(fileno(cfp));
		cleng =
		HTTP_putHeader(Conn,tc,vno,"application/octet-stream",cleng,-1);
			copyfile1(cfp,tc);
			fclose(cfp);
			goto EXIT2;
		}
		sprintf(msg,"-ERROR: no configuration file");
	    }else{
		sprintf(msg,"push <B>Download</B> again to download");
	    }
	}else
	if( strcaseeq(act,"UPLOAD") ){
		if( conf ){
			putConfig("default","w",conf);
	sprintf(msg,"OK: push <B>Restart</B> to refect the configuration");
		}else{
		sprintf(msg,"Enter the local file name and push <B>Upload</B>");
		}
	}else
	if( strcaseeq(act,"SET") ){
		if( conf ){
			putConfig("default","w",conf);
	sprintf(msg,"OK: push <B>Restart</B> to refect the configuration");
		}else{
		sprintf(msg,"-ERROR: no config. data");
		}
	}else
	if( strcaseeq(act,"RESTART") ){
	    if( strcaseeq(prevact,"RESTART") ){
		volrestart(Conn,NULL);
	sprintf(msg,"OK: restarted, <A HREF=?act=Showlog>Show startup log</A>");
	    }else{
		sprintf(msg,"Push <B>Restart</B> to restart the server");
	    }
	}else
	if( strcaseeq(act,"SHOWLOG") ){
		sprintf(msg,"OK");
	}else
	if( strcaseeq(act,"BACKUP") ){
		saveConfig(Conn,AVStr(msg));
	}else
	if( strcaseeq(act,"RESTORE") ){
		restoreConfig(Conn,AVStr(msg));
	}else{
		sprintf(msg,"-ERROR: the action '%s' not supported\n",act);
	}
EXIT:

	cleng = putBuiltinPage(Conn,vno,tc,"Config",
		"admin/Configure.dhtml",NULL,(iFUNCP)DHTML_printConn,NULL);

EXIT2:
	return cleng;
}
static int statsAdmin(Connection *Conn,PCStr(method),PCStr(url),int vno,FILE *fc,FILE *tc){
	int cleng;
	cleng = putBuiltinPage(Conn,vno,tc,"Stats",
		"admin/StatusCtl.dhtml",NULL,(iFUNCP)DHTML_printConn,NULL);
	return cleng;
}

static int doAccount(Connection *Conn,FILE *fc,FILE *tc,PCStr(who))
{
	const char *button;
	const char *digest;
	const char *user;
	const char *pass;
	const char *host;
	CStr(xhost,MaxHostNameLen);
	int argc,rcode;
	CStr(com,512);
	CStr(u,64);
	CStr(p,64);

	button = getv(Form_argv,"button");
	digest = getv(Form_argv,"digest");
	user = getv(Form_argv,"username");
	pass = getv(Form_argv,"password");
	host = getv(Form_argv,"domain");

	sv1log("ACCOUNT: %d button=[%s] user=[%s] domain=[%s]\n",Form_argc,
		button?button:"", user?user:"", host?host:"");

	if( user ) lineScan(user,admin_user);
	if( host ) lineScan(host,admin_domain);

	if( digest && streq(digest,"1") ){
		admin_basic = 0;
		if( host == 0 )
			host = "";
		if( strncmp(host,"-dgauth",7) != 0 ){
			strcpy(xhost,"-dgauth");
			if( *host != 0 ){
				strcat(xhost,".");
				wordscanX(host,TVStr(xhost),
					sizeof(xhost)-strlen(xhost));
			}
			host = xhost;
		}
	}else{
		admin_basic = 1;
		if( host == 0 || *host == 0 )
			host = "localhost";
	}
	if( pass == 0 )
		pass = "";

	com[0] = 0;
	if( button != 0 && (user != 0 && *user != 0) ){
		lineScan(user,u);
		lineScan(pass,p);
		if( strstr(button,"add") ){
			sprintf(com,"-Fauth -a %s %s",user,host);
			rcode = authEdit0(Conn,1,tc,'a',host,u,p);
		}
		else
		if( strstr(button,"delete") ){
			sprintf(com,"-Fauth -d %s %s",user,host);
			rcode = authEdit0(Conn,1,tc,'d',host,u,p);
		}
		else
		if( strstr(button,"verify") ){
			sprintf(com,"-Fauth -v %s %s",user,host);
			rcode = authEdit0(Conn,1,tc,'v',host,u,p);
		}
	}
	if( com[0] ){
		admin_command = stralloc(com);
	}
	return 1;
}
static int accountControl(Connection *Conn,int vno,PCStr(method),FILE *fc,FILE *tc,PCStr(who))
{	int leng,size;
	FILE *tmp;

	tmp = TMPFILE("Account");
	if( strneq(method,"POST",4) ){
		doAccount(Conn,fc,tmp,who);
	}
	fflush(tmp);
	if( 0 < (size = file_size(fileno(tmp))) ){
		if( admin_stat ){
			free((char*)admin_stat);
			admin_stat = 0;
		}
		fseek(tmp,0,0);
		admin_stat = (char*)malloc(size+1);
		IGNRETP fread(admin_stat,1,size,tmp);
		admin_stat[size] = 0;
	}
	fclose(tmp);

	leng = putBuiltinPage(Conn,vno,tc,"Account","admin/account.dhtml",
		NULL,(iFUNCP)DHTML_printConn,"");
	fflush(tc);
	return leng;
}

static CriticalSec captureCSC;
static CriticalSec sendCSC;
static CriticalSec recvCSC;
static int LogSent;
static int LogSendErr;
static int LogRecv;
static int LogRecvErr;
int sendLog(int sock,PCStr(str),int len){
	int wcc;
	if( lMULTIST() ){
		setupCSC("sendLog",sendCSC,sizeof(sendCSC));
		if( enterCSCX(sendCSC,1) != 0 ){
			LogSendErr++;
			return -1;
		}
	}
	wcc = send(sock,str,len,0);
	LogSent++;
	if( lMULTIST() ){
		leaveCSC(sendCSC);
	}
	return wcc;
}
int recvLog(FILE *tc,FILE *fc,int sock,int pls,char *buf,int bsz,int *rccp){
	int rcc;
	int nrdy;
	int fdv[2];
	int rdv[2];

	*rccp = 0;
	fdv[0] = sock;
	fdv[1] = fileno(fc);
	nrdy = PollIns(100,2,fdv,rdv);
	if( nrdy <= 0 ){
		fflush(tc);
		nrdy = PollIns(pls,2,fdv,rdv);
	}
	if( nrdy && rdv[1] )
		return -1;
	if( nrdy <= 0 )
		return nrdy;
	if( lMULTIST() ){
		setupCSC("recvLog",recvCSC,sizeof(recvCSC));
		if( enterCSCX(recvCSC,1) != 0 ){
			LogRecvErr++;
			buf[0] = 'x';
			*rccp = 1;
			return 0;
		}
	}
	rcc = recv(sock,buf,bsz,0);
	*rccp = rcc;
	LogRecv++;
	if( lMULTIST() ){
		leaveCSC(recvCSC);
	}
	return nrdy;
}
void dumpDGFL(void *me,FILE *tc);
int setDebugX(Connection *Conn,PCStr(arg),int force);
int captureLOG(Connection *Conn,FILE *tc,FILE *fc,int lns,int sec){
	double St;
	int oexp,nexp;
	int leng = 0;
	int ln = 0;
	int icc,rcc,wcc;
	int rem,pls;
	IStr(buf,1024);
	int bi;
	int nrdy;
	int pad = 0;
	int min = 5000;
	IStr(emsg,1024);

	if( lMULTIST() ){
		leng += fprintf(tc,"--Log S/R{%d,%d] err{%d,%d}\n",
			LogSent,LogRecv,LogSendErr,LogRecvErr);
		setthread_FL(0,FL_ARG,"capturing");
		dumpthreads("-",tc);
		fflush(tc);
	}
	setupCSC("captureLog",captureCSC,sizeof(captureCSC));
	if( enterCSCX(captureCSC,1000) != 0 ){
		leng += fprintf(tc,"ERROR:under capturing by anotherone %X\r\n",
			PRTID(LOG_recvTid));
		return leng;
	}
	oexp = lPUTUDPLOG();
	nexp = time(0) + sec;
	if( oexp < nexp ){
		lPUTUDPLOG() = nexp;
		LOG_recvTid = getthreadid();
		if( lLOGCTRL() ){
			fprintf(stderr,"[%u] enabled UDPLOG: %d<%d\n",
				getpid(),oexp,nexp);
		}
	}else{
		nexp = 0;
	}
	LOG_type3T |= L_BCASTLOG;
	St = Time();

	for(;;){
		rem = (int)(1000*(sec-(Time()-St)));
		if( rem <= 0 ){
			sprintf(emsg,"timeout %d/%d %.3f",rem,sec,Time()-St);
			break;
		}
		if( min < rem )
			pls = min;
		else	pls = rem;
		if( pls <= 0 )
			pls = 1;
		nrdy = recvLog(tc,fc,LOG_UDPsock[0],pls,buf,sizeof(buf),&rcc);
		if( nrdy <= 0 ){
			fflush(tc);
			if( fPollIn(fc,1) ){
				break;
			}
			if( !lSINGLEP() && !procIsAlive(serverPid()) ){
				porting_dbg("captureLOG() server [%d] dead",
					serverPid());
				sprintf(emsg,"server exit");
				break;
			}
			if( pad == 0 )
				sprintf(buf,"...");
			else
			if( 0 < rcc )
				sprintf(buf,"-");
			else	sprintf(buf,".");
			pad++;
			icc = strlen(buf);
			fflush(tc);
			wcc = write(fileno(tc),buf,icc);
			if( lLOGCTRL() ){
			fprintf(stderr,"-- captureLOG %d %d/%d %d/%d %d*%d\n",
				pls,rem/1000,sec,ln,lns,wcc,pad);
			}
			if( wcc <= 0 ){
				sprintf(emsg,"i-write failure %d/%d",wcc,icc);
				break;
			}
			continue;
		}
		if( pad ){
			wcc = fprintf(tc,"\r\n");
			pad = 0;
		}
		if( 0 < rcc ){
			wcc = fwrite(buf,1,rcc,tc);
			if( wcc < 0 ){
				sprintf(emsg,"write failure %d/%d",wcc,rcc);
				break;
			}
			leng += wcc;
			for( bi = 0; bi < rcc; bi++ ){
				if( buf[bi] == '\n' ){
					ln++;
				}
			}
			if( lns < ln ){
				sprintf(emsg,"filled %d/%d",ln,lns);
				break;
			}
		}
	}
	sv1log("captureLOG done (%s)\n",emsg);
	fprintf(tc,"%s\r\n",emsg);
	if( lMULTIST() ){
		dumpthreads("+",tc);
		dumpDGFL(Conn,tc);
		dumposf(tc,"capture",0,0,0);
		dumpFILEX(tc,0);
		fprintf(tc,"--Log S/R{%d,%d] err{%d,%d} exp=%d\r\n",
			LogSent,LogRecv,LogSendErr,LogRecvErr,nexp);
	}
	if( lPUTUDPLOG() == nexp ){
		lPUTUDPLOG() = 0;
	}
	leaveCSC(captureCSC);
	return leng;
}

const char *setupLoglev(LogControl *logControl,PCStr(lev)){
	const char *lv;
	if( lev && *lev  ){
		LOG_type1 &= ~(L_SILENT|L_TERSE|L_VERB);
		switch( *lev ){
		  case 's': LOG_type1 |= L_SILENT; break;
		  case 't': LOG_type1 |= L_TERSE; break;
		  default:
		  case 'u': break;
		  case 'v':
		  case 'd': LOG_type1 |= L_VERB; break;
		}
		if( lVERB() )
			LOG_VERBOSE = 1;
		else	LOG_VERBOSE = 0;
	}
	lv = "u";
	if( LOG_type1 & L_SILENT ) lv = "s"; else
	if( LOG_type1 & L_TERSE ) lv = "t"; else
	if( LOG_type1 & L_VERB ) lv = "v";
	return lv;
}
//void HTTP_clntClose(Connection *Conn,PCStr(fmt),...);
static int loggingControl(Connection *Conn,int vno,PCStr(method),FILE *fc,FILE *tc)
{	int leng;
	const char *v1;
	const char *lev;
	const char *com;
	const char *lv,*Lv;
	IStr(levc,32);
	IStr(Levc,32);
	int osp,Osp;
	int csc = 5;
	int cln = 500;
	int flags = 0;
	LogControl olc[2];

	com = admin_getv("com");
	lev = admin_getv("loglev");
	if( v1 = admin_getv("capsec") ) csc = atoi(v1);
	if( v1 = admin_getv("caplns") ) cln = atoi(v1);
	if( lLOGCTRL() ){
		fprintf(stderr,"--logging com[%s] lev[%s] capture:%d/%d\n",
			com?com:"",lev?lev:"",cln,csc);
	}
	Lv = lv = setupLoglev(&logControl[LC_PST],"");
	olc[LC_PST] = logControl[LC_PST];
	olc[LC_TMP] = logControl[LC_TMP];
	if( v1 = admin_getv("opt") ){
		setDebugX(Conn,v1,1);
	}
	if( com ){
		if( streq(com,"logging") ){
			Lv = lv = setupLoglev(&logControl[LC_PST],lev);
		}
		if( streq(com,"capture") ){
			lv = setupLoglev(&logControl[LC_TMP],lev);
			flags |= BP_NOCLENG;
			sprintf(addRespHeaders,"%s\r\n%s\r\n",
				"Pragma: no-cache",
				"X-Pragma: no-gzip");
			HTTP_clntClose(Conn,"logging/capture");
		}
	}
	if( lev == 0 || *lev == 0 ){
		sprintf(levc,"loglev=%s",lv);
		if( lLOGCTRL() )
		fprintf(stderr,"--logging [%d]%s(%X)\n",admin_genc,levc,p2i(lev));
		osp = pushgenv(Conn,levc);
	}
	sprintf(Levc,"LogLev=%s",Lv);
	Osp = pushgenv(Conn,Levc);
	leng = putBuiltinPageX(Conn,vno,tc,"Logging","admin/logging.dhtml",
		NULL,(iFUNCP)DHTML_printConn,"",flags);
	popgenv(Conn,Osp);
	if( lev == 0 ){
		popgenv(Conn,osp);
	}

	if( com && streq(com,"capture") ){
		fprintf(tc,"<PR><PLAINTEXT>\r\n");
		fflush(tc);
		captureLOG(Conn,tc,fc,cln,csc);
		logControl[LC_PST] = olc[LC_PST];
	}else{
		fflush(tc);
	}
	return leng;
}
int dump_ENTR(PVStr(entrance));
static int dumpcurconf(Connection *Conn,FILE *tc){
	IStr(entrance,256);

	/*
	fprintf(tc,"DGROOT=\"%s\"\n",DELEGATE_DGROOT);
	fprintf(tc,"ADMIN=\"%s\"\n",DELEGATE_ADMIN);
	if( iSERVER_PROTO[0] )
	fprintf(tc,"SERVER=\"%s\"\n",iSERVER_PROTO);
	if( dump_ENTR(AVStr(entrance)) ){
		fprintf(tc,"%s\n",entrance);
	}
	*/
	return 0;
}

static int identd_auth(Connection *Conn,AuthInfo *ident,PVStr(who),PCStr(command))
{
	if( who == 0 && (AuthStat & A_EVALED_IDENT) )
		return AuthStat;
	AuthStat = (AuthStat & ~A_IDENT) | A_EVALED_IDENT;

	{	CStr(asv,256);
		truncVStr(asv);
		getAdminAuthorizer(Conn,AVStr(asv),sizeof(asv),1);
		if( !streq(asv,"*") ){
			/* explicit authServ, not the obsolete default */
			return AuthStat;
		}
	}

	if( VA_getOriginatorIdent(Conn,ident) == 0 )
		return AuthStat;

	AuthStat |= A_WITH_IDENTD;

	sprintf(who,"%s@%s",ident->i_user,ident->i_Host);
	if( CTX_auth_admin(Conn,command,"IDENT",who) )
		AuthStat |= A_OK_IDENTAUTHOR;
	return AuthStat;
}

int CTX_protoAuthorizer(Connection *Conn,PCStr(proto),PVStr(asv),int asiz);
static int passwd_auth2(Connection *Conn,AuthInfo *xident,PVStr(who),PCStr(command));
static int passwd_auth(Connection *Conn,AuthInfo *ident,PVStr(who),PCStr(command))
{	AuthInfo xident;
	const char *aus = 0;
	CStr(asv,256);
	CStr(tmp,256);
	CStr(aub,256);
	int astat;

	if( who == 0 && (AuthStat & A_EVALED_PASS) )
		return AuthStat;
	AuthStat = (AuthStat & ~A_PASS) | A_EVALED_PASS;

	/* Authentication was done and the field was removed in AUTHORIZER */
	/*
	if( ClientAuth.i_stat == AUTH_SET )
	*/
	if( ClientAuth.i_stat & (AUTH_SET|AUTH_MAPPED) )
	if( ClientAuth.i_error == 0 )
	{
		AuthStat |= A_WITH_PASSAUTH;
		AuthStat |= A_OK_PASSAUTHEN;
		*ident = ClientAuth;

		if( ident->i_Host[0] == '-' )
			sprintf(who,"%s",ident->i_user);
		else
		sprintf(who,"%s@%s",ident->i_user,ident->i_Host);
		aus = getAdminAuthorizer(Conn,AVStr(tmp),sizeof(tmp),1);
		sv1log("Admin Authenticated[%s] -> [%s]\n",ident->i_Host,who);

		astat = passwd_auth2(Conn,&ClientAuth,BVStr(who),command);
		if( astat & A_OK_PASSAUTHOR ){
			/* AUTHORIZER=... + AUTH=admin:... */
			AuthStat |= A_OK_PASSAUTHOR;
		}else
		if( CTX_auth_admin(Conn,command,"AUTHORIZER",who) )
			AuthStat |= A_OK_PASSAUTHOR;
		else	AuthStat |= A_REJ_PASSAUTHOR;
		return AuthStat;
	}

	if( !HTTP_getAuthorization(Conn,0,&xident,1) )
		return AuthStat;

	AuthStat = passwd_auth2(Conn,&xident,BVStr(who),command);

	if( AuthStat & A_OK_PASSAUTHEN ){
		char pass[64];
		Xstrcpy(FVStr(pass),"MD5:");
		toMD5(xident.i_pass,pass+strlen(pass));
		if( AdminPass ) free(AdminPass);
		if( AdminUser ) free(AdminUser);
		AdminPass = stralloc(pass);
		AdminUser = stralloc(xident.i_user);
		*ident = xident;
	}
	return AuthStat;
}
static int admin_auth(Connection *Conn,PCStr(user),PCStr(pass)){
	CStr(who,128);
	AuthInfo xident;
	int auth = AuthStat;
	int rauth;

	if( user == 0 || pass == 0 )
		return -1;
	AuthStat = 0;
	bzero(&xident,sizeof(xident));
	strcpy(xident.i_user,user);
	strcpy(xident.i_pass,pass);
	rauth = passwd_auth2(Conn,&xident,AVStr(who),"test");
	rauth = AuthStat;
	AuthStat = auth;
	if( rauth & A_OK_PASSAUTHOR )
		return 0;
	return -1;
}
static int passwd_auth2(Connection *Conn,AuthInfo *xident,PVStr(who),PCStr(command)){
	const char *aus = 0;
	CStr(asv,256);
	CStr(tmp,256);
	CStr(aub,256);

	asv[0] = 0;
	if( aus = getAdminAuthorizer(Conn,AVStr(tmp),sizeof(tmp),1) ){
		CStr(hosts,MaxHostNameLen);
		int hl;
		int ec;
		int ok;
		ec = scan_Listlist(aus,':',AVStr(aub),AVStr(hosts),VStrNULL,
			VStrNULL,VStrNULL);
		if( ec == 2 ){
			aus = aub;
			hl = makePathList("AdminAuth",hosts);
			ok =
			matchPath1(hl,xident->i_user,Client_Host,Client_Port);
			sv1log("AUTH=admin for %s@%s:%d match=%d with {%s}\n",
				xident->i_user,Client_Host,Client_Port,ok,hosts);
			if( !ok )
				return AuthStat;
		}
		if( !streq(tmp,"*") ){
			strcpy(asv,tmp);
		}
		if( xident->i_Host[0] == 0 ){
			const char *dp;
			if( dp = strrchr(aus,'@') ){
				strcpy(xident->i_Host,dp+1);
			}
		}
	}
	else{
		aus = "";
	}
	if( asv[0] != 0 ){
		/* AUTH=admin should be prior to (generic) AUTHORIZER */
	}else
	if( CTX_protoAuthorizer(Conn,"admin",AVStr(tmp),sizeof(tmp)) ){
		strcpy(asv,tmp);
		strcpy(REAL_PROTO,"admin");
	}
	if( asv[0] ){
		strcpy(xident->i_Host,asv);
		if( aus == 0 ) /* without AUTH parameter */
			aus = xident->i_user;
	}
	if( aus && (aus[0] == 0 || streq(aus,"*")) ){
		aus = xident->i_user; /* AUTH="admin:authServ:*" */
	}
	if( xident->i_Host[0] == 0 )
		strcpy(xident->i_Host,"localhost");

	sv1log("AdminAuthorizer[%s]:[%s] User[%s]\n",asv,aus,xident->i_user);


	AuthStat |= A_WITH_PASSAUTH;
	if( AuthenticateX(Conn,xident->i_Host,xident->i_user,xident->i_pass,
	 "/",xident) < 0 ){
		AuthStat |= A_REJ_PASSAUTHEN;
		if( asv[0] ){
			/* set REQ_AUTH to be used Authenticate:Digest */
			REQ_AUTH = *xident;
		}
		return AuthStat;
	}

	AuthStat |= A_OK_PASSAUTHEN;

	sprintf(who,"%s@%s",xident->i_user,xident->i_Host);
	if( asv[0] == '-' && aus[0] == 0 ){
		/* any user is OK: acceptable user list is not specified */
		AuthStat |= A_OK_PASSAUTHOR;
	}else
	if( asv[0] && (isinList(aus,xident->i_user)||(isinList(aus,who))) ){
		AuthStat |= A_OK_PASSAUTHOR;
	}else
	if( CTX_auth_admin(Conn,command,"FTP",who) )
		AuthStat |= A_OK_PASSAUTHOR;
	else	AuthStat |= A_REJ_PASSAUTHOR;
	return AuthStat;
}

int IsMyself(PCStr(host));
int localsocket(int sock);
static int sysauthok(Connection *Conn,PVStr(msg),PCStr(user),PCStr(pass)){
	/*
	if( localsocket(ClientSock) ){
		putMssg(BVStr(msg),"@ADM + sysauthok for self '%s'\n",Client_Host);
		return 1;
	}
	*/
	if( IsMyself(Client_Host) ){
		/*
		putMssg(BVStr(msg),"@ADM + sysauthok for myself '%s'\n",Client_Host);
		*/
		return 1;
	}
	putMssg(BVStr(msg),"@ADM - sysauthok not implemented yet for remote: '%s'\n",
		Client_Host);
	return 0;
}

int DHTML_printAuth(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(name),PCStr(arg),const void *value)
{	AuthInfo ident;

	if( streq(arg,"admin_enabled") ){
		CStr(asv,256);
		if( CTX_protoAuthorizer(Conn,"admin",AVStr(asv),sizeof(asv)) )
			return 1;
		return CTX_with_auth_admin(Conn);
	}else
	if( streq(arg,"fauth") ){
		if( ClientAuth.i_stat && ClientAuth.i_error == 0 ){
			fprintf(fp,"%s@%s",ClientAuth.i_user,ClientAuth.i_Host);
		}else
		if( HTTP_getAuthorization(Conn,0,&ident,0) )
			fputs(ident.i_user,fp);
	}else
	if( streq(arg,"with_pass") )  return AuthStat & A_WITH_PASSAUTH; else
	if( streq(arg,"withauth") )   return AuthStat & A_WITH_PASSAUTH; else
	if( streq(arg,"withident") )  return AuthStat & A_WITH_IDENTD; else
	if( streq(arg,"iauthorized") )return AuthStat & A_OK_IDENTAUTHOR; else
	if( streq(arg,"authorized_pass") )
		return AuthStat & A_OK_PASSAUTHOR; else
	if( streq(arg,"authorized") )
		 return AuthStat & (A_OK_IDENTAUTHOR|A_OK_PASSAUTHOR); else
	if( streq(arg,"bad_pass") )   return AuthStat & A_REJ_PASSAUTHEN; else
	if( streq(arg,"rej_pass") )   return AuthStat & A_REJ_PASSAUTHOR; else
	{
		/* unknown arg */
	} 
	return 0;
}
int admin_authok(Connection *Conn){
	return AuthStat & A_OK_PASSAUTHOR;
}

extern char GEN_MovedTo[];
int putBuiltinPage(Connection *Conn,int vno,FILE *tc,PCStr(what),PCStr(upath),PCStr(desc),iFUNCP func,PCStr(arg))
{
	return putBuiltinPageX(Conn,vno,tc,what,upath,desc,func,arg,0);
}
int putBuiltinPageX(Connection *Conn,int vno,FILE *tc,PCStr(what),PCStr(upath),PCStr(desc),iFUNCP func,PCStr(arg),int flags)
{	FILE *tmp;
	int leng,cleng;
	const char *chset;
	CStr(ctype,1024);

	if( CCXactive(CCX_TOCL) == 0 ){
		CCXcreate("*","guess-and-set",CCX_TOCL);
	}

	tmp = TMPFILE(what);
	GEN_MovedTo[0] = 0;
	putBuiltinHTML(Conn,tmp,what,upath,NULL,func,NULL);
	if( GEN_MovedTo[0] ){
		leng = putMovedTo(Conn,tc,GEN_MovedTo);
		GEN_MovedTo[0] = 0;
	}else{
		fflush(tmp); cleng = ftell(tmp); fseek(tmp,0,0);
		strcpy(ctype,"text/html");
		chset = 0;
		if( CCXguessing(CCX_TOCL) )
			chset = CCXident(CCX_TOCL);
		else	CCXoutcharset(CCX_TOCL,&chset);
		if( chset == 0 || *chset == 0 ){
			if( isWindowsCE() ){
				chset = "UTF-8";
			}
		}
		if( chset && *chset ){
			Xsprintf(TVStr(ctype),"; charset=%s",chset);
		}
if( lHTMLGEN() )
 fprintf(stderr,"---- putting Header [%s] guessing=%d\n",ctype,CCXguessing(CCX_TOCL));

		if( flags & BP_NOCLENG ){
			cleng = 0;
		}
		leng = HTTP_putHeader(Conn,tc,vno,ctype,cleng,-1);
		if( RespWithBody ){
			copyfile1(tmp,tc);
		}
	}
	fclose(tmp);
	return leng + cleng;
}
static int putText(Connection *Conn,int vno,FILE *tc,FILE *txt)
{	int leng,cleng;

	fflush(txt); cleng = ftell(txt); fseek(txt,0,0);
	leng = HTTP_putHeader(Conn,tc,vno,"text/plain",cleng,-1);
	if( RespWithBody ) copyfile1(txt,tc);
	fclose(txt);
	fflush(tc);
	return leng + cleng;
}

int stop_server(FILE *dst);
void stopStickyServer(PCStr(why));
int get_init_size();
static int volrestart(Connection *Conn,FILE *tmp){
	int ri;
	int itime;
	int isize;

	sv1log("++++ voluntary restart: set softbreak ...\n");
	stopStickyServer("admin.volrestart");
	isize = get_init_size();
	setSoftBreak(Conn,"");
	for( ri = 0; ri < 30; ri++ ){
		if( get_init_size() != isize ){
			break;
		}
		sleep(1);
	}
	if( tmp ){
		sleep(1); /* wait init to finish ... */
		get_serverinitlog(tmp);
	}
	sv1log("++++ voluntary restart: sent startlog #%d\n",ri);
	return 0;
}

void HTML_clearCache(PCStr(url));
static int getconv(Connection *Conn,PCStr(lang),PVStr(rurl),PVStr(map),int siz){
	CStr(aurl,1024);
	if( lang == 0 || *lang == 0 ){
		return 0;
	}
	sprintf(aurl,"/-/builtin/mssgs/admin/admin-%s.cnv",lang);
        if( 0 < getBuiltinData(Conn,"Conv",aurl,AVStr(map),siz,BVStr(rurl)) ){
/*
 fprintf(stderr,"-- lang-%s [%s] leng=%d / %d\n",lang,rurl,strlen(map),siz);
*/
		return 1;
	}else{
		return 0;
	}
}

int addHostSet(PCStr(hostset),PCStr(host),PCStr(addr),int del,PVStr(msg));
int updateHostSet(PCStr(set),int *nh);
int putHostSet(FILE *fp,PCStr(set),int expire);
static void setconvmap(Connection *Conn,int ac,const char *av[]);
static int sysauthok(Connection *Conn,PVStr(msg),PCStr(user),PCStr(pass));
int DHTML_printForm2conf(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(pm),PCStr(pma1),PCStr(pma2),int *cleng);
int DHTML_printAdmin(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(name),PCStr(param))
{	CStr(pm,256);
	CStr(pma,4*1024);
	CStr(pma1,4*1024);
	CStr(pma2,4*1024);
	int cleng;
	refQStr(rmsg,admin_respmssg);
	const char *a1;
	int aput;

	truncVStr(pm);
	truncVStr(pma);
	truncVStr(pma1);
	truncVStr(pma2);
	Xsscanf(param,"%[^.].%[^\377]",AVStr(pm),AVStr(pma));
	Xsscanf(param,"%[^.].%[^.].%[^\377]",AVStr(pm),AVStr(pma1),AVStr(pma2));

	if( streq(pm,"dump_common") ){
		CStr(vb,1024);
		const char *a1;

		a1 = admin_getv("lang");
		if( a1 && *a1 ){
		sprintf(vb,"<INPUT type=hidden name=lang value=\"%s\">\n",a1);
		fputs(vb,fp);
		}

		a1 = admin_getv("menu");
		if( a1 && *a1 ){
		sprintf(vb,"<INPUT type=hidden name=menu value=\"%s\">\n",a1);
		fputs(vb,fp);
		}

		a1 = admin_getv("mode");
		if( a1 && *a1 ){
		sprintf(vb,"<INPUT type=hidden name=mode value=\"%s\">\n",a1);
		fputs(vb,fp);
		}
		return 1;
	}
	if( streq(pm,"url_common") ){
		aput = 0;
		a1 = admin_getv("lang");
		if( a1 && *a1 && !streq(a1,"en") ){
			fprintf(fp,"lang=%s",a1);
			aput = 1;
		}
		a1 = admin_getv("menu");
		if( a1 && *a1 ){
			if( aput ) fprintf(fp,"&");
			aput = 1;
			fprintf(fp,"menu=%s",a1);
		}
		return 1;
	}
	if( rmsg == 0 ){
		if( fp ){
			fprintf(fp,"(*NotAccessedViaAdmin*)");
		}
		return 0;
	}
/*
 fprintf(stderr,"-- printAdmin %X [%s][%s]\n",fp,name,param);
*/
	if( streq(param,"stat") ){
		if( admin_stat )
			return 1;
		else	return 0;
	}else
	if( streq(param,"command") ){
		if( admin_command ){
			HTML_ccxput1s(Conn,fp,fmt,admin_command);
		}
	}else
	if( streq(param,"result") ){
		if( admin_stat ){
			HTML_ccxput1s(Conn,fp,fmt,admin_stat);
		}
	}
	else
	if( streq(param,"respmssg") ){
		if( rmsg ){
			HTML_ccxput1s(Conn,fp,fmt,rmsg); /* not interpret ${} */
			return rmsg[0];
		}
		return 0;
	}else
	if( streq(pm,"putrespmssg") ){
		putMssg(AVStr(rmsg),"%s\n",pma);
		return 0;
	}else
	if( streq(pm,"config") && streq(pma1,"writable") ){
		const char *a1;
		a1 = admin_getv(pma2);
		if( a1 && *a1 )
			return writable(Conn,VStrNULL,a1);
		else	return 0;
	}else
	if( streq(pm,"confsize") ){
		fprintf(fp,"0");
	}else
	if( streq(param,"config.error") ){
		if( rmsg && *rmsg == '-' ){
			return 1;
		}else	return 0;
	}else
	if( streq(param,"prevact") ){
		if( admin_prevact )
			put1sX(Conn,fp,fmt,admin_prevact);
	}else
	if( streq(param,"act") ){
		if( admin_act )
			put1sX(Conn,fp,fmt,admin_act);
	}else
	if( strneq(param,"prevact.",8) ){
		if( admin_prevact ){
			return isinList(param+8,admin_prevact);
		}else	return 0;
	}else
	if( streq(pm,"admpath") ){
		if( admin_admpath ){
			CStr(path,1024);
			wordScanY(admin_admpath,path,"^?");
			put1sX(Conn,fp,fmt,path);
			return isinList(pma1,path);
		}else	return 0;
	}else
	if( streq(pm,"admact") ){
		if( admin_admcom ){
			if( *pma1 == 0 ){
				return *admin_admcom;
			}
			return isinList(pma1,admin_admcom);
		}else	return 0;
	}else
	if( strneq(param,"act.",4) ){
		if( admin_act ){
			return isinList(pma1,admin_act);
		}else	return 0;
	}else
	if( streq(pm,"com") ){
		if( admin_com )
			return isinList(pma1,admin_com);
		else	return 0;
	}else
	if( strneq(param,"authlog",7) ){
		FILE *lfp;
		int size = 2048;
		if( param[7] == '.' ){
			size = atoi(param+8);
		}
		if( lfp = get_authlog(Conn,"admin","ALL",size,1) ){
			filter_authlog(Conn,lfp,fp);
			fclose(lfp);
		}
	}else
	if( DHTML_printForm2conf(Conn,fp,fmt,pm,pma1,pma2,&cleng) ){
		return cleng;
	}else
	if( !admin_authok(Conn) ){
		if( fp ){
			fprintf(fp,"(*NotLoggedInAsAdmin(%s)*)",pm);
		}
		return 0;
	}else
	if( streq(name,"main") ){
		if( streq(param,"args") ){
			int ai;
			for( ai = 0; ai < main_argc; ai++ ){
				fprintf(fp,"arg[%d] %s\r\n",ai,main_argv[ai]);
			}
		}
	}else
	if( streq(pm,"curconf") ){
		dumpcurconf(Conn,fp);
	}else
	if( streq(param,"conf-selfname") ){
		put1sX(Conn,fp,fmt,config_self);
	}else
	if( streq(pm,"isself") ){
		const char *name;
		int pid;
		name = admin_getv(pma1);
		if( name && *name ){
			pid = getpidof(name);
			return pid == serverPid();
		}
		return 0;
	}else
	if( streq(pm,"decompose_conf") ){
		decompose(Conn,AVStr(rmsg),admin_getv(pma1));
	}else
	if( streq(pm,"new_conf") ){
/*
 fprintf(stderr,"-- new_conf [%s][%s]%X\n",param,pma1,admin_getv(pma1));
*/
		conf_new(Conn,AVStr(rmsg),admin_getv(pma1));
	}else
	if( streq(pm,"rename_conf") ){
		conf_rename(Conn,AVStr(rmsg),admin_getv(pma1),admin_getv(pma2));
	}else
	if( streq(pm,"remove_conf") ){
		conf_removerestore(Conn,AVStr(rmsg),CONF_REMOVE);
	}else
	if( streq(pm,"backup_conf") ){
		conf_removerestore(Conn,AVStr(rmsg),CONF_BACKUP);
	}else
	if( streq(pm,"restore_conf") ){
		conf_removerestore(Conn,AVStr(rmsg),CONF_RESTORE);
	}else
	if( streq(pm,"start_serv") ){
		return serv_startstop(Conn,AVStr(rmsg),pma1,pma2,SERV_START);
	}else
	if( streq(pm,"restart_serv") ){
		return serv_startstop(Conn,AVStr(rmsg),pma1,pma2,SERV_RESTART);
	}else
	if( streq(pm,"stop_serv") ){
		return serv_startstop(Conn,AVStr(rmsg),pma1,pma2,SERV_STOP);
	}else
	if( streq(pm,"show_initlog") ){
		return serv_showinit(Conn,AVStr(rmsg),pma1,pma2,fp);
	}else
	if( streq(pm,"storeconf") ){
		return conf_store(Conn,AVStr(rmsg),pma1,pma2);
	}else
	if( streq(pm,"loadconf") ){
		return load_servconf(Conn,AVStr(rmsg),pma1,pma2);
	}else
	if( streq(pm,"sysauthok") ){
		return sysauthok(Conn,AVStr(rmsg),admin_getv(pma1),admin_getv(pma2));
	}else
	if( streq(param,"confdatas") ){
		return dump_confdata(AVStr(rmsg),Conn,fp,fmt);
	}else
	if( streq(pm,"config") && streq(pma1,"form2conf") ){
		if( pma2 && streq(pma2,"check") ){
if( lHTMLGEN() )
 fprintf(stderr,"---- config.form2conf.check form2conf - A checking\n");
			form2conf(AVStr(rmsg),NULLFP(),0,-1);
		}else{
if( lHTMLGEN() )
 fprintf(stderr,"---- config %s.%s - B\n",pm,pma1);
			form2conf(AVStr(rmsg),fp,0,-1);
		}
	}else
	if( strneq(param,"editconf",8) ){
		if( streq(param+8,".curln") )
			fprintf(fp,"%d",config_editln);
	}else
	if( strneq(param,"getconfig",9) ){
		if( streq(param+9,".crc32") ){
			int crc = crc32config();
			fprintf(fp,"%08X/%u",crc,crc);
		}else
		if( streq(param+9,".curln") ){
			if( config_editln )
			dispconfig(Conn,fp,1,0,config_editln,0,NULL);
		}else
		if( streq(param+9,".putln") )
			dispconfig(Conn,fp,1,"config?act=Editline&ln=",0,0,NULL);
		else	dispconfig(Conn,fp,1,0,0,0,NULL);
	}else
	if( streq(param,"statconf") ){
		int DELEGATE_dumpEnvX(FILE *fp,int gentoo,int imPM,int showx);
		FILE *tmp;
		tmp = TMPFILE("Admin.showconf");
		DELEGATE_dumpEnvX(tmp,1,1,0);
		fflush(tmp);
		fseek(tmp,0,0);
		dumpfile(tmp,fp,"text/plain",1,0,0,0,NULL,32*1024,512,64);
	}else
	if( streq(param,"getlog") ){
		FILE *tmp;
		tmp = TMPFILE("Admin.getlog");
		get_serverinitlog(tmp);
		fflush(tmp);
		fseek(tmp,0,0);
		dumpfile(tmp,fp,"text/plain",1,0,0,0,NULL,32*1024,512,64);
		fclose(tmp);
	}else
	if( strneq(pm,"hostset-",8) ){
		const char *set = 0;
		const char *host = 0;
		CStr(msg,1024);
		const char *addr = "";

		if( pma1[0] )
			set = admin_getv(pma1);
		if( set == 0 )
			set = "screen";
		if( pma2[0] ){
			host = admin_getv(pma2);
			addr = gethostaddr(host);
		}
		if( streq(pm+8,"get") ){
			extern int SCREEN_TIMEOUT;
			int exp = 0;
			if( streq(set,"screen") )
				exp = SCREEN_TIMEOUT;
			putHostSet(fp,set,exp);
		}else
		if( streq(pm+8,"add") ){
			int nh;
			addHostSet(set,host,addr,0,AVStr(msg));
			updateHostSet(set,&nh);
		}else
		if( streq(pm+8,"del") ){
			int nh;
			addHostSet(set,host,addr,1,AVStr(msg));
			updateHostSet(set,&nh);
		}
		return 1;
	}else
	if( streq(pm,"openssl") ){
		int putSSLverX(FILE *fp,PCStr(fmt));
		if( streq(pma1,"version") ){
			putSSLverX(fp,"%n %v %d");
			return 1;
		}
		return OpenSSL(AVStr(rmsg),Conn,fp,pma);
	}else
	if( streq(pm,"system") ){
		systemStatus(AVStr(rmsg),Conn,admin_getv("com"),fp);
	}else
	if( strneq(param,"showdir",7) ){
		showdir1(AVStr(rmsg),Conn,fp,SHOW_DIR,NULL,NULL);
	}else
	if( streq(pm,"foreachfile") ){
		const char *sort;
		if( strncmp(pma1,"sortby-",7) == 0 ){
			sort = admin_getv(pma1+7);
		}
		showdir1(AVStr(rmsg),Conn,fp,SHOW_DIR,sort,pma2);
	}else
	if( streq(pm,"is_dir") ){
		return showdir1(AVStr(rmsg),Conn,fp,SHOW_ISDIR,"is-dir",NULL);
	}else
	if( streq(pm,"show_file") ){
		return showdir1(AVStr(rmsg),Conn,fp,SHOW_FILE,"show-file",pma1);
	}else
	if( streq(pm,"remove_file") ){
		const char *file;
		file = admin_getv(pma1);
		showdir1(AVStr(rmsg),Conn,fp,SHOW_REMOVE,"remove-file",file);
	}else
	if( streq(pm,"create_file") ){
		const char *file;
		file = admin_getv(pma1);
		showdir1(AVStr(rmsg),Conn,fp,SHOW_CREATE,"create-file",file);
	}else
	if( streq(pm,"openfiles") ){
		foreachfile(fp,pma1,pma2);
	}else
	if( streq(param,"user") ){
		put1sX(Conn,fp,fmt,admin_user);
	}
	else
	if( streq(param,"domain") ){
		put1sX(Conn,fp,fmt,admin_domain);
	}
	else
	if( streq(param,"digest") ){
		return !admin_basic;
	}
	else
	if( streq(pm,"setconv") || streq(pm,"addconv") ){
		void HTML_clearconvmap(Connection *Conn);
		const char *lang = admin_getv("lang");
		CStr(cnv,16*1024);
		CStr(rurl,16*1024);
		FILE *mp;
		const char *a1;
		const char *a2;
		const char *cv;

		if( streq(pm,"addconv") ){
			a1 = admin_getv(pma1);
			a2 = admin_getv(pma2);
			if( a1 == 0 || *a1 == 0 || a2 == 0 ){
				putMssg(AVStr(rmsg),"@ADM - no data to add\n");
				return 0;
			}
		}else
		if( streq(pm,"setconv") ){
			cv = admin_getv(pma1);
			if( cv == 0 ){
				putMssg(AVStr(rmsg),"@ADM - no data to set\n");
				return 0;
			}
		}

		if( !getconv(Conn,lang,AVStr(rurl),AVStr(cnv),sizeof(cnv)) ){
			putMssg(AVStr(rmsg),"@ADM - cannot get the conv.\n");
			return 0;
		}
		if( !strneq(rurl,"file://localhost/",17) ){
			putMssg(AVStr(rmsg),"@ADM - not writable conv. %s\n",
				rurl);
			return 0;
		}
		mp = fopen(rurl+16,"r+");
		if( mp == 0 ){
			putMssg(AVStr(rmsg),"@ADM - cannot open the conv.\n");
			return 0;
		}
		if( mp ){
			if( streq(pm,"setconv") ){
				fprintf(mp,"%s",cv);
				Ftruncate(mp,0,1);
				putMssg(AVStr(rmsg),"@ADM + the data is set\n");
			}else{
				fseek(mp,0,2);
				fprintf(mp,"< %s\n> %s\n",a1,a2);
				fclose(mp);
				putMssg(AVStr(rmsg),"@ADM + added the data\n");
			}
			HTML_clearCache(rurl);
			DontReadCache = 3; /* to ignore old version */
			HTML_clearconvmap(Conn);
			setconvmap(Conn,Form_argc,Form_argv);
		}
	}
	else
	if( streq(pm,"dumpconv") ){
		const char *lang = admin_getv("lang");
		CStr(cnv,16*1024);
		CStr(rurl,16*1024);
		if( getconv(Conn,lang,AVStr(rurl),AVStr(cnv),sizeof(cnv)) ){
			HTML_ccxput1s(Conn,fp,fmt,cnv);
		}
	}
	else{
		CStr(line,1024);
		sprintf(line,"- unknown or not implemented: %s.%s\n",name,param);
		strsubst(AVStr(line),"<","&lt;");
		strsubst(AVStr(line),">","&gt;");
		if( rmsg )
			strcat(rmsg,line);
		set_conferror("conf-ERROR");
	}
	return 0;
}

#define T_BUTTON	1
#define T_LABEL		2
#define T_MESSAGE	4
#define T_TEXT		8
typedef struct {
	int	 m_type;
	short	 m_slen;
 const char	*m_src;
 const char	*m_dst;
} ConvMap;
static ConvMap *mssgmap;
static CriticalSec mssgmapCSC;

static int putconvmap(PCStr(map),int mac,ConvMap *cm){
	int cx = 0;
	const char *cp;
	const char *np;
	const char *from = 0;
	CStr(xmap,64*1024);
	CStr(ymap,64*1024);

	TO_euc(map,AVStr(xmap),sizeof(xmap));
/*
	encodeEntitiesX(xmap,AVStr(ymap),sizeof(ymap));
*/
	for( cp = xmap; cp && *cp; cp = np ){
		if( np = strpbrk(cp,"\r\n") ){
			while( *np == '\r' || *np == '\n' ){
				truncVStr(np);
				np++;
			}
		}
		if( *cp == '<' ){
			from = cp + 2;
		}
		if( *cp == '>' ){
			if( mac <= cx ){
				break;
			}
			if( from == 0 ){
			}else{
				cm[cx].m_slen = strlen(from);
				cm[cx].m_src = stralloc(from);
				cm[cx].m_dst = stralloc(cp+2);
				cx++;
				from = 0;
			}
		}
	}
	return cx;
}

void HTML_clearconvmap(Connection *Conn){
	int cx;

	if( mssgmap == 0 ){
		return;
	}
	enterCSC(mssgmapCSC);
	for( cx = 0; mssgmap[cx].m_src; cx++ ){
		free((char*)mssgmap[cx].m_src);
		free((char*)mssgmap[cx].m_dst);
	}
	free(mssgmap);
	mssgmap = 0;
	leaveCSC(mssgmapCSC);
}
static int sortmap(const void *a,const void *b){
	if( ((ConvMap*)a)->m_slen < ((ConvMap*)b)->m_slen )
		return 1;
	else	return -1;
}
static void setconvmap(Connection *Conn,int ac,const char *av[]){
	CStr(rurl,1024);
	CStr(map,32*1024);
	const char *lang;
	ConvMap cm[1024];
	int size;
	int cx = 0;
	FILE *fp;

	HTML_clearconvmap(Conn);
	setupCSC("setconvmap",mssgmapCSC,sizeof(mssgmapCSC));
	enterCSC(mssgmapCSC);
	lang = admin_getv("lang");
	if( getconv(Conn,lang,AVStr(rurl),AVStr(map),sizeof(map)) ){
		cx += putconvmap(map,elnumof(cm)-cx,cm+cx);
	}

	cm[cx].m_src = 0;
	size = sizeof(ConvMap)*(cx+1);
	mssgmap = (ConvMap*)malloc(size);
	bcopy((char*)cm,(char*)mssgmap,size); /**/
	qsort(mssgmap,cx,sizeof(mssgmap[0]),sortmap);
	leaveCSC(mssgmapCSC);
/*
int ci;
for(ci=0;ci<cx;ci++)
 fprintf(stderr,"sorted[%d] %s\n",ci,mssgmap[ci].m_src);
*/
}

int HTML_conv(PCStr(ttype),PCStr(srctxt),PVStr(dsttxt)){
	int cx;
	const char *src;
	refQStr(dp,dsttxt);
	int nconv = 0;

	if( dsttxt != srctxt )
		strcpy(dsttxt,srctxt);
	if( mssgmap ){
		for( cx = 0; src = mssgmap[cx].m_src; cx++ ){
			if( dp = strstr(dsttxt,src) ){
				ovstrcpy((char*)dp,dp+mssgmap[cx].m_slen);
				Strins(AVStr(dp),mssgmap[cx].m_dst);
				nconv++;
			}
		}
	}
	return nconv;
}

void HTML_putmssg(Connection *Conn,PVStr(mssg),PCStr(fmt),...){
	CStr(xfmt,1024);
	const char *mp;
	refQStr(dp,mssg);
	const char *src;
	int cx;
	VARGS(16,fmt);

	if( admin_mssg == NULL ){
		return;
	}
	if( strneq(fmt,"@ADM ",5) )
		fmt += 5;
	if( mssgmap ){
		for( cx = 0; src = mssgmap[cx].m_src; cx++ ){
			if( dp = strstr(fmt,src) )
			if( dp == fmt && dp[mssgmap[cx].m_slen] == '\n' )
			{
				sprintf(xfmt,"%s\n",mssgmap[cx].m_dst);
				fmt = xfmt;
			}
		}
	}

	fprintf(admin_mssg,fmt,VA16);
	mp = mssg+strlen(mssg); 
	Xsprintf(TVStr(mssg),fmt,VA16);

	if( mssgmap ){
		for( cx = 0; src = mssgmap[cx].m_src; cx++ ){
			if( dp = strstr(mp,src) ){
				ovstrcpy((char*)dp,dp+mssgmap[cx].m_slen);
				Strins(AVStr(dp),mssgmap[cx].m_dst);
			}
		}
	}
/*
 fprintf(stderr,"-- %4d %4d putmssg: ",ftell(admin_mssg),strlen(mssg));
 fprintf(stderr,fmt,VA16);
 fprintf(stderr,"\n");
*/
}

static
int DHTML_putControlX(Connection *Conn,PCStr(req),FILE *fc,FILE *tc,int vno,PVStr(command),int *stcodep);
int DHTML_putControl(Connection *Conn,PCStr(req),FILE *fc,FILE *tc,int vno,PVStr(command),int *stcodep)
{	int leng;
	CStr(respmssg,16*1024);

	setVStrEnd(respmssg,0);
	setQStr(admin_respmssg,respmssg,sizeof(respmssg));

	HTML_clearconvmap(Conn);
	admin_mssg = TMPFILE("DHTMLmssg");
	leng = DHTML_putControlX(Conn,req,fc,tc,vno,BVStr(command),stcodep);
	fclose(admin_mssg);
	admin_mssg = NULL;

	admin_respmssg = 0;
	ClientFlags &= ~PF_ADMIN_ON;
	return leng;
}

void Form_conv_namevalue(int argc,const char *argv[]);
static int setupControl(Connection *Conn,int vno,PCStr(mt),FILE *fc,FILE *tc);

static
int DHTML_putControlXX(Connection *Conn,PCStr(req),FILE *fc,FILE *tc,int vno,xPVStr(command),int *stcodep,char *fv[]);
static
int DHTML_putControlX(Connection *Conn,PCStr(req),FILE *fc,FILE *tc,int vno,xPVStr(command),int *stcodep)
{
	int rcode;
	int fi;
	char *fv[8];

	fv[0] = 0;
	rcode = DHTML_putControlXX(Conn,req,fc,tc,vno,BVStr(command),stcodep,
		fv);
	for( fi = 0; fv[fi]; fi++ ){
		free(fv[fi]);
	}
	return rcode;
}
static
int DHTML_putControlXX(Connection *Conn,PCStr(req),FILE *fc,FILE *tc,int vno,xPVStr(command),int *stcodep,char *fv[])
{	int leng = 0;
	CStr(xcommand,URLSZ);
	CStr(from,URLSZ);
	AuthInfo ident;
	CStr(mssg,URLSZ);
	CStr(admcom,64);
	const char *dp;
	CStr(who,MaxHostNameLen);
	FILE *tmp;
	int cleng;
	int fx = 0;

	int argc = 0;
	const char *argv[256];
	const char *qryp;
	defQStr(qry);
	const char *act;

	if( strneq(command,"setup/",6) ){
		setVStrElem(command,5,'?');
	}
	if( strneq(command,"logging/",8) ){
		setVStrElem(command,7,'?');
	}
	if( strneq(command,"servers/",8) ){
		setVStrElem(command,7,'?');
	}
	if( strneq(command,"system/",7) ){
		setVStrElem(command,6,'?');
	}
	if( strneq(command,"config/",7) ){
		setVStrElem(command,6,'?');
	}
	if( strneq(command,"showdir/",8) )
		admin_admpath = command+8;
	else	admin_admpath = "";

if( qryp = strchr(command,'?') ){
	setQStr(qry,stralloc(qryp+1),strlen(qryp));
	argc = form2v(AVStr(qry),elnumof(argv),argv);
	fv[fx++] = (char*)argv[0];
	fv[fx] = 0;
	strcpy(xcommand,command);
	if( qryp = strchr(xcommand,'?') )
		truncVStr(qryp);
	command = xcommand;
 }
	if( strneq(req,"POST",4) ){
		argc = HTTP_form2v(Conn,fc,elnumof(argv),argv);
		fv[fx++] = (char*)argv[0];
		fv[fx] = 0;
	}else{
/*
		if( qryp = strchr(command,'?') ){
			setQStr(qry,stralloc(qryp+1),strlen(qryp));
			argc = form2v(AVStr(qry),elnumof(argv),argv);
		}
*/
		if( argc == 0 ){
			argc = 1;
			argv[0] = stralloc("act=Get");
			argv[1] = 0;
			fv[fx++] = (char*)argv[0];
			fv[fx] = 0;
		}
	}

	/* convert xxx.yyy=zzz to xxx=yyy */
	Form_conv_namevalue(argc,argv);

	if( act = getv(argv,"action") ){
		CStr(action,1024);
		strcpy(action,act);
		argc += form2v(AVStr(action),elnumof(argv)-argc,argv+argc);
	}

{
	const char *prevact;
	Form_argcmax = elnumof(argv);
	Form_argc = argc;
	Form_argv = argv;
	if( (act = getv(argv,"act")) == 0 )
		act = "";
	admin_act = act;
	if( (prevact = getv(argv,"prevact")) == 0 )
		prevact = "";
	admin_prevact = prevact;
	admin_com = getv(argv,"com");
	if( admin_com == 0 )
		admin_com = "";
	admin_genc = 0;
	admin_genv[0] = 0;

/*
	if( 1 ){
		int ai;
		for( ai = 0; ai < Form_argc; ai++ ){
			const char *a1 = Form_argv[ai];
			if( strchr(a1,'\033') ){
				int len = strlen(a1);
				TO_euc(a1,ZVStr(a1,len+1),len+1);
				if( strlen(a1) != len ){
 fprintf(stderr,"ARG[%d] %d -> %d %s\n",ai,len,strlen(a1),a1);
				}
			}
		}
	}
*/

	setconvmap(Conn,argc,argv);
	clear_conferror();
 }

	if( strchr(command,'?') )
		Xsscanf(command,"%[^?]",AVStr(admcom));
	else	FStrncpy(admcom,command);
	admin_admcom = admcom;

	if( lHTMLGEN() ){
		int ai;
		fprintf(stderr,"** admin_act=%s admin_com=%s\n",act,admin_com);
		for(ai=0;ai<argc;ai++)
		fprintf(stderr,"** ARGS[%2d/%2d] \"%s\"\n",ai,argc,argv[ai]);
	}

	ClientFlags |= PF_ADMIN_ON;
	if( streq(command,"reauth") ){
		if( HTTP_getAuthorization(Conn,0,&ident,0) == 0
		 || ident.i_user[0] == 0 ){
			CStr(path,128);
			extbase(Conn,AVStr(path),"/-/admin/");
			return putMovedTo(Conn,tc,path);
			/*
			return putMovedTo(Conn,tc,"/-/admin/");
			*/
		}
		leng = putNotAuthorized(Conn,tc,req,ProxyAuth,NULL,
	"You are clearing authorization thus are never authorized.\r\n");
		return leng;
	}

	if( HTTP_getRequestField(Conn,"From",AVStr(from),sizeof(from)) != 0 )
		sv1log("#### putControl -- From: %s\n",from);

	who[0] = 0;
	bzero(&ident,sizeof(AuthInfo));
	identd_auth(Conn,&ident,AVStr(who),command);
	passwd_auth(Conn,&ident,AVStr(who),command);
	if( dp = strchr(who,'{') )
		truncVStr(dp);

	/*
	if( *command == 0 || streq(command,"unauth") ){
	*/
	if( *admcom == 0 || streq(admcom,"unauth") ){
		return putBuiltinPage(Conn,vno,tc,"Admin",
		    "admin/AdminMain.dhtml",NULL,(iFUNCP)DHTML_printConn,NULL);
	}

	if( !(AuthStat & (A_OK_IDENTAUTHOR | A_OK_PASSAUTHOR)) ){
		if( !streq(command,"authenticate") ){
			CStr(path,128);
			extbase(Conn,AVStr(path),"/-/admin/unauth");
			return putMovedTo(Conn,tc,path);
			/*
			return putMovedTo(Conn,tc,"/-/admin/unauth");
			*/
		}
		if( AuthStat & (A_WITH_IDENTD|A_OK_PASSAUTHEN) ){
			sprintf(mssg,"Authenticated as <I>&lt;%s@%s&gt;</I>.\r\n",
				ident.i_user,ident.i_Host);
			Xsprintf(TVStr(mssg),
				"You are not authorized to do `");
			encodeEntitiesX(command,TVStr(mssg),
					sizeof(mssg)-strlen(mssg));
			strcat(mssg,"'.<BR>\r\n");
		}else{
			sprintf(mssg,"Not-Authenticated.\r\n");
		}
		leng += putNotAuthorized(Conn,tc,req,ProxyAuth,NULL,mssg);
		*stcodep = 401;
		HTTP_delayReject(Conn,req,"",1);
		put_authlog(Conn,"admin",NULL,&ident,-1,"Error");
		return leng;
	}

	if( (leng = forbidden(Conn,command,"",tc))
	 || (leng = forbidden(Conn,admin_com,"",tc))
	){
		HTTP_delayReject(Conn,req,"",1);
		*stcodep = 403;
		return leng;
	}

	Conn->no_dstcheck = 1;
	if( streq(command,"authenticate") ){
		put_authlog(Conn,"admin",NULL,&ident,0,"OK");
	}

	if( streq(command,"account") ){
		leng = accountControl(Conn,vno,req,fc,tc,who);
		return leng;
	}
	if( streq(command,"mount") ){
		leng = mountControl(Conn,vno,req,fc,tc,who);
		return leng;
	}
	if( streq(admcom,"unmount") ){
		unMount(Conn);
		setSoftBreak(Conn,"");
		leng = putMount(Conn,vno,tc,"");
		return leng;
	}
	if( streq(admcom,"logging") ){
		leng = loggingControl(Conn,vno,req,fc,tc);
		return leng;
	}
	if( streq(admcom,"setup") ){
		leng = setupControl(Conn,vno,req,fc,tc);
		return leng;
	}
	if( streq(admcom,"servers") ){
		return putBuiltinPage(Conn,vno,tc,"Admin",
			"admin/servers.dhtml",NULL,(iFUNCP)DHTML_printConn,NULL);
	}
	if( streq(admcom,"ca") ){
		if( streq(admin_com,"download") ){
			int hleng;
			int cleng;
			FILE *tmp;
			tmp = TMPFILE("ca");
			OpenSSL(AVStr(mssg),Conn,tmp,admin_com);
			fflush(tmp);
			fseek(tmp,0,0);
			cleng = file_size(fileno(tmp));
			hleng=HTTP_putHeader(Conn,tc,vno,"text/plain",cleng,-1);
			copyfile1(tmp,tc);
			fclose(tmp);
			return hleng+cleng;
		}
		return putBuiltinPage(Conn,vno,tc,"Admin",
		    "admin/CertAdmin.dhtml",NULL,(iFUNCP)DHTML_printConn,NULL);
	}
	if( streq(admcom,"system") ){
		return putBuiltinPage(Conn,vno,tc,"Admin",
		    "admin/SystemCfg.dhtml",NULL,(iFUNCP)DHTML_printConn,NULL);
	}
	if( strneq(command,"showdir/",8) ){
		return showdir(Conn,command+8,fc,tc,vno);
	}

	if( streq(command,"authenticate") ){
		CStr(path,128);
		extbase(Conn,AVStr(path),"/-/admin/");
		return putMovedTo(Conn,tc,path);
		/*
		return putMovedTo(Conn,tc,"/-/admin/");
		*/
	}else
	if( streq(command,"stop") ){
		tmp = TMPFILE("Admin.stop");
		stop_server(tmp);
		return putText(Conn,vno,tc,tmp);
	}else
	if( streq(command,"volrestart") ){
		tmp = TMPFILE("Admin.volrestart");
		volrestart(Conn,tmp);
		cleng = putText(Conn,vno,tc,tmp);
		return cleng;
	}else
	if( streq(command,"restart") ){
		tmp = TMPFILE("Admin.restart");
		restart_server(tmp);
		return putText(Conn,vno,tc,tmp);
	}else
	if( streq(command,"getlog") ){
		tmp = TMPFILE("Admin.getlog");
		get_serverinitlog(tmp);
		return putText(Conn,vno,tc,tmp);
	}else
	if( streq(command,"showconf") ){
		tmp = TMPFILE("Admin.showconf");
		DELEGATE_dumpEnv(tmp,1,0);
		return putText(Conn,vno,tc,tmp);
	}
	else
	if( strneq(command,"config",6) ){
		return configControl(Conn,command+6,vno,fc,tc,argc,argv);
	}
	else
	if( strneq(command,"stats",5) ){
		return statsAdmin(Conn,req,command+5,vno,fc,tc);
	}
	else{
		CStr(line,1024);
		sprintf(line,"- not implemented: %s\n",command);
		strsubst(AVStr(line),"<","&lt;");
		strsubst(AVStr(line),">","&gt;");
		if( admin_respmssg )
			strcat(admin_respmssg,line);
		set_conferror("conf-ERROR");
	}
/*
 if( streq(command,"replace") ){
leng += HTTP_putHeader(Conn,tc,vno,"text/html",0,-1);
FPRINTF(tc,"<TITLE> Replaced </TITLE>\n");
FPRINTF(tc,"Authorization: %s\n",dauth);
return leng;
 }
*/

	sprintf(mssg,"Not yet supported: %s (%s)\n",command,DELEGATE_ver());
	cleng = strlen(mssg);
	leng = HTTP_putHeader(Conn,tc,vno,"text/html",cleng,-1);
	if( RespWithBody ) fputs(mssg,tc);
	return leng;
}

int DHTML_putDeleGatePage(Connection *Conn,PCStr(req),FILE *tc,int vno)
{
	return putBuiltinPage(Conn,vno,tc,"DGinfo","welcome.dhtml",
		NULL,(iFUNCP)DHTML_printConn,NULL);
}

static int HTTP_toMyself(Connection *Conn,PCStr(me),PCStr(req))
{	const char *url;
	HttpRequest reqx;
	CStr(Host,MaxHostNameLen);
	CStr(svhost,MaxHostNameLen);
	CStr(myhost,MaxHostNameLen);
	int svport,myport;

	decomp_http_request(req,&reqx);
	url = reqx.hq_url;

	getFieldValue2(req,"Host",AVStr(Host),sizeof(Host));
	svport = scan_hostport("http",Host,AVStr(svhost));
	myport = scan_hostport("http",me,AVStr(myhost));

	if( strncmp(url,"/-/",3) == 0 ){
		if( Host[0] == 0
		 || hostcmp(svhost,myhost)==0 && svport == myport )
			return 1;
	}
	return 0;
}

int isFTPxHTTP(PCStr(proto));
int DDI_peekCbuf(Connection *Conn,PVStr(buf),int siz);
int daemonControl(Connection *Conn,int fromC,FILE *tc,int timeout)
{	int rcc;
	CStr(req,1024);
	CStr(me,1024);
	CStr(myurl,1024);
	int httpReq;
	int isAdmin = 0;

	if( (ClientFlags|ServerFlags) & PF_MITM_ON ){
		return 0;
	}

	if( streq(iSERVER_PROTO,"tunnel1") ){
		Conn->from_myself = 1;
		return 0;
	}

	if( 0 <= Conn->clif._withAdmin ){
		if( Conn->clif._isAdmin < 0 ){
			return 0;
		}
		isAdmin = 1;
		if( ClientFlags & PF_STLS_ON ){
			double Start = Time();
			int nready;
			nready = PollIn(fromC,1000);
			sv1log("## daemonControl with SSL, ready=%d %.3f\n",
				nready,Time()-Start);
		}
	}

	/*
	 * if this is the "delegate" server, then any request including
	 * "GET /-/ HTTP" for target "ftp" server should be handled in
	 * the target server (which might be DeleGate server).
	 */

	if( !isAdmin )
	if( iSERVER_PROTO[0] == 0
	 || streq(iSERVER_PROTO,"delegate")
	 || streq(iSERVER_PROTO,"http")
	 || streq(iSERVER_PROTO,"httpft")
	 || streq(iSERVER_PROTO,"htmux")
	 || streq(iSERVER_PROTO,"https")
	 || streq(iSERVER_PROTO,"tcprelay")
	 || streq(iSERVER_PROTO,"exec")
	 || streq(iSERVER_PROTO,"pam")
	 || streq(iSERVER_PROTO,"httpam")
	 || isFTPxHTTP(iSERVER_PROTO)
	)
		return 0;

	if( Port_Proto ){
		if( Port_Proto == serviceport("http")
		 || Port_Proto == serviceport("https")
		){
			return 0;
		}
	}

	httpReq = 0;
	if( 0 < DDI_peekCbuf(Conn,AVStr(req),sizeof(req)) ){
		/* maybe the request line prefetched by a Generailst */
		if( HTTP_isMethod(req) ){
			httpReq = 1;
		}
	}else
	if( 0 < PollIn(fromC,timeout) ){
		rcc = recvPeekTIMEOUT(fromC,AVStr(req),sizeof(req)-1);
		if( 8 < rcc ){
			setVStrEnd(req,rcc);
			if( HTTP_isMethod(req) ){
				httpReq = 1;
			}
		}
	}
	if( httpReq == 0 )
		return 0;

	if( !source_permitted(Conn) ){
		sv1log("## daemonControl(%s): Forbidden\n",DFLT_PROTO);
		fprintf(tc,"HTTP/1.0 403 Forbidden\r\n");
		fprintf(tc,"Content-Type: text/plain\r\n");
		fprintf(tc,"\r\n");
		fprintf(tc,"*** No access right ***\r\n");
		return 1;
	}

	ClientIF_HP(Conn,AVStr(me));
	if( isAdmin ){
		/* it is to myself even if "Host:unknown-host" */
	}else
	if( !HTTP_toMyself(Conn,me,req) ){
		CStr(com,16);
		wordScan(req,com);
		if( streq(iSERVER_PROTO,"nntp") ){
			if( strcaseeq(com,"POST") || strcaseeq(com,"HEAD") )
				return 0;
		}
		sv1log("## daemonControl(%s): non-control URL\n",DFLT_PROTO);
		sv1log("## REQ[%s] %s\n",DFLT_PROTO,req);
		fprintf(tc,"HTTP/1.0 500 Protocol Mismatch\r\n");
		fprintf(tc,"Content-Type: text/html\r\n");
		fprintf(tc,"\r\n");
		fprintf(tc,"<PRE>\r\n");
		fprintf(tc,"*** Protocol Mismatch ***\r\n");
		fprintf(tc,"You are accessing this DeleGate server <B>%s</B>\r\n",me);
		fprintf(tc,"from a client software of <B>HTTP</B> protocol.\r\n");
		fprintf(tc,"But this DeleGate is for clients of ");
		fprintf(tc,"<B>%s</B> protocol.\r\n",iSERVER_PROTO);
		fprintf(tc,"If you intend to contol this DeleGate server, ");
		fprintf(tc,"see <A HREF=http://%s/-/>here</A>.\r\n",me);
		fprintf(tc,"</PRE>\r\n");
		return 1;
	}

	sv1log("## daemonControl(%s)\n",DFLT_PROTO);

	ClientFlags |= PF_ADMIN_SW;
	if( ClientFlags & PF_STLS_ON )
		strcpy(CLNT_PROTO,"https");
	else	strcpy(CLNT_PROTO,"http");
	sprintf(myurl,"%s://%s",CLNT_PROTO,me);
	set_BASEURL(Conn,myurl);
	strcpy(DFLT_PROTO,CLNT_PROTO);
	Conn->no_dstcheck_proto = serviceport(CLNT_PROTO);
	if( isAdmin ){
		Conn->no_dstcheck = 1;
	}
	return 0;
#if 0
	sprintf(myurl,"http://%s",me);
	set_BASEURL(Conn,myurl);
	strcpy(DFLT_PROTO,"http");
	strcpy(CLNT_PROTO,"http"); /* used in forcedIF_HP() <- HTTP_baseURL() */
	Conn->no_dstcheck_proto = serviceport("http");
	return 0;
#endif
}

extern int THEXIT;
void setup1(Connection *Conn){
	const char *v1;
	int vi = 0;

	if( v1 = admin_getv("ioconf-sock-sndbuf") ){
		vi = atoi(v1);
		if( vi == 0 || 64 <= vi && vi <= 64*1024 ){
			Verbose("#### SOCK_SNDBUF_MAX=%d\n",vi);
			SOCK_SNDBUF_MAX = vi;
		}
	}
	if( v1 = admin_getv("ioconf-sock-sndmutex") ){
		if( streq(v1,"on") )
			SOCK_SNDMUTEX = 1;
		else	SOCK_SNDMUTEX = 0;
	}
	if( v1 = admin_getv("ioconf-sock-sndnodelay") ){
		if( streq(v1,"on") )
			SOCK_SNDNODELAY = 1;
		else	SOCK_SNDNODELAY = 0;
	}
	if( v1 = admin_getv("ioconf-sock-sndwait") ){
		vi = atoi(v1);
		if( 0 <= vi && vi < 1000 )
			SOCK_SNDWAIT = vi;
	}
}
void popupConsole();
static int setupControl(Connection *Conn,int vno,PCStr(mt),FILE *fc,FILE *tc){	int leng;
	const char *v1;
	const char *lev;
	const char *com;
	int flags = 0;
	const char *dhtml = "admin/setup.dhtml";

	com = admin_getv("com");
	if( com && streq(com,"apply") ){
		setup1(Conn);
	}
	if( com && streq(com,"terminate") ){
		/* MovedTo */
		dhtml = "admin/terminate.dhtml";
		THEXIT = 1;
	}
	if( com && streq(com,"show-console") ){
		popupConsole();
	}
	leng = putBuiltinPageX(Conn,vno,tc,"Setup",dhtml,
		NULL,(iFUNCP)DHTML_printConn,"",flags);
	if( THEXIT ){
		fflush(tc);
		Finish(0);
	}
	fflush(tc);
	return leng;
}
