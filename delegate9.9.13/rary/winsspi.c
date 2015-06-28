const char *SIGN_winssl_c="{FILESIGN=winsspi.c:20141022165616+0900:e77647baa52309c8:Author@DeleGate.ORG:l1Ib1ZDPBkjwMinYB8SNdNSzUluP+mzYFmkOgKJ0Qe//G6t/7iWjCKkhPVkBINdb0nbFKluLuKfIu6xoZXD84kWoRk2zUCuFxPxM7Fx9fdLms6TvDW2Rq/5moCJJu1qbkcz43+UOAfd5XFqP5dAlkBNrbwPwgjXOGzW1wvorF9A=}";

/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2008 National Institute of Advanced Industrial Science and Technology (AIST)
AIST-Product-ID: 2000-ETL-198715-01, H14PRO-049, H15PRO-165, H18PRO-443

Permission to use this material for noncommercial and/or evaluation
purpose, copy this material for your own use,
without fee, is hereby granted
provided that the above copyright notice and this permission notice
appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
//////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	winsspi.c (Security Support Providers Interface on Windows)
Author:		Yutaka Sato <y.sato@delegate.org>
Description:
	- SSL gateway
	- {NTLM/Negotiate}/Baisc authentication gateway
          [MS-NTHT] http://msdn.microsoft.com/en-us/library/cc237488.aspx
	  [RFC4559] ftp://ftp.rfc-editor.org/in-notes/rfc4559.txt
History:
	080624	created
//////////////////////////////////////////////////////////////////////#*/
/* '"DiGEST-OFF"' */

#include "ystring.h"
#include "fpoll.h"
#include "log.h"
#if !defined(_MSC_VER) || _MSC_VER < 1400 || defined(UNDER_CE)
int NTHT_connect(int toproxy,int tosv,int fromsv,PCStr(reql),PCStr(head),PCStr(user),PCStr(pass),void *utoken,PCStr(chal)){
	return -1;
}
int NTHT_accept(int asproxy,int tocl,int fromcl,PCStr(reql),PCStr(head),PVStr(user),void **utoken){
	return -1;
}
#endif

/* FrOM-HERE
##########################################################################
    CAUTION: re-distributing the copy of this file is not permitted.
##########################################################################
 */
#if defined(_MSC_VER) && _MSC_VER < 1400
int testLogin(PCStr(user),PCStr(pass)){
	return -1;
}
#endif
#if defined(_MSC_VER) && 1400 <= _MSC_VER

#ifdef UNDER_CE
#define UNICODE
#endif
#include <windows.h>
#include <winbase.h>
#define SECURITY_WIN32
#include <security.h>

#ifdef UNDER_CE
#define SSL2SP_NAME  L"Microsoft TLS 1.0"
#define NTLM_NAME    L"NTLM"
#define AcquireCredentialsHandle AcquireCredentialsHandleW
#else
#include <schannel.h>
#define NTLM_NAME "NTLM"
#define NEGO_NAME "Negotiate"
#endif

#define SSL2 SSL2SP_NAME
#define NTLM NTLM_NAME
#define NEGO NEGO_NAME

#pragma comment (lib, "secur32.lib")

#include <ctype.h>

int wstrtostrX(int sz,char *dst,WCHAR *src,int esc);
int strtowstrX(int sz,WCHAR *dst,PCStr(src),int esc);
#define wstrtostr(dst,src,e) wstrtostrX(sizeof(dst)/sizeof(dst[0]),dst,src,e)
#define strtowstr(dst,src,e) strtowstrX(sizeof(dst)/sizeof(dst[0]),dst,src,e)

#if defined(UNDER_CE) /*{*/
int testLogin(PCStr(user),PCStr(pass)){
	return -1;
}
#else /*}{*/
int setSeTcbPrivilege(HANDLE token,int on);
static const char *aerr(int err){
	static IStr(serr,32);
	switch( err ){
	 case 0: return "OK";
	 case ERROR_PRIVILEGE_NOT_HELD: return
	  "A required privilege is not held by the client";
	 case ERROR_LOGON_FAILURE: return
	  "Logon failure: unknown user name or bad password";
	 case ERROR_LOGON_TYPE_NOT_GRANTED: return
	  "Logon failure: the user has not been granted the requested logon type at this computer";
	 case ERROR_NO_LOGON_SERVERS: return
	  "There are currently no logon servers available to service the logon request";
	 case ERROR_TRUSTED_RELATIONSHIP_FAILURE: return
	  "The trust relationship between this workstation and the primary domain failed";
	}
	sprintf(serr,"%dL",err);
	return serr;
}
int testLogin(PCStr(user),PCStr(pass)){
	int ok;
	HANDLE ctoken;
	int err;
	const char *auser = user;
	const char *domain = ".";
	IStr(userb,128);
	refQStr(dp,userb);
	HANDLE ptoken = 0;
	HANDLE ph;

	if( strchr(user,'\\') ){
		strcpy(userb,user);
		if( dp = strchr(userb,'\\') ){
			truncVStr(dp);
			user = dp+1;
			domain = userb;
		}
	}else
	if( strchr(user,'@') ){
		strcpy(userb,user);
		if( dp = strchr(userb,'@') ){
			truncVStr(dp);
			user = userb;
			domain = dp+1;
		}
	}

	SetLastError(0);
	if( domain[0] && !streq(domain,".") )
	if( ph = OpenProcess(PROCESS_ALL_ACCESS,0,getpid()) ){
		//if( OpenProcessToken(ph,TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&ptoken) ){
		if( OpenProcessToken(ph,TOKEN_ALL_ACCESS,&ptoken) ){
			if( setSeTcbPrivilege(ptoken,1) ){
			}else{
			}
		}else{
		}
	}
	ok = LogonUser(user,domain,pass,
		LOGON32_LOGON_INTERACTIVE, //LOGON32_LOGON_NETWORK,
		LOGON32_PROVIDER_DEFAULT,
		&ctoken);
	err = GetLastError();
	syslog_ERROR(">>>>LogonUser(%s@%s) ok=%d err=%d (%s)\n",
		user,domain,ok,err,aerr(err));
	if( ptoken ){
		setSeTcbPrivilege(ptoken,0);
		CloseHandle(ph);
		CloseHandle(ptoken);
	}
	if( ok ){
		CloseHandle(ctoken);
		return 0;
	}
	return -1;
}
#endif /*}*/

int SocketOf(int fd);
char *getFieldValue2(PCStr(head),PCStr(field),PVStr(value),int size);
static void dump(PCStr(buf),int siz){
	int bi;
	int ch;

	if( lSECRET() == 0 )
		return;

	fprintf(stderr,"============== (%d)\n",siz);
	for( bi = 0; bi < siz; bi++ ){
		if( 0 < bi && bi % 32 == 0 ){
			fprintf(stderr,"\n");
		}
		ch = 0xFF & buf[bi];
		if( ch == 0 ){
			fprintf(stderr,"  ",ch);
		}else
		if( isprint(ch) ){
			fprintf(stderr," %c",ch);
		}else{
			fprintf(stderr,"%02X",ch);
		}
	}
	fprintf(stderr,"\n");
	fprintf(stderr,"==============\n");
}

#if !defined(UNDER_CE) /*{*/
SECURITY_STATUS DLL_QuerySecurityContextToken(CtxtHandle *ctx,HANDLE token);
#define QuerySecurityContextToken DLL_QuerySecurityContextToken

static void dumpcred(CredHandle *cred){
	int ss;
	SecPkgCredentials_Names cn;
	bzero(&cn,sizeof(cn));
	ss = QueryCredentialsAttributes(cred,SECPKG_CRED_ATTR_NAMES,&cn);
	if( ss != SEC_E_OK ){
		syslog_ERROR("####cred %X ss=%X\n",cred,ss);
		return;
	}
	syslog_ERROR("####cred name=%s\n",cn.sUserName?cn.sUserName:"");
}
static void dumptoken(HANDLE ctoken,PVStr(user)){
	int tub[256];
	TOKEN_USER *tup = (TOKEN_USER*)tub;
	DWORD rlen;
	SID_NAME_USE snu;	
	int ok;

	rlen = 0;
	ok = GetTokenInformation(ctoken,TokenUser,tup,sizeof(tub),&rlen);
	if( ok == 0 ){
		syslog_ERROR("----NTLM #### TokenUser:%d err=%d %d\n",ok,
			GetLastError(),rlen);
		return;
	}
	IStr(name,128);
	DWORD nlen = sizeof(name);
	IStr(ndom,128);
	DWORD rndomsz = sizeof(ndom);
	LookupAccountSid(0,tup->User.Sid,name,&nlen,ndom,&rndomsz,&snu);
	syslog_ERROR("----NTLM #### TokenUser '%s@%s'\n",name,ndom);
	sprintf(user,"%s@%s",name,ndom);
}

#define AFname(proxy) proxy?"Proxy-Authorization":"Authorization"
#define CFname(proxy) proxy?"Proxy-Authenticate" :"WWW-Authenticate"
#define CCode(proxy)  proxy?407:401

int NTHT_accept(int asproxy,int tocl,int fromcl,PCStr(reql),PCStr(head),PVStr(user),void **utoken){
	SECURITY_STATUS ss;
	CtxtHandle ctxt;
	CredHandle cred;
	CtxtHandle *ctxtp = 0;
	TimeStamp ts;
	ULONG attr = ISC_REQ_STREAM;
	ULONG rattr = 0;
	int dir = SECPKG_CRED_BOTH;
	int ri;
	SecBufferDesc *sbdip = 0;
	SecBufferDesc sbdo;
	SecBufferDesc sbdi;
	SecBuffer sbo[2];
	SecBuffer sbi;
	IStr(resp,8*1024);
	refQStr(rp,resp);
	IStr(req,8*1024);
	IStr(auth,1024);
	IStr(atyp,1024);
	IStr(aval,1024);
	const char *ap;
	IStr(aauth,1024);
	IStr(bauth,1024);
	int blen;
	int rcc;
	int wcc;
	int tcl = SocketOf(tocl);
	int fcl = SocketOf(fromcl);
	int rcode = -1;

	sprintf(req,"%s%s",reql,head);
	ss = AcquireCredentialsHandle(NULL,NEGO,dir,0,0,0,0,&cred,&ts);
	syslog_ERROR("----NTHT_accept(%d,%d,%d) ss=%X\n",asproxy,tocl,fromcl,ss);
	if( ss != SEC_E_OK ){
		return -1;
	}
	dumpcred(&cred);

	for( ri = 0; ri < 4; ri++ ){
		sbdip = 0;
		if( getFieldValue2(req,AFname(asproxy),AVStr(auth),sizeof(auth)) ){
			ap = wordScan(auth,atyp);
			lineScan(ap,aval);
			if( strcaseeq(atyp,"Negotiate") ){
				blen = str_from64(aval,strlen(aval),
					AVStr(bauth),sizeof(bauth));
				sbi.cbBuffer = blen;
				sbi.pvBuffer = bauth;
				sbi.BufferType = SECBUFFER_TOKEN;
				sbdip = &sbdi;
				dump(bauth,blen);
			}
		}
		if( ri == 0 && sbdip == 0 ){
			syslog_ERROR("====NTLM Start\n");
			clearVStr(aauth);
			goto SENDRESP;
		}
		if( lSECRET() ){
			syslog_ERROR("====NTLM client REQ isz=%d\n%s",
				sbi.cbBuffer,req);
		}
		sbdi.cBuffers = 1;
		sbdi.pBuffers = &sbi;
		sbdi.ulVersion = SECBUFFER_VERSION;

		sbo[0].cbBuffer = 0;
		sbo[0].pvBuffer = 0;
		sbo[0].BufferType = SECBUFFER_TOKEN;
		sbdo.cBuffers = 1;
		sbdo.pBuffers = sbo;
		sbdo.ulVersion = SECBUFFER_VERSION;

		ss = AcceptSecurityContext(&cred,ctxtp,sbdip,
			attr|ISC_REQ_ALLOCATE_MEMORY,
			SECURITY_NETWORK_DREP,
			&ctxt,&sbdo,&rattr,0);
		dumpcred(&cred);
		SECURITY_STATUS tss;
		HANDLE ctoken;
		tss = QuerySecurityContextToken(&ctxt,&ctoken);
		syslog_ERROR("====NTLM QSC ss=%X tss=%X out=%d\n",
			ss,tss,sbo[0].cbBuffer);
		if( tss == SEC_E_OK ){
			dumptoken(ctoken,BVStr(user));
		}

		if( ss == SEC_E_LOGON_DENIED ){
			syslog_ERROR("====NTLM Login Denied\n");
			sprintf(resp,"HTTP/1.1 %d Auth-Err ####\r\n\r\n",
				CCode(asproxy));
			send(tcl,resp,strlen(resp),0);
			break;
		}
		if( ss != SEC_I_CONTINUE_NEEDED ){
			if( tss != SEC_E_OK ){
			syslog_ERROR("====NTLM Authentication Failed\n");
				break;
			}
			syslog_ERROR("====NTLM Authentication Succeeded\n");
			if( strneq(reql,"CONNECT ",8) ){
				/* 9.9.1 code 100 for CONNECT seems bad */
			}else{
			static int ni;
			sprintf(resp,"HTTP/1.1 100 Auth-OK ####(%d.%d)[%d]\r\n",
				ni++,ri,getpid());
			strcat(resp,"\r\n");
			send(tcl,resp,strlen(resp),0);
			}
			*utoken = ctoken;
			if( 1 ){
				int ok;
				if( ok = ImpersonateLoggedOnUser(ctoken) ){
					dumptoken(ctoken,BVStr(user));
					RevertSecurityContext(&ctxt);
				}
				syslog_ERROR("----NTLM Impersonate=%d [%s]\n",
					ok,user);
			}
			rcode = 0;
			break;
		}

		clearVStr(aauth);
		if( sbo[0].pvBuffer ){
			dump((char*)sbo[0].pvBuffer,sbo[0].cbBuffer);
			str_to64((char*)sbo[0].pvBuffer,sbo[0].cbBuffer,
				AVStr(aauth),sizeof(aauth),1);
			strsubst(AVStr(aauth),"\r","");
			strsubst(AVStr(aauth),"\n","");
			FreeContextBuffer(sbo[0].pvBuffer);
		}

	SENDRESP:
		rp = resp;
		Rsprintf(rp,"HTTP/1.1 %d\r\n",CCode(asproxy));
		Rsprintf(rp,"%s: %s%s%s\r\n",CFname(asproxy),
			"Negotiate",aauth[0]?" ":"",aauth);
		Rsprintf(rp,"Content-Length: 0\r\n");
		Rsprintf(rp,"\r\n");

		wcc = send(tcl,resp,strlen(resp),0);
		if( lSECRET() ){
			syslog_ERROR("====NTLM MY RESP\n%s",resp);
		}
		if( aauth[0] == 0 ){
			int ShutdownSocket(int sock);
			ShutdownSocket(tocl);
			break;
		}
		rcc = recv(fcl,req,sizeof(req)-1,0);
		if( rcc <= 0 ){
			break;
		}
		setVStrEnd(req,rcc);
		syslog_ERROR("====NTLM client REQ rcc=%d\n",rcc);
		ctxtp = &ctxt;
	}
	// FreeSecurityHandle
	// FreeSecurityContext
	return rcode;
}
static int skipHTTP100(int fsv,int fromsv,PCStr(resp0)){
	IStr(resp,1024);
	const char *eh;
	int rem = 0;
	int rcc;

	if( eh = strstr(resp0,"\r\n\r\n") ){
		if( strstr(eh+4,"\r\n\r\n") == 0 ){
			rem = 1;
		}
	}else{
		rem = 1;
	}
	if( rem ){
		syslog_ERROR("----NTLM SKIP the resp to HEAD\n%s",resp);
		if( PollIn(fromsv,5*1000) == 0 ){
			syslog_ERROR("----NTLM recv timeout\n");
			return -1;
		}else{
			rcc = recv(fsv,resp,sizeof(resp)-1,0);
			setVStrEnd(resp,rcc);
			if( lSECRET() )
			syslog_ERROR("----NTLM recv\n%s\n",resp);
		}
	}
	return 0;
}

int NTLM_LOGINTEST = 1;
int NTHT_connect(int toproxy,int tosv,int fromsv,PCStr(reql),PCStr(head),PCStr(user),PCStr(pass),void *utoken,PCStr(chal)){
	SECURITY_STATUS ss;
	CredHandle tcred; /* NTLM */
	CtxtHandle ctxt;
	CredHandle ncred; /* Negotiate */
	CredHandle *ccred = &ncred;
	CtxtHandle *ctxtp = 0;
	TimeStamp ts;
	ULONG attr;
	ULONG rattr = 0;
	int dir;
	int ri;
	char data[8*1024];
	int rcc;
	int wcc;
	SecBufferDesc *sbdip = 0;
	SecBufferDesc sbdo;
	SecBufferDesc sbdi;
	SecBuffer sbo[2];
	SecBuffer sbi;
	int tsv = SocketOf(tosv);
	int fsv = SocketOf(fromsv);
	IStr(req,4*1024);
	IStr(resp,8*1024);
	refQStr(rp,req);
	IStr(auth,4*1024);
	IStr(atyp,1024);
	IStr(aval,4*1024);
	const char *ap;
	IStr(bauth,4*1024);
	int blen;
	IStr(line,4*1024);
	SEC_CHAR *suser;
	int ok;
	IStr(rdom,128);
	IStr(method,128);
	IStr(url,1024);
	IStr(vhost,256);
	IStr(userb,128);
	IStr(suserb,128);
	IStr(principal,128);
	HANDLE ctoken = 0;
	int hcode = -1;

	Xsscanf(reql,"%s %s",AVStr(method),AVStr(url));
	getFieldValue2(head,"Host",AVStr(vhost),sizeof(vhost));
	syslog_ERROR("----NTLM REQ[%s][%s][%s][%s]\n",method,user,vhost,url);
	if( chal[0] ){
		syslog_ERROR("----NTLM prev. challenge: %s\n",chal);
	}

	bzero(&ctxt,sizeof(ctxt));
	dir = SECPKG_CRED_BOTH;
	//dir = SECPKG_CRED_OUTBOUND;

	SetLastError(0);
	rdom[0] = 0;

	if( utoken != 0 ){
		ctoken = utoken;
		ok = ImpersonateLoggedOnUser(ctoken);
		syslog_ERROR("----NTLM forwarded Impersonate=%d [%X]\n",ok,
			ctoken);
		IStr(ruser,128);
		dumptoken(ctoken,AVStr(ruser));
		sprintf(principal,"%s",ruser);
	//ss = AcquireCredentialsHandle(principal,NEGO,dir,0,0,0,0,&ncred,&ts);
		ss = AcquireCredentialsHandle(0,NEGO,dir,0,0,0,0,&ncred,&ts);
		if( ss == 0 ) dumpcred(&ncred);
		goto AUTHOK;
	}

	const char *host = "";
	int sidb[128];
	DWORD sidsz = sizeof(sidb);
	DWORD rdomsz = sizeof(rdom);
	SID_NAME_USE snu;	

	ok = LookupAccountName(host,user,(PSID)sidb,&sidsz,rdom,&rdomsz,&snu);
	syslog_ERROR("----NTLM Lookup[%s]@[%s]%d e=%d %d\n",user,rdom,ok,
		ok?0:GetLastError(),sidsz);
	if( !ok ){
		if( strchr(user,'@') ){
			Xsscanf(user,"%[^@]@%s",AVStr(userb),AVStr(rdom));
		}else
		if( strchr(user,'\\') ){
			Xsscanf(user,"%[^\\]\\%s",AVStr(rdom),AVStr(userb));
		}
		if( rdom[0] ){
			ok = LookupAccountName(host,userb,(PSID)sidb,&sidsz,rdom,&rdomsz,&snu);
			syslog_ERROR("----NTLM Lookup[%s]@[%s]%d e=%d %d\n",userb,rdom,ok,
				ok?0:GetLastError(),sidsz);
		}
	}
	if( !ok ){
		//return -1;
	}
	if( rdom[0] == 0 ){
		syslog_ERROR("----NTLM user[%s] Unknown\n",user);
		//return -1;
	}

	/*
	if( strchr(user,'@') ){
		Xsscanf(user,"%[^@]@%s",AVStr(userb),AVStr(rdom));
		user = userb;
	}else{
		Xsscanf(vhost,"%[^:]",AVStr(rdom));
	}
	*/

	////////////////////////////////////////////////////////////
	ok = LogonUser(user,rdom,pass,
		LOGON32_LOGON_NETWORK,
		//LOGON32_LOGON_NETWORK_CLEARTEXT,
		LOGON32_PROVIDER_DEFAULT,
		//LOGON32_PROVIDER_WINNT50,
		&ctoken);
	syslog_ERROR("----NTLM Logon[%s]@[%s]%d e=%d\n",user,rdom,ok,
		ok?0:GetLastError());
	if( !ok ){
		if( strchr(user,'@') ){
			Xsscanf(user,"%[^@]@%s",AVStr(userb),AVStr(rdom));
		}else
		if( strchr(user,'\\') ){
			Xsscanf(user,"%[^\\]\\%s",AVStr(rdom),AVStr(userb));
		}
		if( rdom[0] ){
			ok = LogonUser(userb,rdom,pass,
				LOGON32_LOGON_NETWORK,
				//LOGON32_LOGON_NETWORK_CLEARTEXT,
				LOGON32_PROVIDER_DEFAULT,
				&ctoken);
			syslog_ERROR("----NTLM Logon[%s]@[%s]%d e=%d\n",
				userb,rdom,ok,ok?0:GetLastError());
			if( ok ){
				user = userb;
			}
		}
	}
	if( ok ){
		ok = ImpersonateLoggedOnUser(ctoken);
		syslog_ERROR("----NTLM Impersonate=%d\n",ok);
		//CloseHandle(ctoken);
		sprintf(principal,"%s@%s",user,rdom);
		IStr(ruser,128);
		dumptoken(ctoken,AVStr(ruser));
	}else{
		syslog_ERROR("----NTLM Logon[%s] ## DENIED ##\n",user);
		if( NTLM_LOGINTEST ){
			return -1;
		}
	}

 {
	SEC_WINNT_AUTH_IDENTITY id;
	WCHAR wuser[128];
	WCHAR wrdom[32];
	WCHAR wpass[128];

/*
	sprintf(suserb,"%s@%s",user,rdom);
	sprintf(suserb,"%s",user);

	strcpy(rdom,"WorkGroup");
	sprintf(suserb,"%s\\%s","DGDELL-LTXT",user);

	strcpy(rdom,"DGDELL-LTXT");
	sprintf(suserb,"%s",user);
*/

	strcpy(rdom,".");
strcpy(rdom,"DGDELL-LTXT");
	sprintf(suserb,"%s",user);
	suser = (SEC_CHAR*)suserb;

/*
strcpy(rdom,"NT AUTHORITY");
sprintf(suserb,"%s","SYSTEM");
*/

	syslog_ERROR("----NTLM %s@%s\n",user,rdom);
	strtowstr(wuser,suser,0);
	strtowstr(wrdom,rdom,0);
	strtowstr(wpass,pass,0);

	id.User = (unsigned char*)wuser;
	id.UserLength = strlen(suser);
	id.Password = (unsigned char*)wpass;
	id.PasswordLength = strlen(pass);
	id.Domain = (unsigned char*)wrdom;
	id.DomainLength = strlen(rdom);
	id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
/*
dump((char*)&id,sizeof(id));
dump((char*)wuser,2*strlen(user));
dump((char*)wrdom,2*strlen(rdom));
dump((char*)wpass,2*strlen(pass));
*/
	ss = AcquireCredentialsHandle(NULL,NTLM,dir,0,&id,0,0,&tcred,&ts);
	if( ss == 0 ) dumpcred(&tcred);
	ss = AcquireCredentialsHandle(suser,NTLM,dir,0,0,0,0,&tcred,&ts);
	if( ss == 0 ) dumpcred(&tcred);

	syslog_ERROR("----NTLM user[%s] AcauireCred %d\n",suser?suser:"",ss);
	if( ss != SEC_E_OK ){
		return -1;
	}

	//ss = AcquireCredentialsHandle(NULL,NEGO,dir,0,&id,0,0,&ncred,&ts);
	ss = AcquireCredentialsHandle(principal,NEGO,dir,0,0,0,0,&ncred,&ts);
	//ss = AcquireCredentialsHandle(principal,NEGO,dir,0,&id,0,0,&ncred,&ts);
	if( ss == 0 ) dumpcred(&ncred);
	/*
	ss = AcquireCredentialsHandle(NULL,NEGO,dir,0,0,0,0,&ncred,&ts);
	if( ss == 0 ) dumpcred(&ncred);
	*/

	syslog_ERROR("----Nego user[%s] AcauireCred %d\n",suser?suser:"",ss);
 }

AUTHOK:

	attr = 0;
	attr |= ISC_REQ_STREAM | ISC_REQ_CONNECTION;
	attr |= ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH;
	attr |= ISC_REQ_CONFIDENTIALITY;
	attr |= ISC_REQ_EXTENDED_ERROR;

	if( chal[0] ){
		/* should initialize with previous request and charenge
		 * without an I/O pair of send / recv
		 */
	}
	for( ri = 0; ri < 4; ri++ ){
		if( 0 < ri ){
			ap = wordScan(auth,atyp);
			lineScan(ap,aval);
			if( strcaseeq(atyp,"NTLM") ){
				ccred = &tcred;
			}else
			if( strcaseeq(atyp,"Negotiate") ){
				ccred = &ncred;
			}else{
				syslog_ERROR("----NTLM auth: non-NTLM [%s]\n",atyp);
				break;
			}
			blen = str_from64(aval,strlen(aval),AVStr(bauth),sizeof(bauth));
			if( lSECRET() )
			syslog_ERROR("----NTLM challenge[%s] isz=%d/%d\n",atyp,
				blen,strlen(aval));
			dump(bauth,blen);
			sbi.cbBuffer = blen;
			sbi.pvBuffer = bauth;
			sbi.BufferType = SECBUFFER_TOKEN;
			sbdi.cBuffers = 1;
			sbdi.pBuffers = &sbi;
			sbdi.ulVersion = SECBUFFER_VERSION;
			sbdip = &sbdi;
		}
		sbo[0].cbBuffer = 0;
		sbo[0].pvBuffer = 0;
		sbo[0].BufferType = SECBUFFER_TOKEN;
		sbo[1].cbBuffer = 0;
		sbo[1].pvBuffer = 0;
		sbo[1].BufferType = SECBUFFER_TOKEN;
		sbdo.cBuffers = 2;
		sbdo.pBuffers = sbo;
		sbdo.ulVersion = SECBUFFER_VERSION;

		ss = InitializeSecurityContext(ccred,ctxtp,0,
			attr|ISC_REQ_ALLOCATE_MEMORY,0,
			SECURITY_NETWORK_DREP,
			sbdip,0,&ctxt,&sbdo,&rattr,0);
			if( lSECRET() )
			syslog_ERROR("----NTLM ISC[%d] ss=%X at=%X/%X oz=%d\n",
				ri,ss,attr,rattr,sbo[0].cbBuffer);

		if( ss != SEC_I_CONTINUE_NEEDED ){
			if( lSECRET() )
			syslog_ERROR("----NTLM auth. done-A ss=%X oz=%d\n",
				ss,sbo[0].cbBuffer);
			//return 0;
		}
		if( sbo[0].pvBuffer ){
			dump((char*)sbo[0].pvBuffer,sbo[0].cbBuffer);
			str_to64((char*)sbo[0].pvBuffer,sbo[0].cbBuffer,
				AVStr(auth),sizeof(auth),0);
			strsubst(AVStr(auth),"\r","");
			strsubst(AVStr(auth),"\n","");
/*
blen = str_from64(auth,strlen(auth),AVStr(bauth),sizeof(bauth));
syslog_ERROR("----NTLM auth: vrfy isz=%d/%d\n",blen,strlen(bauth));
dump(bauth,blen);
*/
			rp = req;
			if( strneq(reql,"CONNECT ",8) ){
				Rsprintf(rp,"CONNECT %s HTTP/1.1\r\n",url);
			}else
			Rsprintf(rp,"HEAD %s HTTP/1.1\r\n",url);
			Rsprintf(rp,"User-Agent: DeleGate\r\n");
			Rsprintf(rp,"Host: %s\r\n",vhost);
			if( ccred == &tcred )
			Rsprintf(rp,"%s: NTLM %s\r\n",AFname(toproxy),auth);
			else
			Rsprintf(rp,"%s: Negotiate %s\r\n",AFname(toproxy),auth);
			Rsprintf(rp,"\r\n");
			if( lSECRET() ) syslog_ERROR("----NTLM REQ\n%s",req);
			wcc = send(tsv,req,strlen(req),0);
			if( lSECRET() ) syslog_ERROR("----NTLM ISC[%d] ss=%X buf=%d wcc=%d\n",
			ri,ss,sbo[0].cbBuffer,wcc);
			FreeContextBuffer(sbo[0].pvBuffer);
		}

		SetLastError(0);
		if( PollIn(fromsv,5*1000) <= 0 ){
			syslog_ERROR("----NTLM recv timeout\n");
			break;
		}
		rcc = recv(fsv,resp,sizeof(resp)-1,0);
		if( lSECRET() ) syslog_ERROR("----NTLM rcc=%d e=%d %d\n",rcc,
			GetLastError(),errno);

		if( rcc <= 0 ){
			break;
		}
		setVStrEnd(resp,rcc);
		if( lSECRET() ) syslog_ERROR("----NTLM RESP\n%s",resp);
		lineScan(resp,line);
		if( ss != SEC_I_CONTINUE_NEEDED ){
			sscanf(line,"%*s %d",&hcode);
			if( lSECRET() )
			syslog_ERROR("----NTLM auth. done-B: EH%d %d %s\n",
				strstr(resp,"\r\n")!=0,hcode,line);
			if( hcode == 100 ){
				if( skipHTTP100(fsv,fromsv,resp) < 0 ){
					break;
				}
				/* should cope with the case of non-100
				 * but incomplete head ...
				 */
			}
			if( lSECRET() ){
/*
int Isend(int sock,const void *buf,unsigned int len,int flags);
int Irecv(int sock,void *buf,unsigned int len,int flags);
void relaytest(int ts,int fs);
void relaytestX(int tss,int fss);
relaytest(tosv,fromsv);
relaytest(tosv,fromsv);
relaytestX(tsv,fsv);
int qi;
for(qi=0;qi<4;qi++){
rp = req;
Rsprintf(rp,"GET %s HTTP/1.1\r\n",url);
Rsprintf(rp,"Host: %s\r\n",vhost);
Rsprintf(rp,"\r\n");
wcc = Isend(tsv,req,strlen(req),0);
syslog_ERROR("----NTLM REQ wcc=%d -----------[%d][%d]\n%s",wcc,tosv,fromsv,req);
rcc = Irecv(fsv,resp,sizeof(resp)-1,0);
if( 0 < rcc )
setVStrEnd(resp,rcc);
syslog_ERROR("----NTLM RESP rcc=%d ------------\n%s",rcc,resp);
syslog_ERROR("###############################################test[%d] %d,%d\n",qi,tsv,fsv);
sleep(1);
}
relaytest(tosv,fromsv);
relaytestX(tsv,fsv);
*/
			}
			RevertSecurityContext(&ctxt);
			break;
		}
		if( getFieldValue2(resp,CFname(toproxy),AVStr(auth),sizeof(auth)) == 0 ){
			break;
		}
/*
		ap = wordScan(auth,atyp);
		lineScan(ap,aval);
		if( strcaseeq(atyp,"NTLM") ){
			ccred = &tcred;
		}else
		if( strcaseeq(atyp,"Negotiate") ){
			ccred = &ncred;
		}else{
			syslog_ERROR("----NTLM auth: non-NTLM [%s]\n",atyp);
			break;
		}
		blen = str_from64(aval,strlen(aval),AVStr(bauth),sizeof(bauth));
		if( lSECRET() ) syslog_ERROR("----NTLM auth: [%s] isz=%d/%d\n",atyp,
			blen,strlen(aval));
		dump(bauth,blen);
		sbi.cbBuffer = blen;
		sbi.pvBuffer = bauth;
		sbi.BufferType = SECBUFFER_TOKEN;
		sbdi.cBuffers = 1;
		sbdi.pBuffers = &sbi;
		sbdi.ulVersion = SECBUFFER_VERSION;
		sbdip = &sbdi;
*/

		ctxtp = &ctxt;
	}
	RevertSecurityContext(&ctxt);
	return hcode;
}

// http://msdn.microsoft.com/en-us/library/aa446619.aspx
BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
){
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if ( !LookupPrivilegeValue( 
		NULL,           // lookup privilege on local system
		lpszPrivilege,  // privilege to lookup 
		&luid ) )       // receives LUID of privilege
	{
		syslog_ERROR("-- LookupPrivilegeValue error: %u\n",GetLastError()); 
		return FALSE; 
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else	tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if ( !AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(TOKEN_PRIVILEGES), 
		(PTOKEN_PRIVILEGES) NULL,(PDWORD) NULL) ){ 
		syslog_ERROR("-- AdjustTokenPrivileges error: %u\n",GetLastError()); 
		return FALSE; 
	} 

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED){
		syslog_ERROR("-- The token does not have the specified privilege %X\n",
			lpszPrivilege);
		return FALSE;
	} 
	return TRUE;
}
int setSeTcbPrivilege(HANDLE token,int on){
	int ok;
	ok = SetPrivilege(token,SE_TCB_NAME,on);
	syslog_ERROR("SE_TDB_NAME %s %s\n",on?"ON":"OFF",ok?"OK":"NG");
	//if( ok ) ok = SetPrivilege(token,SE_CHANGE_NOTIFY_NAME,1);
	//if( ok ) ok = SetPrivilege(token,SE_INTERACTIVE_LOGON_NAME,1);
	return ok;
}
#else
int setSeTcbPrivilege(HANDLE token,int on){
	return 0;
}
#endif /*}*/

int winssl_accept(int cl){
	SECURITY_STATUS ss;
	CredHandle cred;
	CtxtHandle ctxt;
	TimeStamp ts;
	SecBufferDesc sbdi;
	SecBufferDesc sbdo;
	ULONG attr;
	char data[1024];
	ULONG rcc;
	int wcc;
	SecBuffer sbi;
	SecBuffer sbo;
	int rcode = -1;
	int ri;
	int dir;

	bzero(&ctxt,sizeof(ctxt));
	dir = SECPKG_CRED_BOTH;
	ss = AcquireCredentialsHandle(0,SSL2,dir,0,0,0,0,&cred,&ts);
	if( ss != SEC_E_OK ){
		const char *res = "";
		switch( ss ){
		  case SEC_E_UNKNOWN_CREDENTIALS: res = "UnknownCred"; break;
		  case SEC_E_NO_CREDENTIALS: res = "NoCred"; break;
		  case SEC_E_NOT_OWNER: res = "NotOwner"; break;
		  case SEC_E_INSUFFICIENT_MEMORY: res = "NoMem"; break;
		  case SEC_E_INTERNAL_ERROR: res = "InternalError"; break;
		  case SEC_E_SECPKG_NOT_FOUND: res = "NotFound"; break;
		}
		fprintf(stderr,"-- Can't get credential handle (%s)\n",res);
fprintf(stderr,"-- Can't get credential handle (%s)\n",res);
		return -1;
	}

	attr = ASC_REQ_STREAM | ASC_REQ_ALLOCATE_MEMORY;
	for( ri = 0; ; ri++ ){
fprintf(stderr,"-- recv...\n");
		rcc = recv(cl,data,sizeof(data),0);
		fprintf(stderr,"-- rcc=%d\n",rcc);
fprintf(stderr,"-- rcc=%d\n",rcc);
		if( rcc <= 0 ){
			break;
		}
		sbi.cbBuffer = rcc;
		sbi.pvBuffer = data;
		sbi.BufferType = SECBUFFER_TOKEN;
		sbdi.cBuffers = 1;
		sbdi.pBuffers = &sbi;
		sbdi.ulVersion = SECBUFFER_VERSION;

		sbo.cbBuffer = 0;
		sbo.pvBuffer = 0;
		sbo.BufferType = SECBUFFER_TOKEN;
		sbdo.cBuffers = 1;
		sbdo.pBuffers = &sbo;
		sbdo.ulVersion = SECBUFFER_VERSION;

		ss = AcceptSecurityContext(&cred,ri==0?0:&ctxt,&sbdi,attr,
			SECURITY_NETWORK_DREP,&ctxt,&sbdo,&attr,0);
fprintf(stderr,"-- rcc=%d stat=%d\n",rcc,ss,sbo.cbBuffer);

		if( sbo.cbBuffer ){
			wcc = send(cl,(char*)sbo.pvBuffer,sbo.cbBuffer,0);
			FreeContextBuffer(sbo.pvBuffer);
		}
		if( ss != SEC_I_CONTINUE_NEEDED ){
			const char *res = "";
			switch( ss ){
			case SEC_I_CONTINUE_NEEDED: res = "Continue"; break;
			case SEC_I_COMPLETE_NEEDED: res = "Complete"; break;
			case SEC_I_COMPLETE_AND_CONTINUE: res = "CompCont"; break;
			//case SEC_I_LOCAL_LOGIN: res = "Login"; break;
			case SEC_E_INVALID_TOKEN: res = "InvalidTOken"; break;
			}
fprintf(stderr,"-- rcc=%d stat=%X DONE (%s)\n",rcc,ss,res);
			rcode = 0;
			break;
		}
	}
	DeleteSecurityContext(&ctxt);
	FreeCredentialsHandle(&cred);
	return 0;
}

#endif
