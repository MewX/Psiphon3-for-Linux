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
Program:	nntpgw.c (NNTP / HTTP gateway)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970202	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <ctype.h>
#include "delegate.h"
#include "file.h"
#include "fpoll.h"
#include "ystring.h"

int HTTP_putRequest(Connection *Conn,FILE *fp);
FILE *SMTP_POST(PCStr(host),int port,PCStr(to),PCStr(from));
const char *MailGate(Connection *Conn);
FILE *openAclFile(int create,PCStr(proto),PCStr(host),int port,PCStr(upath));
FILE *openMuid(int create,PCStr(muid),PVStr(mbox));
FILE *openGACL(int create,PCStr(muid));

int ACLMAX = 32;
int ACL_MAXLINES = 128;
int ACL_MAXBYTES = 32*1024;

static void printAdmin(FILE *tc,PCStr(stime),PCStr(com),PCStr(user),PCStr(admstat),PCStr(admid))
{	CStr(adminid,1024);
	const char *ap;

	adminid[0] = 0;
	Xsscanf(admid,"<%[^>]",AVStr(adminid));
	fprintf(tc,"[%s] %-4s %-10s ",stime,com,user);
	if( ap = strchr(adminid,'-') )
		if( *++ap && *++ap )
			while( *++ap )
				*(char*)ap = '*';
	if( strcasecmp(admstat,"anonymous") == 0 )
		fprintf(tc,"%-10s %s\r\n",admstat,adminid);
	else	fprintf(tc,"%-10s <A HREF=?Admin=GetACL&ADMINID=%s>%s</A>\r\n",admstat,adminid,adminid);
}

int getSubscription(Connection *Conn,FILE *tc,PCStr(userclass),PCStr(newsgroup),int *subp,int *unsp)
{	FILE *acl;
	CStr(ac1,2048);
	const char *wp;
	CStr(stime,128);
	CStr(com,128);
	CStr(user,128);
	CStr(admstat,128);
	CStr(admid,1024);
	int point,adm,sub,uns;

	adm = sub = uns = 0;
	if( acl = openAclFile(0,DST_PROTO,DST_HOST,DST_PORT,newsgroup) ){
		while( fgets(ac1,sizeof(ac1),acl) ){
			wp = wordScan(ac1,stime);
			wp = wordScan(wp,com);
			wp = wordScan(wp,user);
			if( strcmp(userclass,user) != 0 )
				continue;

			wp = wordScan(wp,admstat);
			if( strcaseeq(admstat,"open") )
				point = 10;
			else	point = 1;
			if( strcaseeq(com,"On") ){ adm++; sub += point; } else
			if( strcaseeq(com,"Off")){ adm++; uns += point; }

			if( tc != NULL ){
				wordScan(wp,admid);
				printAdmin(tc,stime,com,user,admstat,admid);
			}
		}
		fclose(acl);
	}

	if( subp ) *subp = sub;
	if( unsp ) *unsp = uns;
	return adm;
}

static int setACL(Connection *Conn,int add,PCStr(aclID),PCStr(user),PCStr(url),FILE *cfp,FILE *tc,void *env,sFUNCP ckfunc)
{	CStr(ctl,2048);
	CStr(com,2048);
	CStr(arg,2048);
	CStr(ac1,2048);
	CStr(Ver,256);
	CStr(AdmClass,128);
	CStr(Base,1024);
	int len;
	int errors = 0;
	int nl,cnl;
	FILE *acl;
	CStr(admid,2048);
	const char *xp;
	CStr(xmbox,128);
	int off;
	const char *cp;
	CStr(stime,64);
	const char *err;
	int bytes;

	cnl = 0;
	bytes = 0;
	Ver[0] = 0;
	AdmClass[0] = 0;
	Base[0] = 0;
	StrftimeLocal(AVStr(stime),sizeof(stime),"%Y/%m/%d-%H:%M:%S",time(0),0);

	sprintf(admid,"<%s>",aclID);

	for( nl = 1; fgets(ctl,sizeof(ctl),cfp) != NULL; nl++ ){
		bytes += strlen(ctl);
		if( ACL_MAXBYTES < bytes ){
fprintf(tc,"[WARNING] your ACL should be smaller than %d bytes.\r\n",
ACL_MAXBYTES);
			fprintf(tc,"[WARNING] remaining list is ignored.\r\n");
			errors++;
			break;
		}

		if( cp = strchr(ctl,'#') )
			truncVStr(cp);
		if( ctl[0] == 0 )
			continue;

		com[0] = arg[0] = 0;
		Xsscanf(ctl,"%[^: \t\r\n]%*[: \t\r\n]%[^\r\n]",AVStr(com),AVStr(arg));
		if( com[0] == 0 )
			continue;

		if( strcaseeq(com,"ACL-Version") ){
			strcpy(Ver,arg);
			continue;
		}
		if( strcaseeq(com,"Admin-Class") ){
			if( !strcaseeq(arg,"anonymous") ){
				fprintf(tc,"[FATAL: unknown Admin-Class] %s\r\n",arg);
				return -1;
			}
			strcpy(AdmClass,arg);
			continue;
		}
		if( strcaseeq(com,"Base-URL") ){
			CStr(proto,128);
			CStr(login,128);
			CStr(path,128);
			CStr(clogin,128);

			decomp_absurl(arg,AVStr(proto),AVStr(login),AVStr(path),sizeof(path));
			HostPort(AVStr(clogin),DST_PROTO,DST_HOST,DST_PORT);
			if( strcmp(proto,DST_PROTO) || hostcmp(login,clogin) ){

fprintf(tc,"[FATAL: Base-URL arrogation] <%s> should be <%s://%s>\r\n",
arg,DST_PROTO,clogin);

				return -1;
			}
			strcpy(Base,arg);
			continue;
		}

		if( Ver[0] == 0 ){
			fprintf(tc,"[FATAL: no ACL-Version specified]\r\n");
			return -1;
		}
		if( AdmClass[0] == 0 ){
			strcpy(AdmClass,"anonymous");
			fprintf(tc,"[WARNING: no Admin-Class specified] assumed %s\r\n",
				AdmClass);
		}
		if( ACL_MAXLINES < nl ){
fprintf(tc,"[WARNING] your ACL should be less than %d lines.\r\n",
ACL_MAXLINES);
			fprintf(tc,"[WARNING] remaining list is ignored.\r\n");
			errors++;
			break;
		}

		if( strcaseeq(com,"On") || strcaseeq(com,"Off") ){
			++cnl;

			if( add && ACLMAX < cnl ){
fprintf(tc,"[WARNING] you cannot control ACLs for more than %d newsgroups.\r\n",
ACLMAX);
				fprintf(tc,"[WARNING] remaining list is ignored.\r\n");
				errors++;
				break;
			}
			if( add && (err = (*ckfunc)(env,Base,arg)) ){
				fprintf(tc,"[ERROR] %d:[%s] %s: %s\r\n",
					nl,err,com,arg);
				errors++;
				continue;
			}

			acl = openAclFile(1,DST_PROTO,DST_HOST,DST_PORT,arg);
			fseek(acl,0,0);
			for(;;){
				off = ftell(acl);
				if( fgets(ac1,sizeof(ac1),acl) == NULL )
					break;
				if( xp = strstr(ac1,admid) ){
					if( add )
					fprintf(tc,"[UPDATE] %d: %s: %s\r\n",nl,com,arg);
					fseek(acl,off,0);
					break;
				}
			}
			if( add ){
				fprintf(acl,"%s %-10s %-10s %-10s %s\r\n",
					stime,com,user,AdmClass,admid);
			}else{
				int fsize,rcc;
				const char *buff;

				fsize = file_size(fileno(acl));
				buff = (char*)malloc(fsize);
				rcc = fread((char*)buff,1,fsize,acl);
				fseek(acl,off,0);
				fwrite(buff,1,rcc,acl);
				free((char*)buff);
				Ftruncate(acl,off,0);
			}
			fclose(acl);
			continue;
		}
	}
	return errors;
}

static void notifyAdmin(Connection *Conn,FILE *admfp,FILE *infp,PCStr(adminid),PCStr(adminmbox),PCStr(event))
{	CStr(mailer,128);
	CStr(line,1024);
	CStr(stime,128);
	FILE *fp;

	mailer[0] = 0;

	fseek(admfp,0,0);
	while( fgets(line,sizeof(line),admfp) != NULL ){
		if( Xsscanf(line,"MAILER: %s",AVStr(mailer)) )
			break;
	}
	if( mailer[0] ){
		fp = SMTP_POST(mailer,25,adminmbox,MailGate(Conn));
		fprintf(fp,"Subject: Notice: GACL %s\r\n",event);
		fprintf(fp,"\r\n");
		fprintf(fp,"ACTION: %s\r\n",event);
		fprintf(fp,"MUID: %s\r\n",adminid);
		fprintf(fp,"\r\n--CONTENT--\r\n");
		if( infp ){
			fseek(infp,0,0);
			copyfile1(infp,fp);
		}
		fprintf(fp,"\r\n--REQUEST--\r\n");
		HTTP_putRequest(Conn,fp);
		fprintf(fp,"--END--\r\n");
		pclose(fp);
	}
	fseek(admfp,0,2);
	StrftimeLocal(AVStr(stime),sizeof(stime),"%Y/%m/%d-%H:%M:%S",time(0),0);
	fprintf(admfp,"[%s] %s\r\n",stime,event);
	fflush(admfp);
}

void uploadACL(Connection *Conn,PCStr(user),FILE *tc,FILE *oldacl,FILE *newacl,PCStr(aclID),PCStr(mbox),PCStr(durl),void *env,sFUNCP ckfunc);
void httpAdmin(Connection *Conn,PVStr(user),FILE *tc,PCStr(group),PVStr(search),void *env,iFUNCP prfunc,sFUNCP ckfunc,PVStr(adminid))
{	const char *np;
	CStr(sub,128);
	CStr(dhtml,128);
	CStr(url,1024);
	CStr(durl,1024);
	CStr(aurl,1024);
	CStr(aclurl,1024);
	CStr(adminmbox,1024);
	FILE *cfp,*acl;
	CStr(opath,1024);
	FILE *admfp;
	CStr(line,1024);

	nonxalpha_unescape(search,AVStr(search),0);
	strdelchr(search,AVStr(search),"\"'<>");

	sub[0] = 0;
	Xsscanf(search,"Admin=%[^&]",AVStr(sub));

	if( np = strstr(search,"USER=") )
		Xsscanf(np,"USER=%[^&]",AVStr(user));

	setVStrEnd(adminid,0);
	if( np = strstr(search,"ADMINID=") )
		Xsscanf(np,"ADMINID=%[^&]",AVStr(adminid));

	url[0] = 0;
	if( np = strstr(search,"URL=") )
		Xsscanf(np,"URL=%[^&]",AVStr(url));
	nonxalpha_unescape(url,AVStr(durl),0);

/*
	if( !streq(user,"anonymous") ){
		fprintf(tc,"you cannot control %s users\r\n",)user);
		return;
	}
*/

	if( streq(sub,"GetACL") || streq(sub,"PutACL") ){
		CStr(line,1024);

		if( adminid[0] == 0 ){
			fprintf(tc,"You must show your <I>Admin-ID</I>.\r\n");
			return;
		}

		if( streq(sub,"PutACL") )
		if( durl[0] == 0 ){
			fprintf(tc,"You must show your <I>ACL-URL</I> (URL of your GACL).\r\n");
			return;
		}else
		if( durl[0] ){
			cfp = tmpfile();
			URLget(durl,1,cfp);
			if( file_size(fileno(cfp)) <= 0 ){
				fprintf(tc,"Your GACL at &lt;%s&gt; is not accessible\r\n",durl);
				return;
			}
		}

		if( (admfp = openMuid(0,adminid,AVStr(adminmbox))) == NULL ){
			fprintf(tc,"The <I>Admin-ID</I> shown [%s] does not exist.\r\n",adminid);
			return;
		}
		if( streq(sub,"GetACL") )
		if( (acl = openGACL(0,adminid)) && 0 < file_size(fileno(acl)) ){
			line[0] = 0;
			while( fgets(line,sizeof(line),acl) != NULL ){
				if( line[0] == '#' ){
					fputs(line,tc);
					break;
				}
				if( line[0] == '\r' || line[0] == '\n' )
					break;
			}
			if( line[0] != '#' ) /* maybe template */
				fprintf(tc,"#<PLAINTEXT>\r\n");

			copyfile1(acl,tc);
			fflush(tc);
			notifyAdmin(Conn,admfp,acl,adminid,adminmbox,"downloaded");
			return;
		}

		acl = openGACL(1,adminid);
		line[0] = 0;
		fgets(line,sizeof(line),acl);
		fseek(acl,0,0);

		if( streq(sub,"GetACL") ){
putBuiltinHTML(Conn,acl,"NNTP/HTTP-Gateway-Admin","news/adminNewACL.dhtml",NULL,prfunc,env);
			fflush(acl);
			fseek(acl,0,0);
			copyfile1(acl,tc);
			notifyAdmin(Conn,admfp,acl,adminid,adminmbox,"created+downloaded");
			fclose(acl);
			fflush(tc);
			return;
		}

		if( line[0] == 0 || line[0] == '#' ){
			fseek(admfp,0,2);
			fprintf(admfp,"ACL-URL: %s\r\n",durl);
			fflush(admfp);
		}else{
			/* check consistensy of ACL-URL */
		}

		uploadACL(Conn,user,tc,acl,cfp,adminid,adminmbox,durl,env,ckfunc);

		fseek(cfp,0,0);
		copyfile1(cfp,acl);
		Ftruncate(acl,0,1);

		fflush(tc);
		notifyAdmin(Conn,admfp,cfp,adminid,adminmbox,"uploaded");

		fclose(cfp);
		fclose(acl);
		fclose(admfp);
	}

	sprintf(dhtml,"news/admin%s.dhtml",sub);
	putBuiltinHTML(Conn,tc,"NNTP/HTTP-Gateway-Admin",dhtml,NULL,prfunc,env);
}

void uploadACL(Connection *Conn,PCStr(user),FILE *tc,FILE *oldacl,FILE *newacl,PCStr(aclID),PCStr(mbox),PCStr(durl),void *env,sFUNCP ckfunc)
{	int errors;
	int osize;
	CStr(line,1024);

	fprintf(tc,"<PLAINTEXT>\r\n");
	fprintf(tc,"UPLOAD/UPDATE/REMOVE Gateway Access Control List (GACL)\r\n");
	fprintf(tc,"Source GACL URL: <%s>\r\n",durl);
	fprintf(tc,"\r\n--DIAGNOSIS--\r\n");

	osize = file_size(fileno(oldacl));

	if( 0 < osize ){
		while( fgets(line,sizeof(line),oldacl) != 0 ){
			/* skip HTTP header */
			if( line[0] == '#' || line[0] == '\r' || line[0] == '\n' )
				break;
		}
		setACL(Conn,0,aclID,user,durl,oldacl,tc,env,ckfunc);
		fseek(oldacl,0,0);
	}

	if( file_size(fileno(newacl)) <= 0 ){
		if( 0 < osize )
			fprintf(tc,"Your ACL is removed\r\n");
	}else{
		errors = setACL(Conn,1,aclID,user,durl,newacl,tc,env,ckfunc);
		if( errors == 0 )
			fprintf(tc,"NO ERROR\r\n");

		fseek(newacl,0,0);
		fprintf(tc,"\r\n--SOURCE--\r\n");
		copyfile1(newacl,tc);
	}
	if( 0 < osize ){
		fprintf(tc,"\r\n--PREVIOUS--\r\n");
		copyfile1(oldacl,tc);
		fseek(oldacl,0,0);
	}

	fprintf(tc,"\r\n--END--\r\n");
}
