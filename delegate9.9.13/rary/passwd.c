/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1997-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	passwd.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970514	extracted from misc.c
//////////////////////////////////////////////////////////////////////#*/
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "ystring.h"
int setCloseOnExec(int fd);
int pam_auth1(PCStr(service),PCStr(user),PCStr(pass));

#include <sys/types.h>
#include <sys/stat.h>
#ifdef S_ISUID /* set UID on execution */
#include <pwd.h>
#include <grp.h>
#else
#include "passwd.h"
static struct passwd passwd0 = { "?", "", 0, 0, 0, "", "", "/", "" };
#define getpwuid(uid)	(&passwd0)
#define getpwnam(name)	(&passwd0)

static struct group group0 = { "?", "", 0, 0 };
#define getgrgid(gid)	(&group0)
#define getgrnam(gid)	(&group0)
#endif

/* Solaris2.X leaves NIS+? relevant fd be opened after exec() */
struct passwd *GETpwuid(int uid)
{	struct passwd *pw;
	int fd;

	fd = nextFD();
	pw = getpwuid(uid);
	usedFD(fd);
	return pw;
}
struct group *GETgrgid(int gid)
{	struct group *gr;
	int fd;

	fd = nextFD();
	gr = getgrgid(gid);
	usedFD(fd);
	return gr;
}
struct passwd *GETpwnam(PCStr(name))
{	struct passwd *pw;
	int fd;

	fd = nextFD();
	pw = getpwnam(name);
	usedFD(fd);
	return pw;
}
struct group *GETgrnam(PCStr(group))
{	struct group *gr;
	int fd;

	fd = nextFD();
	gr = getgrnam(group);
	usedFD(fd);
	return gr;
}

char *getUsername(int uid,PVStr(name))
{	struct passwd *passwd;
	const char *user;

	if( passwd = GETpwuid(uid) )
		strcpy(name,passwd->pw_name);
	else
	if( uid == getuid() && (user = getlogin()) ){
		/* 9.9.7 for MacOSX */
		strcpy(name,user);
	}
	else	sprintf(name,"#%d",uid);
	return (char*)name;
}

typedef struct {
	int ue_LastUid;
	MStr(ue_LastUname,32);
} UidnameCache;
static UidnameCache *uidnameCache;
#define LastUid   uidnameCache->ue_LastUid
#define LastUname uidnameCache->ue_LastUname
/**/

char *getUsernameCached(int uid,PVStr(name))
{
	if( uidnameCache == 0 ){
		uidnameCache = NewStruct(UidnameCache);
		LastUid = -1;
	}
	if( uid == LastUid && LastUname[0] != 0 )
		strcpy(name,LastUname);
	else{
		getUsername(uid,AVStr(name));
		strcpy(LastUname,name);
		LastUid = uid;
	}
	return (char*)name;
}

void getHOME(int uid,PVStr(home))
{	struct passwd *passwd;

	if( passwd = GETpwuid(uid) )
		strcpy(home,passwd->pw_dir);
	else	strcpy(home,"/");
}
int getSHELL(int uid,PVStr(shell))
{	struct passwd *passwd;

	if( passwd = GETpwuid(uid) ){
		strcpy(shell,passwd->pw_shell);
		return 1;
	}
	return 0;
}
char *getGroupname(int gid,PVStr(name))
{	struct group *group;

	if( group = GETgrgid(gid) )
		strcpy(name,group->gr_name);
	else	sprintf(name,"#%d",gid);
	return (char*)name;
}
char *getusernames(PVStr(names))
{	CStr(uname,32);
	CStr(euname,32);
	CStr(gname,32);
	CStr(egname,32);

	uname[0] = euname[0] = 0;
	getUsername(getuid(),AVStr(uname));
	getUsername(geteuid(),AVStr(euname));

	gname[0] = egname[0] = 0;
	getGroupname(getgid(),AVStr(gname));
	getGroupname(getegid(),AVStr(egname));

	sprintf(names,"%s/%s(%s/%s)",uname,gname,euname,egname);
	return (char*)names;
}

int getUserId(PCStr(user))
{	struct passwd *passwd;

	if( passwd = GETpwnam(user) )
		return passwd->pw_uid;
	else	return -1;
}
int getGroupId(PCStr(gname))
{	struct group *group;

	if( group = GETgrnam(gname) )
		return group->gr_gid;
	else	return -1;
}

int owner_main(int ac,const char *av[]){
	struct passwd *pw;
	int id;
	IStr(name,128);

	id = getuid();
	errno = 0;
	pw = getpwuid(id);
	Xfprintf(stdout,"getpwuid(%d)=%llX, errno=%d\n",id,p2llu(pw),errno);
	if( pw == 0 && errno == 0 ){
		endpwent(); /* for MacOSX ? */
		setpwent();
		pw = getpwuid(id);
		endpwent();
		Xfprintf(stdout,">>> getpwuid(%d)=%llX, errno=%d\n",id,p2llu(pw),errno);
	}

	printf("User: %s (%d)\n",getUsername(id,AVStr(name)),id);
	id = geteuid();
	printf("E-User: %s (%d)\n",getUsername(id,AVStr(name)),id);
	id = getgid();
	printf("Group: %s (%d)\n",getGroupname(id,AVStr(name)),id);
	return 0;
}

/*
 *	user_group:	user / group ( euser / egroup )
 */
int scan_guid(PCStr(user_group),int *uidp,int *gidp)
{	const char *dp;
	CStr(user,256);
	CStr(group,256);
	struct passwd *pw;
	struct group *gr;
	int len;
	int uid,gid;

	if( dp = strchr(user_group,'/') ){
		if( len = dp - user_group ){
			strncpy(user,user_group,len); setVStrEnd(user,len);
		}else	getUsername(getuid(),AVStr(user));
		strcpy(group,dp+1);
	}else{
		strcpy(user,user_group);
		group[0] = 0;
	}

	uid = gid = -1;

	if( *user == '#' ){
		uid = atoi(user+1) & 0xFFFF;
		if( pw = GETpwuid(uid) )
			gid = pw->pw_gid;
	}else
	if( pw = GETpwnam(user) ){
		uid = pw->pw_uid;
		gid = pw->pw_gid;
	}else	return -1;

	if( *group == '#' )
		gid = atoi(group+1);
	else
	if( gr = GETgrnam(group) )
		gid = gr->gr_gid;

	if( uidp ) *uidp = uid;
	if( gidp ) *gidp = gid;
	return 0;
}

static struct passwd *_pwuids;
#define _pwuid	_pwuids[0]
struct passwd *getpwuid_nis(PCStr(map),PCStr(domain),int uid)
{	const char *ypdomain;
	const char *key;
	const char *val;
	const char *vp;
	CStr(uids,32);
	int vlen;
	int rcode;

	if( _pwuids == 0 )
		_pwuids = NewStruct(struct passwd);

	if( _pwuid.pw_name ){
		if( _pwuid.pw_uid == uid )
			return &_pwuid;
		free((char*)_pwuid.pw_name);
		bzero(&_pwuid,sizeof(struct passwd));
	}

	if( map == NULL ){
		map = "passwd.byuid";
	}

	if( domain != NULL && domain[0] != 0 )
		ypdomain = domain;
	else{
		ypdomain = NULL;
		rcode = yp_get_default_domain((char**)&ypdomain);
		if( rcode != 0 || ypdomain == NULL || *ypdomain == 0 )
			return NULL;
		if( strcmp(ypdomain,"(none)") == 0 )
			return NULL;
	}

	sprintf(uids,"%d",uid);
	rcode = yp_match(ypdomain,(char*)map,uids,strlen(uids),(char**)&val,&vlen);
	if( rcode != 0 )
		return NULL;

	((char*)val)[vlen] = 0; /* is this safe ? */

	_pwuid.pw_name = (char*)(vp = stralloc(val));
	if( vp = strchr(vp,':') ){
		truncVStr(vp); vp++;
		_pwuid.pw_passwd = (char*)vp;
	if( vp = strchr(vp,':') ){
		truncVStr(vp); vp++;
		_pwuid.pw_uid = atoi(vp);
	if( vp = strchr(vp,':') ){
		truncVStr(vp); vp++;
		_pwuid.pw_gid = atoi(vp);
	if( vp = strchr(vp,':') ){
		truncVStr(vp); vp++;
		_pwuid.pw_gecos = (char*)vp;
	if( vp = strchr(vp,':') ){
		truncVStr(vp); vp++;
		_pwuid.pw_dir = (char*)vp;
	if( vp = strchr(vp,':') ){
		truncVStr(vp); vp++;
		_pwuid.pw_shell = (char*)vp;
	}}}}}}

	return &_pwuid;
}
struct passwd *Getpwuid(int uid)
{	struct passwd *pw;

	if( pw = getpwuid(uid) )
		return pw;
	else	return getpwuid_nis(NULL,NULL,uid);
}

#ifdef MAIN
main(int ac,char *av[])
{	struct passwd *pp;

	if( pp = Getpwuid(atoi(av[1])) ){
		printf("name=	%s\n",pp->pw_name);
		printf("pass=	%s\n",pp->pw_passwd);
		printf("uid=	%d\n",pp->pw_uid);
		printf("gid=	%d\n",pp->pw_gid);
		printf("gecos=	%s\n",pp->pw_gecos);
		printf("dir=	%s\n",pp->pw_dir);
		printf("shell=	%s\n",pp->pw_shell);
	}
}
#endif

#define PAM_BY_MAIN_ONLY
#include "pam.c"
