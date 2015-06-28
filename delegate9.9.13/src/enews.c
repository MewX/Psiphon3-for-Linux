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
Program:	enews.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	960624	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdlib.h>
#include <stdio.h>
#include "ystring.h"
#include "dglib.h"
#include "file.h"

void NewsLibdir(PVStr(path),PCStr(spec));
void NNTP_midpath(PVStr(path),PCStr(msgid));
FILE *linkArticle(FILE *afp,PCStr(group),int anum,PCStr(apath),PCStr(msgid),PCStr(nodename));

#define LINESIZE	4095
#define MYSELF	"-.-"
/*
#define GPREFIX	"-."
*/
#define GPREFIX	""
#define ACTIVE_DIR	"groups"
#define HISTORY_DIR	"history"
#define ResentMid	"X-Resent-Message-ID"

#define EOM(line)	(line[0]=='.' && (line[1]=='\r'||line[1]=='\n'))
#define EOH(line)	(line[0] == '\r' || line[0] == '\n')

#define FGPREFIX "+FILE-"

static void file2group(PCStr(gname),PVStr(gpath))
{	const char *pp;
	char pc;
	refQStr(gp,gpath); /**/

	strcpy(gp,FGPREFIX);
	gp += strlen(gp);
	for( pp = gname; pc = *pp; pp++ ){
		assertVStr(gpath,gp+3);
		switch( pc ){
			case '\\':
			case '/': setVStrPtrInc(gp,'.'); break;
			case ':': sprintf(gp,"%%%02x",pc); gp += 3; break;
			default: setVStrPtrInc(gp,pc); break;
		}
	} 
	XsetVStrEnd(AVStr(gp),0);
}

FILE *news_fopen(const char *F,int L,const char *file,const char *mode){
	FILE *fp;
	CStr(xfile,1024);

	strcpy(xfile,file);
	path_escchar(AVStr(xfile));
	fp = fopen(xfile,mode);
	return fp;
}
#undef fopen
#define fopen(file,mode) news_fopen(__FILE__,__LINE__,file,mode)

static FILE *fopen_active(PCStr(group),PCStr(mode1),PCStr(mode2))
{	CStr(actpath1,LINESIZE);
	CStr(apath,LINESIZE);
	FILE *actfp;
	CStr(filegroup,1024);

	if( isFullpath(group) ){
		file2group(group,AVStr(filegroup));
		group = filegroup;
	}

	sprintf(actpath1,"%s/%s",ACTIVE_DIR,group);
	NewsLibdir(AVStr(apath),actpath1);
	sv1vlog("ACTIVEFILE[%s]\n",apath);
	actfp = fopen(apath,mode1);
	if( actfp == NULL && mode2 != NULL )
		actfp = dirfopen("ACTIVE",AVStr(apath),mode2);
	return actfp;
}
static void default_spool(PVStr(dir),PCStr(group))
{	CStr(artpath1,LINESIZE);
	const char *lp;

	sprintf(artpath1,"spool/%s",group);
	for( lp = artpath1; *lp; lp++ )
		if( *lp == '.' )
			*(char*)lp = '/';
	cache_path("nntp",MYSELF,119,artpath1,AVStr(dir));
}
static void strip_msgid(PCStr(src),PVStr(dst));
static FILE *open_history(PCStr(msgid),int create)
{	CStr(histpath,256);
	CStr(hpath,256);
	CStr(path,1024);
	FILE *hfp;

	if( msgid[0] == 0 ){
		return NULL;
	}
	strip_msgid(msgid,ZVStr((char*)msgid,strlen(msgid)+1));
	NNTP_midpath(AVStr(histpath),msgid);
	sprintf(hpath,"%s/%s",HISTORY_DIR,histpath);
	NewsLibdir(AVStr(path),hpath);

	if( create ){
		if( hfp = dirfopen("ART-HISTORY",AVStr(path),"r+") )
			return hfp;
		else	return dirfopen("ART-HISTORY",AVStr(path),"w+");
	}else{
		return dirfopen("ART-HISTORY",AVStr(path),"r");
	}
}
static void put_history(PCStr(msgid),PCStr(group),int anum,PCStr(artpath))
{	FILE *hfp;
	CStr(idline,256);
	CStr(line,256);
	const char *sp;
	char sc;
	int found;
	refQStr(dp,idline); /**/

	if( (hfp = open_history(msgid,1)) == NULL )
		return;

	found = 0;
	for( sp = group; sc = *sp; sp++ ){
		assertVStr(idline,dp+1);
		if( sc == '.' )
			setVStrPtrInc(dp,'/');
		else	setVStrPtrInc(dp,sc);
	}
	sprintf(dp,"/%d %s",anum,artpath);
	while( fgets(line,sizeof(line),hfp) ){
		if( dp = strpbrk(line,"\r\n") )
			truncVStr(dp);
		if( strcmp(line,idline) == 0 ){
			found = 1;
			break;
		}
	}
	if( found == 0 ){
		sv1log("#### added HISTORY [%s]\n",idline);
		fprintf(hfp,"%s\r\n",idline);
	}
	fclose(hfp);
}
/* history of only the first article */
static void put_history1st(PCStr(msgid),PCStr(group),int anum,PCStr(artpath))
{	FILE *hfp;
	CStr(idline,256);
	CStr(line,256);
	const char *sp;
	char sc;
	int found;
	refQStr(dp,idline); /**/
	int mt0,mt1;

	if( (hfp = open_history(msgid,1)) == NULL )
		return;

	found = 0;
	for( sp = group; sc = *sp; sp++ ){
		assertVStr(idline,dp+1);
		if( sc == '.' )
			setVStrPtrInc(dp,'/');
		else	setVStrPtrInc(dp,sc);
	}
	sprintf(dp,"/%d %s",anum,artpath);
	truncVStr(line);
	if( fgets(line,sizeof(line),hfp) != NULL ){
		if( dp = strpbrk(line,"\r\n") )
			truncVStr(dp);

		mt0 = File_mtime(artpath);
		if( dp = strchr(line,' ') )
			mt1 = File_mtime(dp+1);
		else	mt1 = 0;
		if( 0 < mt0 && 0 < mt1 ){
			if( mt1 <= mt0 ){
				found = 1;
			}
		}else
		if( strlen(line) < strlen(idline) ){
			found = 1;
		}else
		if( strcmp(line,idline) <= 0 ){
			found = 1;
		}
	}
	if( found == 0 ){
		if( line[0] )
			sv1log("#### replaced HISTORY [%s]<[%s]\n",idline,line);
		else	sv1log("#### added HISTORY [%s]\n",idline);
		fseek(hfp,0,0);
		fprintf(hfp,"%s\r\n",idline);
		Ftruncate(hfp,0,1);
	}
	fclose(hfp);
}

static FILE *fopen_article(PCStr(msgid),PCStr(group),int anum,PCStr(mode),PVStr(artpath));
int anomidToGroup(PCStr(msgid),PVStr(rgroup));
static FILE *open_anomid(PCStr(msgid),PCStr(mode)){
	CStr(apath,1024);
	CStr(group,256);
	int anum;
	FILE *afp;

	if( anum = anomidToGroup(msgid,AVStr(group)) ){
		afp = fopen_article(NULL,group,anum,"r",AVStr(apath));
		return afp;
	}
	return NULL;
}

static int get_history(PCStr(msgid),PVStr(artpath),int all,int abspath)
{	CStr(histpath,256);
	FILE *hfp;
	CStr(line,256);
	const char *dp;
	CStr(vpath,256);
	CStr(apath,256);
	refQStr(lp,artpath); /**/
	CStr(xmsgid,256);
	FILE *afp;

	if( anomidToGroup(msgid,VStrNULL) ){
	  if( afp = open_anomid(msgid,"r") ){
		fgetsHeaderField(afp,"Message-ID",AVStr(xmsgid),sizeof(xmsgid));
		fclose(afp);
		if( *xmsgid == 0 ){
			return 0;
		}
		msgid = xmsgid;
	  }else{
		return 0;
	  }
	}

	if( (hfp = open_history(msgid,0)) == NULL )
		return 0;

	setVStrEnd(lp,0);
	while( fgets(line,sizeof(line),hfp) ){
		if( dp = strpbrk(line,"\r\n") )
			truncVStr(dp);
		if( lp != artpath )
			setVStrPtrInc(lp,' ');
		/*
		if( Xsscanf(line,"%s %s",AVStr(vpath),AVStr(apath)) != 2 )
		*/
		if( Xsscanf(line,"%s %[^\r\n]",AVStr(vpath),AVStr(apath)) != 2 )
			continue;
		if( abspath )
			strcpy(lp,apath);
		else	strcpy(lp,vpath);
		lp += strlen(lp);
		if( !all )
			break;
	}
	fclose(hfp);
	return 1;
}
int ENEWS_path(PCStr(msgid),PVStr(artpath),int is_filegroup)
{
	if( get_history(msgid,AVStr(artpath),1,is_filegroup) )
		return 1;
	else	return 0;
}

/*
#define fgetsHF(f,m,b) fgetsHeaderField(f,m,AVStr(b),sizeof(b))
*/

static const char *getartfmt(PCStr(grppath),PVStr(path),PVStr(fmt)){
	const char *dp;

	if( (dp = strrchr(grppath,':')) ){
		if( strchr("0123456789",dp[1]) ){
			if( path != NULL )
				XStrncpy(AVStr(path),grppath,dp-grppath+1);
			if( fmt != NULL )
				strcpy(fmt,dp+1);
			return dp;
		}
	}
	if( path != NULL )
		strcpy(path,grppath);
	if( fmt != NULL )
		strcpy(fmt,"");
	return NULL;
}

void putPosterHistory(PCStr(from),PCStr(group),int anum,PCStr(artpath));
static FILE *fopen_article(PCStr(msgid),PCStr(group),int anum,PCStr(mode),PVStr(artpath))
{	FILE *actfp,*artfp;
	CStr(grppath,LINESIZE);
	const char *artfmt;
	int min,max;
	CStr(msgidbuf,256);
	CStr(actline,1024);
	CStr(from,256);

	if( msgid ){
		if( get_history(msgid,AVStr(artpath),0,1) )
			return fopen(artpath,"r");
		if( artfp = open_anomid(msgid,"r") )
			return artfp;
		return NULL;
	}

	setVStrEnd(artpath,0);
	actfp = fopen_active(group,"r",NULL);
	if( actfp == NULL )
		return NULL;

	grppath[0] = 0;
	if( fgets(actline,sizeof(actline),actfp) != NULL )
		Xsscanf(actline,"%d %d %*d %*d %[^\r\n]",&min,&max,AVStr(grppath));
		/*
		Xsscanf(actline,"%d %d %*d %*d %s",&min,&max,AVStr(grppath));
		*/
	fclose(actfp);

	if( grppath[0] != '/' )
		if( !isFullpath(grppath) )
		return NULL;

	/*
	if( artfmt = strchr(grppath,':') ){
	*/
	if( artfmt = getartfmt(grppath,VStrNULL,VStrNULL) ){
		truncVStr(artfmt); artfmt++;
	}

	if( artfmt != NULL )
		sprintf(artpath,"%s/%03d/%02d",grppath,anum/100,anum%100);
	else	sprintf(artpath,"%s/%d",grppath,anum);

	if( mode[0] == 'r' && mode[1] == 0 )
		artfp = fopen(artpath,mode);
	else	artfp = dirfopen("SPOOL-ARTICLE",AVStr(artpath),mode);

	if( artfp == NULL )
		return NULL;

	fgetsHF(artfp,"Message-ID",msgidbuf);
	put_history(msgidbuf,group,anum,artpath);
	if( fgetsHF(artfp,ResentMid,msgidbuf) ){
		put_history(msgidbuf,group,anum,artpath);
	}

	if( fgetsHF(artfp,"From",from) ){
		putPosterHistory(from,group,anum,artpath);
	}

	return artfp;
}

FILE *ENEWS_article(PCStr(msgid),PCStr(group),int anum)
{	CStr(artpath,LINESIZE);
	FILE *afp;
	CStr(line,256);
	int off;

	if( afp = fopen_article(msgid,group,anum,"r",AVStr(artpath)) ){
		off = ftell(afp);
		if( fgets(line,sizeof(line),afp) != NULL )
		if( strncmp(line,"From ",5) != 0 )
			fseek(afp,off,0);
	}
	return afp;
}
static int getSeqno(FILE *afp)
{	CStr(seqno,512);

	if( fgetsHF(afp,"X-Seqno",   seqno)
	||  fgetsHF(afp,"X-Sequence",seqno)
	||  fgetsHF(afp,"X-Ml-Count",seqno)
	||  fgetsHF(afp,"Mail-Count",seqno)
	)
		return atoi(seqno);
	return 0;
}
int ENEWS_getSeqno(PCStr(head))
{	const char *seqno;

	if( (seqno = findFieldValue(head,"X-Seqno"))
	 || (seqno = findFieldValue(head,"X-Sequence"))
	 || (seqno = findFieldValue(head,"X-Ml-Count"))
	 || (seqno = findFieldValue(head,"Mail-Count"))
	)	return atoi(seqno);
	return 0;
}
int RFC822_getSeqno(FILE *afp){
	return getSeqno(afp);
}

static void addHeader(FILE *nfp,FILE *sfp,PCStr(newhead)){
	CStr(aline,LINESIZE);
	int inHead = 1;
	while( fgets(aline,sizeof(aline),sfp) ){
		if( inHead ){
			if( EOH(aline) ){
				fputs(newhead,nfp);
				inHead = 0;
			}
		}
		fputs(aline,nfp);
	}
}
/* Control: add-resent-message-id group num <message-id> */
static int controlMessage(PVStr(stat),FILE *afp){
	CStr(line,LINESIZE);
	CStr(com,LINESIZE);
	CStr(grp,LINESIZE);
	int num;
	CStr(mid,LINESIZE);
	CStr(rmid,LINESIZE);
	int rcode = 0;
	int off = ftell(afp);
	CStr(artpath,LINESIZE);
	CStr(nartpath,LINESIZE);
	CStr(oartpath,LINESIZE);
	FILE *sfp;
	FILE *nfp;
	int mtime;
	int an;

	while( fgets(line,sizeof(line),afp) != NULL ){
		if( strncmp(line,"Control:",8) != 0 ){
			continue;
		}
		an = Xsscanf(line+8,"%s %s %d <%[^>]>",AVStr(com),
			AVStr(grp),&num,AVStr(mid));
		if( an != 4 ){
			sv1log("##Control: Ignored: %s",line);
			continue;
		}
		truncVStr(artpath);
		sfp = fopen_article(NULL,grp,num,"r",AVStr(artpath));
		sv1log("Control: %s %s %d %s [%s]%X\n",com,grp,num,mid,
			artpath,p2i(sfp));
		if( sfp == NULL ){
			sv1log("##Control: not spooled: %s:%d\n",grp,num);
			strcpy(stat,"441 control message: bad article.\r\n");
			rcode = -1;
			continue;
		}
		if( fgetsHF(sfp,ResentMid,rmid) && strstr(rmid,mid) ){
			sv1log("##Control: already has %s: %s\n",ResentMid,mid);
		}else{
			CStr(newhead,LINESIZE);
			sprintf(newhead,"%s: <%s>\r\n",ResentMid,mid);
			mtime = file_mtime(fileno(sfp));
			sprintf(nartpath,"%s#",artpath);
			sprintf(oartpath,"%s~",artpath);
			if( nfp = fopen(nartpath,"w") ){
				addHeader(nfp,sfp,newhead);
				fclose(nfp);
				if( set_utimes(nartpath,0,mtime) == 0 ){
					rename(artpath,oartpath);
					if( rename(nartpath,artpath) == 0 )
						unlink(oartpath);
					else	rename(oartpath,artpath);
				}
			}
		}
		fclose(sfp);
		put_history(mid,grp,num,artpath);
		strcpy(stat,"240 processed control message.\r\n");
		rcode = 1;
	}
	fseek(afp,off,0);
	return rcode;
}

void copyheader(FILE *in,FILE *out,PVStr(eoh));
int ENEWS_post(PVStr(stat),FILE *afp,PCStr(agroup),PCStr(asubj),PCStr(afrom))
{	CStr(UnixFrom,LINESIZE);
	CStr(group,LINESIZE);
	CStr(From,LINESIZE);
	CStr(Subj,LINESIZE);
	CStr(msgid,LINESIZE);
	CStr(localid,512);
	CStr(host,LINESIZE);
	int now,Lines,Bytes,Sum,Xor,xorx;
	CStr(Date,128);
	CStr(line,LINESIZE);
	CStr(actline,1024);
	CStr(eoh,LINESIZE);
	FILE *actfp,*artfp;
	CStr(lactpath,LINESIZE);
	const char *lp; /* layered active file */
	int min,max,cdate,mdate,anum,ctime;
	CStr(artpath,LINESIZE);
	CStr(dir,LINESIZE);
CStr(lkpath,LINESIZE);
int lkfd;

/*
fprintf(stderr,"-------- Posting ...\n");
int off;
off = ftell(afp);
RFC821_skipheader(afp,stderr,NULL);
fseek(afp,off,0);
*/

	CStr(control,1024);
	if( fgetsHF(afp,"Control",control) ){
		int rcode;
		if( rcode = controlMessage(AVStr(stat),afp) )
			return rcode;
	}

	anum = ctime = 0;
	UnixFrom[0] = 0;
	fgetsHF(afp,"UNIX-From",UnixFrom);
	fgets(line,sizeof(line),afp);
	if( strncmp(line,"From ",5) == 0 )
		lineScan(line+5,UnixFrom);
	else	fseek(afp,0,0);

	if( UnixFrom[0] ){
		From[0] = Date[0] = 0;
		Xsscanf(UnixFrom,"%s %[^\r\n]",AVStr(From),AVStr(Date));
		ctime = scanUNIXFROMtime(Date);
		anum = getSeqno(afp);
		sv1log("POSTed with UNIX-From: %s\n",UnixFrom);
		sv1log("From:%s,Date:%s(%d),Anum:%d\n",From,Date,ctime,anum);
	}

	if( agroup[0] )
		strcpy(group,agroup);
	else	fgetsHF(afp,"Newsgroups",group);
	strip_spaces(group);
	if( group[0] == 0 ){
	    strcpy(stat,"441 Required \"Newsgroups\" header is missing.\r\n");
		return -1;
	}
	if( strncmp(group,GPREFIX,strlen(GPREFIX)) != 0 )
		return 0;
	ovstrcpy(group,group+strlen(GPREFIX));

	if( afrom[0] )
		strcpy(From,afrom);
	else	fgetsHF(afp,"From",From);
	if( From[0] == 0 ){
	    strcpy(stat,"441 Required \"From\" header is missing.\r\n");
		return -1;
	}
	if( asubj[0] )
		strcpy(Subj,asubj);
	else	fgetsHF(afp,"Subject",Subj);
	if( Subj[0] == 0 ){
	    strcpy(stat,"441 Required \"Subject\" header is missing.\r\n");
		return -1;
	}
	now = time(0);
	StrftimeGMT(AVStr(Date),sizeof(Date),TIMEFORM_USENET,now,0);

	actfp = fopen_active(group,"r+","w+");
	if( actfp == NULL ){
		sprintf(stat,"441 POST failed (no active).\r\n");
		return 1;
	}

NewsLibdir(AVStr(dir),ACTIVE_DIR);
Xsprintf(TVStr(dir),"/%s",group);
lkfd = getLocalLock(actfp,"/tmp",dir,AVStr(lkpath));
if( 0 <= lkfd ){
	sv1log("NFS-locallock[%d] %s\n",lkfd,lkpath);
	lock_exclusive(lkfd);
}else
	lock_exclusive(fileno(actfp));

	max = min = cdate = mdate = 0;
	dir[0] = 0;
	if( fgets(actline,sizeof(actline),actfp) != NULL )
		Xsscanf(actline,"%d %d %d %d %[^\r\n]",&min,&max,&cdate,&mdate,AVStr(dir));
		/*
		Xsscanf(actline,"%d %d %d %d %s",&min,&max,&cdate,&mdate,AVStr(dir));
		*/

	fseek(actfp,0,0);
	if( dir[0] != '/' )
		if( !isFullpath(dir) )
		default_spool(AVStr(dir),group);

	if( 0 < anum ){
		if( anum < min ) min = anum;
		if( max < anum ) max = anum;
	}else{
		max++;
		anum = max;
	}
	if( min == 0 )
		min = max;

	fprintf(actfp,"%05d %05d %d %d %s\n",min,max,cdate,mdate,dir);
	fclose(actfp);

if( 0 <= lkfd )
	close(lkfd);

	sv1log("ACTIVE[%s %d %d] %d %d %s\n",group,max,min,cdate,mdate,dir);

	if( artfp = fopen_article(NULL,group,anum,"r",AVStr(artpath)) ){
		fclose(artfp);
		sprintf(stat,"441 don't overwrite existing article (%d)\r\n",
			anum);
		return -1;
	}
	artfp = fopen_article(NULL,group,anum,"w+",AVStr(artpath));
	if( artfp == NULL ){
		sv1log("CAN'T SPOOL POSTED ARTICLE: %s\n",artpath);
		sprintf(stat,"441 can't create article file (%d)\r\n",anum);
		return -1;
	}
	sv1log("SPOOL POSTED ARTICLE: %s\n",artpath);

	fgetsHF(afp,"Message-ID",msgid);
	gethostFQDN(AVStr(host),sizeof(host));

	strip_msgid(msgid,AVStr(msgid));
	if( msgid[0] == 0 ){
		StrftimeLocal(AVStr(localid),sizeof(localid),"%H%M%S.%y%m%d",now,0);
		sprintf(msgid,"%s@%s",localid,host);
	}

	copyheader(afp,NULL,VStrNULL);
	Bytes = Sum = Xor = xorx = 0;
	for( Lines = 0; fgets(line,sizeof(line),afp) != NULL; Lines++ ){
		if( EOM(line) )
			break;
		for( lp = line; *lp; lp++ ){
			Sum += *lp;
			Xor ^= *lp << (xorx*8);
			if( 4 <= ++xorx )
				xorx = 0;
		}
		Bytes += strlen(line);
	}

	fprintf(artfp,"Xref: %s %s:%d\r\n",host,group,anum);
	fprintf(artfp,"Subject: %s\r\n",Subj);
	fprintf(artfp,"From: %s\r\n",From);
	fprintf(artfp,"Date: %s\r\n",Date);
	fprintf(artfp,"Message-ID: <%s>\r\n",msgid);
	fprintf(artfp,"Lines: %d\r\n",Lines);
	fprintf(artfp,"X-CheckSum: %d %d %x\r\n",Bytes,Sum,Xor);
	fprintf(artfp,"Newsgroups: %s\r\n",group);

	fseek(afp,0,0);
	copyheader(afp,artfp,AVStr(eoh));
	if( eoh[0] == '\r' || eoh[0] == '\n' )
		fputs(eoh,artfp);

	RFC821_skipbody(afp,artfp,VStrNULL,0);
	fflush(artfp);
	fseek(artfp,0,0);

	put_history(msgid,group,anum,artpath);

	linkArticle(artfp,group,anum,artpath,msgid,host);
	fclose(artfp);
	set_utimes(artpath,0,ctime);

	sprintf(stat,"240 Article posted locally (%d)<%s>.\r\n",anum,msgid);
	return 1;
}

void copyheader(FILE *in,FILE *out,PVStr(eoh))
{	CStr(line,LINESIZE);
	CStr(fname,LINESIZE);
	int putit;

	putit = 1;
	if( eoh != NULL )
		setVStrEnd(eoh,0);

	while( fgets(line,sizeof(line),in) != NULL ){
		if( EOM(line) )
			break;
		if( EOH(line) ){
			if( eoh != NULL )
				strcpy(eoh,line);
			break;
		}
		if( line[0] == ' ' || line[0] == '\t' ){
			if( !putit )
				continue;
		}else{
			Xsscanf(line,"%[^:]",AVStr(fname));
			if( strcasecmp(fname,"Xref") == 0
			 || strcasecmp(fname,"Subject") == 0
			 || strcasecmp(fname,"From") == 0
			 || strcasecmp(fname,"Date") == 0
			 || strcasecmp(fname,"Message-ID") == 0
			 || strcasecmp(fname,"Lines") == 0
			 || strcasecmp(fname,"Newsgroups") == 0
			){
				putit = 0;
				continue;
			}else	putit = 1;
		}
		if( out != NULL )
			fputs(line,out);
	}
}
static void strip_msgid(PCStr(src),PVStr(dst))
{	const char *dp;

	if( src[0] == '<' ){
		ovstrcpy((char*)dst,src+1);
		if( dp = strchr(dst,'>') )
			truncVStr(dp);
	}else
	if( src != dst )
		strcpy(dst,src);
}

static scanDirFunc minmax(PCStr(file),PCStr(dir),int *min,int *max)
{	int num;

	num = atoi(file);
	if( 0 < num || file[0] == '0' ){
		if( *min < 0 || num < *min )
			*min = num;
		if( *max < 0 || *max < num )
			*max = num;
	}
	return 0;
}

static int find_minmax(PCStr(dirpath),PCStr(artfmt),int *max,int *min);
static int make_active(PCStr(group),int *max,int *min,int *cdate,int *mdate,PVStr(dir))
{	CStr(artpath1,1024);
	CStr(dirpath,1024);
	CStr(artfmt,32);

	*max = *min = -1;
	*mdate = 0;
	if( dir[0] != '/' )
		if( !isFullpath(dir) )
		default_spool(AVStr(dir),group);

	artfmt[0] = 0;
	getartfmt(dir,AVStr(dirpath),AVStr(artfmt));
	/*
	Xsscanf(dir,"%[^:]:%s",AVStr(dirpath),AVStr(artfmt));
	*/

	newPath(AVStr(dirpath));
	*mdate = File_mtime(dirpath);
	if( *cdate <= 0 )
		*cdate = *mdate;

	return find_minmax(dirpath,artfmt,max,min);
}
static int find_minmax(PCStr(dirpath),PCStr(artfmt),int *max,int *min){
	int xmin,xmax;
	CStr(sdir,1024);

	Scandir(dirpath,scanDirCall minmax,dirpath,min,max);
	if( artfmt[0] && 0 <= *min && 0 <= *max ){
		xmin = xmax = -1;
		sprintf(sdir,"%s/%03d",dirpath,*min);
		Scandir(sdir,scanDirCall minmax,sdir,&xmin,&xmax);
		*min = *min * 100 + xmin;
		/* should treat the case where the directory is empty ... */

		xmin = xmax = -1;
		sprintf(sdir,"%s/%03d",dirpath,*max);
		Scandir(sdir,scanDirCall minmax,sdir,&xmin,&xmax);
		*max = *max * 100 + xmax;
		/* should treat the case where the directory is empty ... */
	}
	if( *max < 0 ) *max = 0;
	if( *min < 0 ) *min = 0;
	return 1;
}
int ENEWS_active(PCStr(spool),PCStr(artfmt),int *max,int *min){
	*max = 0;
	*min = 0;
	return find_minmax(spool,artfmt,max,min);
}

static int addgroup(PCStr(actdir),PCStr(group),int *max,int *min,int *cdate,int *mdate,PVStr(dir))
{	int ok;
	FILE *afp;
	CStr(actpath,1024);
	CStr(dirbuf,1024);
	CStr(dirpath,1024);
	CStr(actline,1024);

	sprintf(actpath,"%s/%s",actdir,group);

	ok = 0;
	if( afp = fopen(actpath,"r") ){
		dirbuf[0] = 0;
		if( fgets(actline,sizeof(actline),afp) != NULL )
		/*
		if( Xsscanf(actline,"%d %d %d %d %s",min,max,cdate,mdate,AVStr(dirbuf))
		*/
		if( Xsscanf(actline,"%d %d %d %d %[^\r\n]",min,max,cdate,mdate,AVStr(dirbuf))
		 == 5 ){
/*
			Xsscanf(dirbuf,"%[^:]",AVStr(dirpath));
*/
			getartfmt(dirbuf,AVStr(dirpath),VStrNULL);
			if( dir[0] && strcmp(dir,dirbuf) != 0 )
				syslog_ERROR("#### spool moved ? %s -> %s\n",
					dirbuf,dir);
			else{
				if( dir[0] == 0 )
					strcpy(dir,dirbuf);
				newPath(AVStr(dirpath));
				if( File_mtime(dirpath) == *mdate )
					ok = 1;
			}
		}
		fclose(afp);
	}

	if( ok == 0 )
	if( ok = make_active(group,max,min,cdate,mdate,AVStr(dir)) )
	if( afp = dirfopen("ACTIVE-FILE1",AVStr(actpath),"w") ){
		fprintf(afp,"%05d %05d %d %d %s\n",*min,*max,*cdate,*mdate,dir);
		fclose(afp);
	}
	return ok;
}
void ENEWS_addspool(PCStr(dir),int recursive)
{	int max,min,cdate,mdate;
	CStr(dirbuf,1024);
	CStr(group,1024);
	CStr(actdir,1024);

	strcpy(dirbuf,dir);
	NewsLibdir(AVStr(actdir),ACTIVE_DIR);
	file2group(dir,AVStr(group));
	addgroup(actdir,group,&max,&min,&cdate,&mdate,AVStr(dirbuf));
}

typedef struct {
  const	char	*dir;
	FILE	*out;
	int	 wcc;
	int	 is_filegroup;
	int	 date;
} Lista;

static scanDirFunc list1(PCStr(file),Lista *larg)
{	CStr(act1,LINESIZE);
	CStr(dir,LINESIZE);
	int max,min,cdate,mdate,ok;
	FILE *afp;
	CStr(group,LINESIZE);

	if( file[0] == '.' )
		return 0;
	if( strncmp(file,FGPREFIX,strlen(FGPREFIX))==0 )
	if( !larg->is_filegroup )
		return 0;

	cdate = 0;
	dir[0] = 0;
	ok = addgroup(larg->dir,file,&max,&min,&cdate,&mdate,AVStr(dir));

	if( ok )
	if( larg->date < cdate )
	{
		if( max < 0 ) max = 0;
		if( min < 0 ) min = 0;
		if( strncmp(file,FGPREFIX,strlen(FGPREFIX))==0 )
			strcpy(group,dir);
		else	sprintf(group,"%s%s",GPREFIX,file);
		sprintf(act1,"%s %d %d y\r\n",group,max,min);
		fputs(act1,larg->out);
		larg->wcc += strlen(act1);
	}
	return 0;
}

int ENEWS_listX(FILE *out,int is_filegroup,int date)
{	Lista larg;
	CStr(actdir,LINESIZE);

	NewsLibdir(AVStr(actdir),ACTIVE_DIR);
	sv1log("NEWSLIB-ACTIVE: %s\n",actdir);

	larg.out = out;
	larg.dir = actdir;
	larg.wcc = 0;
	larg.is_filegroup = is_filegroup;
	larg.date = date;

	Scandir(actdir,scanDirCall list1,&larg);
	return larg.wcc;
}
int ENEWS_list(FILE *out,int is_filegroup)
{
	return ENEWS_listX(out,is_filegroup,0);
}

int ENEWS_group(PCStr(group),int *total,int *min,int *max)
{	FILE *afp;

	if( strncmp(group,GPREFIX,strlen(GPREFIX)) )
		return 0;

	if( afp = fopen_active(group,"r",NULL) ){
		*total = *min = *max = 0;
		IGNRETP fscanf(afp,"%d %d",min,max);
		fclose(afp);
		*total = *max - *min;
		if( *total < 0 || (*min == 0 && *max == 0) )
			*total = 0;
		else	*total += 1;
		return 1;
	}
	return 0;
}

int fbsearch(PCStr(group),int min,int max,int date)
{	int mean,mdate;
	CStr(apath,1024);
	FILE *afp;

	if( max == min )
		return max;
	mean = (max + min) / 2;
	if( mean == max || mean == min )
		return mean;

	if( afp = fopen_article(NULL,group,mean,"r",AVStr(apath)) ){
		mdate = File_mtime(apath);
		fclose(afp);
	}else{
		mdate = 0;
	}
	if( mdate == date )
		return mean;
	if( mdate < date )
		return fbsearch(group,mean,max,date);
	else	return fbsearch(group,min,mean,date);
}

void ENEWS_newnews(FILE *out,PCStr(group),int date)
{	int total,min,max,hit,mi;
	FILE *afp;
	CStr(msgid,1024);

	ENEWS_group(group,&total,&min,&max);
	hit = fbsearch(group,min,max,date);
	for( mi = hit; mi <= max; mi++ ){
		if( afp = ENEWS_article(NULL,group,mi) ){
			fgetsHF(afp,"Message-ID",msgid);
			fprintf(out,"%s\r\n",msgid);
			fclose(afp);
		}
	}
}


/*
 * mapping a Message-ID to the server local one
 *   mail-lists.gggggg:nnnnn <-> <_Annnnn@gggggg.ML_>
 */
typedef struct {
	const char *m_lg;
	const char *m_sg;
} MidMap;
static MidMap midMap[] = {
	{"mail-lists.", ".ML_"}, /* should be like "mail-lists.* <-> *.ML_" */
	0
};
#define mmLg(x)		midMap[x].m_lg
#define mmLgLen(x)	strlen(mmLg(x))
#define mmSg(x)		midMap[x].m_sg

extern const char *MIME_mapPosterBase;
int strCRC32(PCStr(str),int len);
int enBase32(PCStr(src),int sbits,PVStr(dst),int dsiz);
char mailClientId[16];
char mailClientAddr[32];
char mailPosterId[16];

int mappedMailAddr(PVStr(sgr),int siz,PCStr(group),int anum){
	CStr(bgr,5);
	const char *gp;
	int gnum;

	if( strncmp(group,mmLg(0),mmLgLen(0)) == 0 )
		gp = group + mmLgLen(0);
	else	gp = group;

	gnum = 0xFFFF & (strCRC32(gp,strlen(gp))>>16);
	setVStrElem(bgr,4,0xFF&(gnum>>8));
	setVStrElem(bgr,3,(0xFF&(gnum))^(0xFF&(anum>>24)) );
	setVStrElem(bgr,2,0xFF&(anum>>16));
	setVStrElem(bgr,1,0xFF&(anum>>8));
	setVStrElem(bgr,0,0xFF&(anum));
	enBase32(bgr,5*8,AVStr(sgr),siz);
	strtolowerX(sgr,BVStr(sgr),siz);
	return 0;
}
void putPosterHistory(PCStr(from),PCStr(group),int anum,PCStr(artpath)){
	CStr(maddr,256);
	CStr(msgidbuf,256);

	RFC822_addresspartX(from,AVStr(maddr),sizeof(maddr));
	sprintf(msgidbuf,"%s.poster",maddr);
	put_history1st(msgidbuf,group,anum,artpath);
}
int _mapPosterAddr(PCStr(addr),PVStr(xaddr)){
	CStr(msgid,256);
	CStr(apath,1024);
	refQStr(ap,apath);
	int anum;
	CStr(sgr,16);
	const char *ma = MIME_mapPosterBase;

	sprintf(msgid,"<%s.poster>",addr);
	if( ENEWS_path(msgid,AVStr(apath),0) ){
		if( ap = strchr(apath,' ') ){
			setVStrEnd(ap,0);
		}
		if( ap = strrchr(apath,'/') ){
			setVStrEnd(ap,0);
			anum = atoi(ap+1);
			strsubst(AVStr(apath),"/",".");
			mappedMailAddr(AVStr(sgr),sizeof(sgr),apath,anum);
			if( streq(mailClientAddr,"127.0.0.1")
			 || strneq(mailClientAddr,"192.168.1",9) )
				sprintf(xaddr,"p%s.%s",sgr,ma);
			else	sprintf(xaddr,"p%s-%s.%s",sgr,mailClientId,ma);
			Xstrcpy(FVStr(mailPosterId),sgr);
			return 1;
		}
	}
	return 0;
}
int (*MIME_mapPosterAddr)(PCStr(maddr),PVStr(xmaddr)) = _mapPosterAddr;

int _mapMessageId(PCStr(xref),PCStr(msgid),PVStr(xmsgid)){
	CStr(apath,1024);
	refQStr(ap,apath);
	int anum;

	sprintf(xmsgid,"<%s>",msgid);
	if( strncmp(xref,mmLg(0),mmLgLen(0)) == 0 ){
		strcpy(apath,xref);
		if( ap = strchr(apath,':') ){
			setVStrPtrInc(ap,0);
			anum = atoi(ap);
			sprintf(xmsgid,"_A%d@%s%s",anum,apath+mmLgLen(0),mmSg(0));
			return 1;
		}
	}
	if( ENEWS_path(msgid,AVStr(apath),0) ){
		if( ap = strchr(apath,' ') ){
			setVStrEnd(ap,0);
		}
		if( ap = strrchr(apath,'/') ){
			setVStrEnd(ap,0);
			anum = atoi(ap+1);
			strsubst(AVStr(apath),"/",".");
			if( strncmp(apath,mmLg(0),mmLgLen(0)) == 0 )
				ap = apath + mmLgLen(0);
			else	ap = apath;
			sprintf(xmsgid,"_A%d@%s%s",anum,ap,mmSg(0));
			return 1;
		}
	}
	return 0;
}
int (*MIME_mapMessageId)(PCStr(xref),PCStr(msgid),PVStr(xmsgid)) = _mapMessageId;

int anomidToGroup(PCStr(msgid),PVStr(rgroup)){
	const char *mid;
	const char *dp;
	int anum;

	mid = msgid;
	if( *mid == '<' )
		mid++;
	if( dp = strstr(mid,"@-group.") ){
		if( rgroup ){
			truncVStr(rgroup);
			Xsscanf(dp+8,"%[^>]",BVStr(rgroup));
		}
		return atoi(mid);
	}
	if( strneq(mid,"_A",2) && (anum = atoi(mid+2)) )
	if( strstr(mid,mmSg(0)) ){
		if( dp = strchr(mid,'@') ){
			if( rgroup ){
				strcpy(rgroup,dp+1);
				if( dp = strstr(rgroup,mmSg(0)) )
				if( dp[4] == 0 || dp[4] == '>' )
					truncVStr(dp);
				Strins(BVStr(rgroup),mmLg(0));
			}
			return anum;
		}
	}
	return 0;
}

