/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1999-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2007 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	ssi.c (SSI and META processor)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

	<META HTTP-EQUIV="Status" content=status-line> ... for CGI compati.
	<!--#include file=requeste/response> ... for CFI

	original-SSI = http://hoohoo.ncsa.uiuc.edu/docs/tutorials/includes.html
	SSI+ = http://www.carleton.ca/~dmcfet/html/ssi3.html
	SPML = http://www.apache.org/docs/mod/mod_include.html

History:
	990802	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <ctype.h>
#include "ystring.h"
#include "dglib.h"
#include "fpoll.h"
#include "file.h"
#include <fcntl.h> /* for open() */
#include "url.h"
#include "log.h"
#define MY_HTTPVER "1.1"

extern int URICONV_nFULL;
extern int TAGCONV_SSI;
extern int TAGCONV_META;
extern int TAGCONV_XML;
double SSI_TIMEOUT = 30;

typedef struct {
	int	h_headput;
	int	h_hleng;
	FILE   *h_savfp;
	const char *t_tagp;
	const char *t_attrp;
	int	h_favgot;
	int	h_fac;
	const char *h_fav[64];
	MStr(	h_url,4096);
	double	f_timeout;
	MStr(	f_timefmt,64);
	MStr(	f_sizefmt,32);
	MStr(	f_counterfmt,256);
	MStr(	h_status,1024);
	MStr(	h_contype,128);
	MStr(	h_header,4096);
	MStr(	h_incctype,128); /* HTTP Content-Type of included data */

	const char *h_basefile; /* abs. path of the current SSI file */
	MStr(	h_pushbase,256); /* pushbase/popbase ... should be upath */
	MStr(	h_pushcwd,256); /* pushbase/popbase */
	int	h_outsupp; /* suppress SSI */

	MStr(	h_vbase,1024); /* v9.9.11 base url by vbase=URL */
	FILE   *m_body;
} Mssg;

#define ssi_timefmt (mssg->f_timefmt[0]?mssg->f_timefmt:TIMEFORM_RFC822)
#define ssi_sizefmt mssg->f_sizefmt

/*
static struct {
} SSIenvs[] = {
};
*/

static struct {
  const	char	*n_ssi;
  const	char	*n_cgi;
} cgi_equiv[] = {
	{"REFERRER",		"HTTP_REFERER"	},
	{"DOCUMENT_NAME",	"SCRIPT_NAME"	},
	{"DOCUMENT_URI",	"REQUEST_URI"	},
	0,
};

#define Fav mssg->h_fav
#define Fac mssg->h_fac
#define getFav(nam)	(setupFav(ctx,mssg,__LINE__),getv(Fav,nam))

int getParam(PVStr(params),PCStr(name),PVStr(val),int siz,int del);
CCXP CCXtoCL(DGC*ctx);
int CCXwithEUCX(DGC*ctx);
void CCXnoeucx(CCXP ccx,int noeucx);
void CCXnojisx(CCXP ccx,int nojisx);
int CCXinURL(CCXP ccx,int inURL);
int HTTP_originalURLPath(DGC*ctx,PVStr(path));
int HTTP_originalURLx(DGC*ctx,PVStr(url),int siz);
void Form_conv_namevalue(int argc,const char *argv[]);
char *HTTP_originalRequestField(DGC*ctx,PCStr(fname),PVStr(buff),int bsize);
const char *HTTP_originalReqBody(DGC*ctx);
const char *HTTP_detectReqCharcode(DGC*ctx,PCStr(iqcharcode));
int form2v(PVStr(form),int maxargc,const char *argv[]);
int formdata2v(PCStr(ctype),PVStr(form),int maxargc,const char *argv[]);
const char *MountSSIpath(DGC*ctx,PVStr(url));
void set_VBASE(DGC*ctx,PCStr(url),PVStr(buff));
void push_VBASE(DGC*ctx,void *sav,int siz);
void pop_VBASE(DGC*ctx,void*sav);

const char *relative_path(PCStr(base),PCStr(path)){
	const char *bp = base;
	const char *pp = path;
	const char *xp;

	for(; *bp && *pp; bp++,pp++ ){
		if( *pp == '/' || *pp == '\\' ){
			xp = pp + 1;
		}
		if( *bp == '/' && *pp == '\\' )
		if( *bp == '\\' && *pp == '/' ){
			continue;
		}
		if( *bp == *pp ){
			continue;
		}
	}
	if( *bp == 0 || strpbrk(bp,"/\\") == 0 ){
		return xp;
	}else{
		return 0;
	}
}
/*
 * read and substitute the pathe name ".lnk"
 */
int readlink_lnk(PVStr(path)){
	IStr(lpath,1024);
	refQStr(lp,lpath);
	int lfd;
	int rcc;
	IStr(link,1024);
	const char *lnkp;

	if( File_is(path) ){
		return 0;
	}
	sprintf(lpath,"%s.lnk",path);

	if( (lfd = open(lpath,0)) < 0 ){
		return -1;
	}
	rcc = read(lfd,link,sizeof(link));
	close(lfd);

	if( rcc <= 0 ){
		return -2;
	}
	if( link[0] != 'L' ){
		return -3;
	}
	for( lnkp = link+rcc; link < lnkp && lnkp[-1] != 0; lnkp-- );
	if( lp = strrchr(lpath,'/') ){
		truncVStr(lp);
	}
	chdir_cwd(AVStr(lpath),lnkp,0);
	if( File_is(lpath) ){
		strcpy(path,lpath);
		return 1;
	}else{
		return -4;
	}
}
int chdir_lnk(PCStr(base),PCStr(dir),FILE *out){
	IStr(xdir,1024);
	refQStr(xp,xdir);
	int rcode;

	strcpy(xdir,base);
	readlink_lnk(AVStr(xdir));

	if( fileIsdir(xdir) ){
	}else
	if( xp = strrchr(xdir,'/') ){
		truncVStr(xp);
		readlink_lnk(AVStr(xdir));
		if( !fileIsdir(xdir) ){
			sv1log("##SSI ERR-A chdir(%s)[%s]\n",dir,base);
			if( out ){
				fprintf(out,"(cannot-chdir-A)");
			}
			return -1;
		}
	}
	chdir_cwd(AVStr(xdir),dir,1);
	readlink_lnk(AVStr(xdir));

	/* should check if the xdir is permitted to be accessed */
	/*
	if( 0 ){
		IStr(rurl,1024);
		IStr(vurl,1024);
		const char *opts;
		sprintf(rurl,"file:%s",xdir);
		opts = CTX_mount_url_fromL(MainConn(),AVStr(vurl),"http",
			"localhost:9999",rurl,NULL,"http","-.-");
		sv1log("####URL %X[%s] %s\n",opts,vurl,rurl);
	}
	*/
	/*
	if( relative_path(base,xdir) == 0 ){
		sv1log("##SSI ERR-B chdir(%s)[%s]\n",xdir,base);
		return -2;
	}
	*/

	rcode = chdir(xdir);
	if( rcode != 0 ){
		sv1log("##SSI ERR-C chdir(%s)[%s]\n",dir,base);
		if( out ){
			fprintf(out,"(cannot-chdir-B)");
		}
		return -3;
	}
	sv1log("##SSI OK chdir(%s) [%s][%s]\n",xdir,dir,base);
	return 0;
}

int CCX_file(CCXP ccx,FILE *fp,FILE *tmp){
	CStr(ib,2*1024);
	CStr(ob,8*1024);
	int ic,oc,occ;

	occ = 0;
	while( 0 < (ic = fread(ib,1,sizeof(ib),fp)) ){
		oc = CCXexec(ccx,ib,ic,AVStr(ob),sizeof(ob));
		fwrite(ob,1,oc,tmp);
		occ += oc;
	}
	oc = CCXexec(ccx,"",0,AVStr(ob),sizeof(ob));
	fwrite(ob,1,oc,tmp);
	occ += oc;
	return occ;
}

static void setupFav(DGC*ctx,Mssg *mssg,int where){
	refQStr(ap,mssg->h_url);
	refQStr(ep,mssg->h_url);
	const char *bp;
	IStr(ctype,256);

	if( mssg->h_favgot ){
		return;
	}
	mssg->h_favgot = where;
	Fac = 0;
	Fav[0] = 0;

	setVStrEnd(mssg->h_url,0);
	HTTP_originalURLPath(ctx,AVStr(mssg->h_url));
	ep = mssg->h_url + strlen(mssg->h_url) + 1;
	if( ap = strchr(mssg->h_url,'?') ){
		ap++;
		Fac = form2v(AVStr(ap),elnumof(Fav),Fav);
		Form_conv_namevalue(Fac,Fav);
	}
	if( (bp = HTTP_originalReqBody(ctx)) && *bp != 0 ){
		strcpy(ep,bp);
		HTTP_originalRequestField(ctx,"Content-Type",AVStr(ctype),
			sizeof(ctype));
		if( strncaseeq(ctype,"multipart/form-data",19) ){
			Fac = formdata2v(ctype,AVStr(ep),elnumof(Fav),Fav);
		}else	Fac = form2v(AVStr(ep),elnumof(Fav),Fav);
		Form_conv_namevalue(Fac,Fav);
	}
}

extern const char *COOKIE_CLCC;
void CTXsetCCX_TOCL(DGC*ctx,CCXP ccx,PCStr(ocs));
int CCX_setindflt(CCXP ccx,PCStr(from));

static int evalvar(DGC*ctx,Mssg *mssg,PCStr(fmt),PVStr(xval)){
	refQStr(dp,xval);
	const char *fp;
	const char *val;
	int fc;
	int nx = 0;
	IStr(nam,128);
	IStr(cnd,512);

	for( fp = fmt; fc = *fp; fp++ ){
		if( fc == '$' ){
			nx++;
			truncVStr(nam);
			truncVStr(cnd);
			if( fp[1] == '{' ){
				fp = wordScanY(fp+2,nam,"^:}");
				if( *fp == ':' ){
					fp = wordScanY(fp+1,cnd,"^}");
				}
			}else{
				fp = wordScan(fp+1,nam);
			}
			if( streq(nam,"request.charcode") ){
				const char *ie;
				if( (ie = getFav("INCHARCODE")) == 0 )
					ie = getFav("ie");
				val = HTTP_detectReqCharcode(ctx,ie);
			}else
			val = getFav(nam);
			switch( cnd[0] ){
				case '+':
					if( val && *val )
						val = cnd+1;
					else	val = 0;
					break;
				case '-':
					if( val == 0 || *val == 0 )
						val = cnd+1;
					break;
			}
			if( val ){
				strcpy(dp,val);
				dp += strlen(dp);
			}
			if( *fp == 0 )
				break;
			continue;
		}
		setVStrPtrInc(dp,fc);
	}
	setVStrPtrInc(dp,0);
	return nx;
}
static void setupCCX(DGC*ctx,Mssg *mssg,PCStr(val)){
	CCXP ccx = CCXtoCL(ctx);
	const char *ocs = 0;

	if( lCHARSET() ){
		CCXoutcharset(ccx,&ocs);
		sv1log("{C} SSI CHARSET=[%s] <- [%s]\n",val,ocs?ocs:"");
	}
	if( CCXguessing(ccx) && (val[0]==0 || strcaseeq(val,"guess")) ){
		/* don't clear guessing status which might be setup by
		 * INCHARCODE, and to be conveyed in charset
		 */
	}else{
	CCXclear(ccx);
	}
	if( val[0] ){
		CTXsetCCX_TOCL(ctx,ccx,val);
		CCXinURL(ccx,1);
		if( !CCXwithEUCX(ctx) ){
			CCXnoeucx(ccx,1);
			CCXnojisx(ccx,1);
		}
	}
}
int strtoB64(PCStr(str),int slen,PVStr(b64),int bsiz,int withnl);
int strtoHex(PCStr(str),int len,PVStr(out),int siz);
static void formValue(DGC*ctx,PCStr(val),PCStr(fmt),PVStr(fval),int fsiz){
	IStr(xval,4*1024);
	int opts;
	CCXP ccx;

	if( streq(fmt,"raw") ){
		strcpy(fval,val);
		return;
	}

	if( strneq(fmt,"orig-",5) ){
		strcpy(xval,val);
		fmt += 5;
	}else
	if( streq(fmt,"origurl") || streq(fmt,"orightml") ){
		strcpy(xval,val);
	}else{
		ccx = CCXtoCL(ctx);
		if( CCXactive(ccx) ){
			CCXexec(ccx,val,strlen(val),AVStr(xval),sizeof(xval));
			CCXexec(ccx,"",0,TVStr(xval),sizeof(xval)-strlen(xval));
		}else{
			strcpy(xval,val);
		}
	}

	if( streq(fmt,"orightml") ){
		if( strstr(xval,"&#") ){
			strcpy(fval,xval);
			strsubst(AVStr(fval),"&#","&amp;#");
		}else{
			strcpy(fval,"");
		}
	}else
	if( streq(fmt,"url") || streq(fmt,"origurl") ){
		url_escapeX(xval,BVStr(fval),fsiz,"%U/?_+&'\"<>#:;(){}[]|!\\$.,","");
	}else
	if( streq(fmt,"hex") ){
		strtoHex(xval,strlen(xval),BVStr(fval),fsiz);
	}else
	if( streq(fmt,"base64") ){
		strtoB64(xval,strlen(xval),BVStr(fval),fsiz,0);
	}else{
		if( streq(fmt,"text") )
			opts = HT_ISFORM;
		else	opts = 0;
		encodeEntitiesXX(xval,BVStr(fval),fsiz,opts);
	}
}
void HTTP_fprintmsgX(DGC*ctx,FILE *fp,PCStr(fmt),int opts);

int scanAttr1(PCStr(tag),int an,PCStr(nam),PVStr(val),int siz);
void SSI_config(DGC*ctx,const char *ev[],PCStr(tag),PCStr(type),PCStr(fmt),FILE *htfp,Mssg *mssg)
{
	IStr(val,256);
	IStr(xval,256);

	if( strcaseeq(type,"var") && streq(fmt,"timeout") ){
		if( scanAttr1(mssg->t_attrp,4,"val",AVStr(val),sizeof(val)) ){
			sscanf(val,"%lf",&mssg->f_timeout);
		}
	}else
	if( strcaseeq(type,"timefmt") )
		lineScan(fmt,mssg->f_timefmt);
	else
	if( strcaseeq(type,"sizefmt") )
		lineScan(fmt,mssg->f_sizefmt);
	else
	if( strcaseeq(type,"var") ){
		if( scanAttr1(mssg->t_attrp,4,"val",AVStr(val),sizeof(val)) ){
			if( evalvar(ctx,mssg,val,AVStr(xval)) ){
				strcpy(val,xval);
			}
			if( streq(fmt,"counterfmt") )
				strcpy(mssg->f_counterfmt,val);
			else
			if( streq(fmt,"CHARCODE") || streq(fmt,"oe") ){
				setupCCX(ctx,mssg,val);
			}
			else
			if( streq(fmt,"INCHARCODE") || streq(fmt,"ie") ){
				wordScan(val,xval);
				if( *xval ){
					sv1log("{C} SSI %s=%s\n",fmt,xval);
					CCX_setindflt(CCXtoCL(ctx),xval);
				}
			}
			else
			if( streq(fmt,"suppress") ){
				/* should be replaced with <!--#if 0 --> */
				if( streq(val,"on") ){
					mssg->h_outsupp = 1;
				}else{
					mssg->h_outsupp = 0;
				}
				fflush(mssg->m_body);
			}
			else
			if( strcaseeq(fmt,"vbase") ){ /* v9.9.11 new-140809f */
				set_VBASE(ctx,val,AVStr(mssg->h_vbase));
			}
		}
	}
	else{
		fprintf(mssg->m_body,"(SSI-UNKNOWN-config-%s)",type);
	}
}

int HTTP_originalURLPath(DGC*ctx,PVStr(path));
int HTTP_originalURLx(DGC*ctx,PVStr(url),int siz);

int scanAttrs(PCStr(src),int an,PCStr(nam1),PVStr(val1),int vsiz1,PCStr(nam2),PVStr(val2),int vsiz2);
int scanAttr1(PCStr(tag),int an,PCStr(nam),PVStr(val),int siz){
	int vn = 0;
	const char *tp;
	char tc;

	setVStrEnd(val,0);
	if( tag == 0 || *tag == 0 )
		return 0;
	if( *tag == '<' ){
		for( tp = tag; tc = *tp; tp++ ){
			if( tc == '>' )
				break;
			if( isspace(tc) ){
				tag = tp + 1;
				break;
			}
		}
	}
	vn = scanAttrs(tag,an,nam,BVStr(val),siz,NULL,VStrNULL,0);
	return vn;
}

extern char *STACK_BASE;
static void basedir(PCStr(path));
static int SSIfilepath(DGC*ctx,const char *ev[],PCStr(file),PVStr(path));
static int SSIfilepathX(DGC*ctx,Mssg *mssg,const char *ev[],PCStr(file),PVStr(path));
int scan_COUNTER1(DGC*ctx,int COUNTER,PCStr(spec));
static int SSI_getenv(DGC*ctx,const char *ev[],PCStr(tag),PCStr(type),PCStr(ename),FILE *htfp,Mssg *mssg,PVStr(buff),int size)
{	const char *sname;
	const char *cname;
	const char *eval;
	int ni;
	const char *tagp = mssg->t_tagp;
	const char *attrp = mssg->t_attrp;
	const char *timefmt = mssg->f_timefmt;
	CStr(url,1024);
	CStr(fmt,1024);
	IStr(nam,1024);
	IStr(arg,1024);
	const char *val;

	truncVStr(arg);
	Xsscanf(ename,"%[^.].%[^\n]",AVStr(nam),AVStr(arg));
	if( strncaseeq(nam,"-formv",6) ){
		if( val = getFav(arg) ){
			formValue(ctx,val,nam+6,AVStr(buff),size);
		}else	strcpy(buff,"");
		return strlen(buff);
	}

	setVStrEnd(buff,0);
	if( strcaseeq(ename,"STACK_DEPTH") ){ /* v9.9.12 new-140817l */
		sprintf(buff,"%u",(unsigned int)(((Int64)STACK_BASE)-((Int64)&val)));
	}else
	if( strcaseeq(ename,"DATE_GMT") ){
		StrftimeGMT(AVStr(buff),size,ssi_timefmt,time(0),0);
	}else
	if( strcaseeq(ename,"DATE_LOCAL") ){
		StrftimeLocal(AVStr(buff),size,ssi_timefmt,time(0),0);
	}else
	if( strcaseeq(ename,"LAST_MODIFIED") ){
		StrftimeGMT(AVStr(buff),size,ssi_timefmt,file_mtime(fileno(htfp)),0);
	}else
	if( strcaseeq(ename,"REFERER_COUNT") ){
		if( scanAttr1(attrp,4,"url",AVStr(url),sizeof(url)) == 0 )
			strcpy(url,"none");
		if( scanAttr1(attrp,4,"fmt",AVStr(fmt),sizeof(fmt)) == 0 )
		{
			if( mssg->f_counterfmt[0] )
				strcpy(fmt,mssg->f_counterfmt);
			else
			strcpy(fmt,"%N");
		}
		strfCounter(ctx,CNT_REFERER,url,fmt,timefmt,AVStr(buff),size);
	}else
	if( strcaseeq(ename,"PAGE_COUNT")
	 || strcaseeq(ename,"COUNTER")
	 || strcaseeq(ename,"BCOUNTER")
	){
		int flags = CNT_ACCESS|CNT_SSIPAGE;
		CStr(sel,128);
		if( scanAttr1(attrp,4,"sel",AVStr(sel),sizeof(sel)) != 0 ){
			flags = scan_COUNTER1(ctx,0,sel);
			if( flags == 0 ){
				flags = CNT_ACCESS|CNT_SSIPAGE;
			}
		}
		if( scanAttr1(attrp,4,"url",AVStr(url),sizeof(url)) == 0
		 || url[0] == 0 ){
			HTTP_originalURLx(ctx,AVStr(url),sizeof(url));
			/*
			 * count up; can be the first access to this page
			 * with COUNTER=ssi
			 */
			if( (flags & CNT_REFERER) == 0 )
				flags |= CNT_INCREMENT;
		}
		/*
		if( !isFullURL(url) && url[0] != '/' ){
		*/
		if( !isFullURL(url) && url[0] != '/' && url[0] != '#' ){
			CStr(rurl,1024);
			strcpy(rurl,url);
			HTTP_originalURLx(ctx,AVStr(url),sizeof(url));
			basedir(url);
			chdir_cwd(AVStr(url),rurl,0);
		}
		if( scanAttr1(attrp,4,"fmt",AVStr(fmt),sizeof(fmt)) == 0 ){
			if( mssg->f_counterfmt[0] )
				strcpy(fmt,mssg->f_counterfmt);
			else
			strcpy(fmt,"%T");
		}
		strfCounter(ctx,flags,url,fmt,timefmt,AVStr(buff),size);
	}else
	if( strcaseeq(ename,"TOTAL_HITS") ){
		if( scanAttr1(attrp,4,"fmt",AVStr(fmt),sizeof(fmt)) == 0 ){
			if( mssg->f_counterfmt[0] )
				strcpy(fmt,mssg->f_counterfmt);
			else
			strcpy(fmt,"%T");
		}
		strfCounter(ctx,CNT_TOTALHITS,"#total",fmt,timefmt,AVStr(buff),size);
	}else
	if( strncaseeq(ename,"clientif_",9) ){
		int CTX_withSSL(DGC*ctx);
		const char *CTX_clif_proto(DGC*ctx);
		const char *name = ename+9;
		if( streq(name,"ssl") ){
			if( CTX_withSSL(ctx) )
				strcpy(buff,"SSL");
			else	strcpy(buff,"");
		}else
		if( streq(name,"protocol") ){
			sprintf(buff,"%s",CTX_clif_proto(ctx));
		}else{
			sprintf(buff,"(UNKNOWN-%s)",ename);
		}
	}else
	if( strncaseeq(ename,"delegate_opt_",13) ){
		const char *name = ename+13;
		const char *ver_sendFd();
		if( streq(name,"sendfd") ){
			sprintf(buff,"%s",ver_sendFd());
		}
	}else
	if( strncaseeq(ename,"delegate_src_",13)
	 || strncaseeq(ename,"delegate_bld_",13)
	 || strncaseeq(ename,"delegate_exe_",13)
	){
		const char *DELEGATE_srcsign();
		const char *DELEGATE_bldsign();
		const char *DELEGATE_exesign();
		const char *ssign;
		const char *name = ename+13;
		IStr(file,1024);
		IStr(signb,1024);
		CStr(ver,64);
		CStr(date,64);
		CStr(md5,128);
		CStr(signer,128);
		CStr(sign,256);

		truncVStr(ver);
		truncVStr(date);
		truncVStr(md5);
		truncVStr(signer);

		if( strncaseeq(ename,"delegate_src_",13) )
			ssign = DELEGATE_srcsign();
		else
		if( strncaseeq(ename,"delegate_bld_",13) )
			ssign = DELEGATE_bldsign();
		else	ssign = DELEGATE_exesign();

		/* this should be "#filesign" rather than "#echo" */
		if( scanAttr1(tagp,4,"file",AVStr(file),sizeof(file)) ){
			int getFileSIGN(PCStr(file),PVStr(signb));
			const char *sig;
			const char *sigval;
			IStr(path,1024);

			SSIfilepathX(ctx,mssg,ev,file,AVStr(path));
			/*
			SSIfilepath(ctx,ev,file,AVStr(path));
			*/
			getFileSIGN(path,AVStr(signb));
			if( strncaseeq(ename,"delegate_src_",13) )
				sig = strstr(signb,"SRCSIGN=");
			else
			if( strncaseeq(ename,"delegate_bld_",13) )
				sig = strstr(signb,"BLDSIGN=");
			else	sig = strstr(signb,"EXESIGN=");
			if( sig && (sigval=strchr(sig,'=')) ){
				ssign = sigval+1;
			}
		}
		Xsscanf(ssign,"%[^:]:%[^:]:%[^:]:%[^:]",
			AVStr(ver),AVStr(date),AVStr(md5),AVStr(signer));

		if( streq(name,"version") ){
			sprintf(buff,"%s",ver);
		}else
		if( streq(name,"date") ){
			sprintf(buff,"%s",date);
		}else
		if( streq(name,"md5") ){
			sprintf(buff,"%s",md5);
		}else
		if( streq(name,"signer") ){
			sprintf(buff,"%s",signer);
		}else{
			sprintf(buff,"(UNKNOWN-%s)",ename);
			goto EXIT;
		}
		if( scanAttr1(attrp,4,"fmt",AVStr(fmt),sizeof(fmt)) ){
			int off = 0;
			int len = 0;
			sscanf(fmt,"%d+%d",&off,&len);
			if( 0 < off && off < strlen(buff) )
				ovstrcpy((char*)buff,buff+off);
			if( 0 < len && len < strlen(buff) )
				setVStrEnd(buff,len);
		}
	}else
	if( eval = getv(ev,ename) ){
		linescanX(eval,AVStr(buff),size);
	}else{
		cname = 0;
		for( ni = 0; sname = cgi_equiv[ni].n_ssi; ni++ ){
			if( strcaseeq(ename,sname) ){
				cname = cgi_equiv[ni].n_cgi;
				break;
			}
		}
		if( cname ){
			if( eval = getv(ev,cname) )
				linescanX(eval,AVStr(buff),size);
		}else{
			sprintf(buff,"(SSI-UNKNOWN-ECHO-%s)",ename);
			sv1tlog("SSI ECHO ERROR: unknown <%s>\n",ename);
		}
	}
EXIT:
	return strlen(buff);
}

void Form_conv_namevalue(int argc,const char *argv[]);
void getClientAddrId(DGC*ctx,PVStr(saddr),PVStr(sid));
int deClientId(PCStr(xid),FILE *dbg,PCStr(fmt),PVStr(sdate),PVStr(saddr));
int SSI_echo(DGC*ctx,const char *ev[],PCStr(tag),PCStr(type),PCStr(ename),FILE *htfp,Mssg *mssg)
{	CStr(buf,4*1024);
	CStr(xbuf,4*1024);
	const char *eval;
	FILE *body = mssg->m_body;
	CStr(nam,1024);
	CStr(arg,1024);

	truncVStr(arg);
	Xsscanf(ename,"%[^.].%[^\n]",AVStr(nam),AVStr(arg));
	if( streq(nam,"-rusage") ){
		const char *fmt = "%uu %ss";
		if( *arg )
			fmt = arg;
		strfRusage(AVStr(buf),fmt,3,NULL);
		fputs(buf,body);
		return 3;
	}

	if( streq(nam,"cwd") ){
		IGNRETS getcwd(buf,sizeof(buf));
		fprintf(body,"%s",buf);
		return 100;
	}
	if( streq(nam,"relbase") ){
		const char *rpath;
		rpath = relative_path(mssg->h_basefile,mssg->h_pushbase);
		if( rpath ){
			fprintf(body,"%s",rpath);
		}else{
			fprintf(body,"(not-relative-path)");
		}
		return 101;
	}
	if( streq(nam,"basefile") ){
		fprintf(body,"%s",mssg->h_basefile);
		return 102;
	}

	if( streq(nam,"request") ){
		if( streq(arg,"mssg") ){
			HTTP_fprintmsgX(ctx,body,"om",HT_ISFORM);
		}else
		if( streq(arg,"charcode") ){
			const char *ie;
			if( (ie = getFav("INCHARCODE")) == 0 )
				ie = getFav("ie");
			fprintf(body,"%s",HTTP_detectReqCharcode(ctx,ie));
		}
		return 7;
	}
	if( streq(nam,"-enclientid") ){
		CStr(addr,128);
		if( *arg == 0 ){
			getClientAddrId(ctx,AVStr(addr),AVStr(buf));
			fprintf(body,"%s",buf);
		}else{
			/* it should not be supported ... */
		}
		return 4;
	}
	if( streq(nam,"-declientid") ){
		const char *xid = ""; /* formv[arg] */
		CStr(sdate,128);
		CStr(saddr,128);
		int err;
		/*
		xid = getv(Fav,arg);
		*/
		xid = getFav(arg);
		if( xid && *xid ){
			err=deClientId(xid,NULL,NULL,AVStr(sdate),AVStr(saddr));
			if( err )
				fprintf(body,"? ?");
			else	fprintf(body,"%s %s",sdate,saddr);
		}
		return 5;
	}

	if( strcaseeq(ename,"*") ){
		int ei;
		for( ei = 0; eval = ev[ei]; ei++ )
			fprintf(body,"%s\r\n",ev[ei]);
		return 1;
	}

	if( evalvar(ctx,mssg,ename,AVStr(buf)) ){
		IStr(fmt,128);
		scanAttr1(mssg->t_attrp,4,"fmt",AVStr(fmt),sizeof(fmt));
		formValue(ctx,buf,fmt,AVStr(xbuf),sizeof(xbuf));
		fputs(xbuf,body);
		return 8;
	}

	SSI_getenv(ctx,ev,tag,type,ename,htfp,mssg,AVStr(buf),sizeof(buf));
	fputs(buf,body);
	return 2;
}
static void basedir(PCStr(path))
{	const char *tp;

	for( tp = path+strlen(path)-1; path < tp; tp-- ){
		if( *tp == '/' )
			break;
		else	*(char*)tp = 0; /* not "const" but fixed */
	}
}

int enentFilecopy(FILE *in,FILE *out,int plain){
	int ch;
	int ee = 0;

	while( (ch = getc(in)) != EOF ){
		if( plain ){
			putc(ch,out);
		}else
		switch( ch ){
			case '<': fputs("&lt;",out); ee++; break;
			case '>': fputs("&gt;",out); ee++; break;
			case '&': fputs("&amp;",out); ee++; break;
			case '"': fputs("&quot;",out); ee++; break;
			default: putc(ch,out); break;
		}
	}
	return ee;
}
/*
 * paramopts=plain,asis
 * opts=getfromquery/plain,asis ... get opts from the URL?query part
 * -- URL.shtml?plain&asis
 * -- URL.shtml?source
 * <!--#include virtual="URL#source" -->
 * <!--#include virtual="URL#source" if="$1=source" -->
 */
static int SSIfilepath(DGC*ctx,const char *ev[],PCStr(file),PVStr(path)){
	return SSIfilepathX(ctx,0,ev,file,BVStr(path));
}
static int SSIfilepathX(DGC*ctx,Mssg *mssg,const char *ev[],PCStr(file),PVStr(path)){
	const char *base = 0;
	const char *ofile = file;
	IStr(upath,1024);
	IStr(lurl,1024);
	const char *mopts;

	if( base = getv(ev,"SCRIPT_NAME") ){
		lineScan(base,upath);
	}else
	if( base = getv(ev,"REQUEST_URI") ){
		upath[0] = '/';
		decomp_absurl(base,VStrNULL,VStrNULL,QVStr(upath+1,upath),sizeof(upath));
	}
	if( base == 0 ){
		strcpy(path,file);
		return 0;
	}
	strcpy(lurl,upath);
	if( file ){
		basedir(lurl);
		chdir_cwd(AVStr(lurl),file,0);
	}
	/* v9.9.11 fix-140731c
	CTX_mount_url_to(ctx,NULL,"GET",AVStr(lurl));
	*/
	mopts = MountSSIpath(ctx,AVStr(lurl));
	if( strncmp(lurl,"file://localhost/",17) == 0 ){
		if( isFullpath(lurl+17) )
			file = lurl+17;
		else	file = lurl+16;
	}else	file = lurl;
	strcpy(path,file);
	if( ofile && !File_is(path) ){
		if( mssg->h_pushbase[0] ){
			strcpy(path,mssg->h_pushbase);
			chdir_cwd(BVStr(path),ofile,0);
		}
	}
	if( isWindows() && !isWindowsCE() ){
		if( !File_is(path) ){
			/*
			if( is-symlink(path) ){
				readlink(path,BVStr(path));
			}
			*/
		}
	}
	return 0;
}

/* reduce "patValueT:ValueF}" to "ValueT" or "ValueF" */
static int replaceByValue(PVStr(url),PCStr(pat),int istrue){
	const char *pp;
	const char *ep;
	const char *vp;
	IStr(subst,URLSZ);
	IStr(vtrue,URLSZ);
	IStr(vfalse,URLSZ);
	const char *values;
	const char *value;

	while( pp = strstr(url,pat) ){
		if( ep = strchr(pp,'}') ){
			QStrncpy(subst,pp,ep-pp+1+1);
			values = pp + strlen(pat);
			if( *values == ':' )
				Xsscanf(values+1,"%[^}]",AVStr(vfalse));
			else	Xsscanf(values,"%[^:}]",AVStr(vtrue));
			if( istrue ){
				value = vtrue;
			}else{
				value = vfalse;
			}
			strsubst(BVStr(url),subst,value);
			return 1;
		}
	}
	return 0;
}
const char *CTX_reqURL(DGC*ctx);
/* v9.9.11 new-140809c, substitute URL
 * example: virtual=xxx.html${QUERY_STRING??{$QUERY_STRING}}
 */
static int substURL(DGC*ctx,const char *ev[],PVStr(url)){
	int nsubst = 0;
	const char *qurl;
	const char *pat;
	const char *query = "";
	const char *qp;

	if( qurl = CTX_reqURL(ctx) ){
		if( qp = getv(ev,"QUERY_STRING") ){
			query = qp;
		}else
		if( qp = strchr(qurl,'?') ){
			/* maybe this does not happen */
			query = qp+1;
		}
		pat = "${QUERY_STRING}";
		strsubst(AVStr(url),pat,query);
		pat = "${QUERY_STRING?";
		replaceByValue(AVStr(url),pat,query[0]!=0);
		nsubst++;
	}
	return nsubst;
}

double CTX_setIoTimeout(DGC*ctx,double tosec);
void SSI_file(DGC*ctx,const char *ev[],PCStr(tag),PCStr(type),PCStr(file),PCStr(np),FILE *htfp,Mssg *mssg)
{	CStr(url,URLSZ);
	refQStr(up,url);
	CStr(lurl,URLSZ);
	CStr(temp,URLSZ);
	CStr(root,URLSZ);
	const char *base;
	CStr(opts,128);
	FILE *body = mssg->m_body;
	FILE *fp;
	int fsize,mtime,direct,xoff,exec;
	double otout = 0;
	const char *mopts;

	syslog_DEBUG("## SSI %s %s=\"%s\"\n",tag,type,file);

	if( streq(type,"file")
	 || streq(type,"virtual") ){
	}else{
		fprintf(body,"(SSI-MISSING-virtual)");
		return;
	}

	lineScan(file,url);
	truncVStr(opts);
	if( up = strchr(url,'#') ){
		setVStrEnd(up,0);
		strcpy(opts,up+1);
	}
	if( url[0] != '/' && !isFullURL(url) ){
		lineScan(url,temp);
		if( base = getv(ev,"SCRIPT_NAME") ){
			sv1log("--SSI SCRIPT_NAME=%s [%s]\n",base,url);
			lineScan(base,url);
		}else
		if( base = getv(ev,"REQUEST_URI") ){
			url[0] = '/';
			decomp_absurl(base,VStrNULL,VStrNULL,QVStr(url+1,url),sizeof(url));
		}
		if( base ){
			basedir(url);
			chdir_cwd(AVStr(url),temp,0);
		}
	}
	substURL(ctx,ev,AVStr(url)); /* v9.9.11 140809c */
	strcpy(lurl,url);
	/* v9.9.11 fix-140731c
	CTX_mount_url_to(ctx,NULL,"GET",AVStr(lurl));
	*/
	mopts = MountSSIpath(ctx,AVStr(lurl));
	if( strncmp(lurl,"file://localhost/",17) == 0 ){
		if( isFullpath(lurl+17) )
			file = lurl+17;
		else	file = lurl+16;
	}else	file = lurl;

/*
fprintf(stderr,"--[%d]-- typ[%s] tag[%s] opts[%s][%s] %s\n",
getpid(),
mssg->h_contype,
tag,opts,file,mssg->t_tagp);
*/
	if( strcaseeq(tag,"include") )
	if( isinListX(opts,"source","c") )
	if( fp = fopen(file,"r") ){
		/* <!--#incldue virtual=URL#source --> */
		int plain = strncaseeq(mssg->h_contype,"text/plain",10);
		enentFilecopy(fp,body,plain);
		fclose(fp);
		return;
	}

	/*
	 * return meta information if the target is a local file
	 */
	exec = isExecutableURL(file);
	syslog_DEBUG("## exec=%d %s [%s]\n",exec,file,url);

	if( strcaseeq(tag,"fsize") ){
		/*
		if( !exec )
		*/
		if( !exec || isinListX(opts,"show","c") )
		if( 0 <= (fsize = File_size(file)) ){
			fprintf(body,"%d",fsize);
			return;
		}
		sv1log("SSI ERROR %s %s %s %X/%d\n",tag,type,file,fsize,exec);
		return;
	}else
	if( strcaseeq(tag,"flastmod") ){
		/*
		if( !exec )
		*/
		if( !exec || isinListX(opts,"show","c") )
		if( 0 <= (mtime = File_mtime(file)) ){
			StrftimeLocal(AVStr(temp),sizeof(temp),ssi_timefmt,mtime,0);
			fprintf(body,"%s",temp);
			return;
		}
		sv1log("SSI ERROR %s %s %s %X/%d\n",tag,type,file,mtime,exec);
		return;

	}else
	if( strcaseeq(tag,"include") ){
	}else{
		fprintf(body,"(SSI-UNKNOWN-%s)",tag);
		return;
	}

	/*
	 * open target (possibly remote) data
	 */
	fp = NULL;
	if( !exec )
		fp = fopen(file,"r");

	/* should set Content-Type:text/plain by default ? */
	if( fp != NULL ){
		/* v9.9.12 fix-140530f, guess the ctype from the file suffix */
		const char *ctype = filename2ctype(file);
		if( ctype ){
			strcpy(mssg->h_incctype,ctype);
		}else{
		}
		sv1log("SSI ctype guessed [%s][%s]\n",mssg->h_incctype,file);
	}
	if( fp == NULL ){
		int oflag;
		CStr(nam,64);
		CStr(val,128);
		fflush(body);  /* necessary not to duplicate buffered data
				* in fork() in responseFilter()
				* for CTX_URLget()
				*/
		xoff = ftell(htfp);

		while( *np && isspace(*np) ) np++;
		/*
		scan_namebody(np,AVStr(nam),sizeof(nam),"=>",AVStr(val),sizeof(val),">");
		*/
		scan_namebody(np,AVStr(nam),sizeof(nam),"=> \t",AVStr(val),sizeof(val),">");

		/* to suppress duplicated rewriting of request */
		/*
		9.2.0 this mod. in 8.9.6 is bad because it suppresses
		 necessary reverse MOUNT of URL in the SHTML file.
		 Maybe this is introduced for FreyaSX SHTML
		 Maybe to be used with "localize"
		*/
		if( exec ){
			/* 9.9.11 fix-140810e, "virtualize" by default.
			 * "Executable" resource should be got with URLget()
			 * based on the virtual-URL of it so that the
			 * preparation of response rewriting is done through
			 * the request virtual-URL interpretaiton.
			 */
		}else
		if( !strcaseeq(nam,"virtualize") )
		if( strneq(lurl,"file:",5) ){
			strcpy(url,lurl);
		}
		if( mssg->f_timeout ){
			otout = CTX_setIoTimeout(ctx,mssg->f_timeout);
		}
		oflag = CTX_addGatewayFlags(ctx,GW_SSI_INCLUDE);
		if( !strcaseeq(nam,"localize") ){
			if( strneq(lurl,"file:",5) ){
			/* v9.9.11 fix-140727f, suppress fullifying URL in
			 * local resouces.
			 * A URL in a response must be rewriten to full-URL
			 * when including from non-local (another) server
			 * because its URL space is differnt from the SHTML.
			 * But it is unnecessary and difficult in local one.
			 * It is unnecessary because URL in the local file:
			 * is rewritten by self as an origin server before
			 * included by SSI.
			 * It is difficult because it is uncertain if or not
			 * an absoulte URL is physical file-path or virtual
			 * URL in this server.
			 */
			}else
			/* v9.9.11 fix-140808b, this modification is cancelled.
 			 * Relative path must be reverse MOUNTed so that it
 			 * is not interpreted as a relative path in the
 			 * including base HTML.
 			 */
			{
			}
			URICONV_nFULL |= 0x8000;
			fp = CTX_URLget(ctx,1,url,0,NULL);
			URICONV_nFULL &= ~0x8000;
		}else
		fp = CTX_URLget(ctx,1,url,0,NULL);
		if( mssg->f_timeout ){
			CTX_setIoTimeout(ctx,otout);
		}
		CTX_setGatewayFlags(ctx,oflag);

		if( fp != NULL && 0 < ftell(fp) ){
			CStr(ct,128);
			int off = ftell(fp);
			fseek(fp,0,0);
			ct[0] = 0;
			fgetsHeaderField(fp,"Content-Type",AVStr(ct),sizeof(ct));
			fseek(fp,off,0);
			FStrncpy(mssg->h_incctype,ct);
		}

		if( ftell(htfp) != xoff ){
			/* On Solaris2, the offset is moved mysteriously,
			 * in wait(0) for fork()ed responseFilter()
			 * which do exit() (not _exit()) at the end.
			 * This causes duplicated SHTML reading...
			 */
			sv1log("## fseeked ? %d -> %d\n",xoff,iftell(htfp));
			fseek(htfp,xoff,0);
		}
	}
	if( fp == NULL ){
		fprintf(body,"(SSI-UNKNOWN-%s-%s)",tag,url);
		return;
	}

	if( strcaseeq(tag,"fsize") ){
		fsize = file_size(fileno(fp)) - ftell(fp);
		fprintf(body,"%d",fsize);
	}else
	if( strcaseeq(tag,"flastmod") ){
		fseek(fp,0,0);
		mtime = HTTP_getLastModInCache(AVStr(temp),sizeof(temp),fp,"(tmp)");
		StrftimeLocal(AVStr(temp),sizeof(temp),ssi_timefmt,mtime,0);
		fprintf(body,"%s",temp);
	}else
	if( isinListX(opts,"asis","c") ){ /* v9.9.12 new-140813d */
		/* <!--#incldue virtual=URL#asis --> */
		int ch;
		while( (ch = getc(fp)) != EOF ){
			putc(ch,body);
		}
	}else
	if( isinListX(opts,"plaintext","c") ){ /* v9.9.12 new-140813e */
		/* <!--#incldue virtual=URL#plaintext --> */
		int ch;
		while( (ch = getc(fp)) != EOF ){
			if( ch == '<' )
				fputs("&lt;",body);
			else	putc(ch,body);
		}
	}else
	if( strcaseeq(tag,"include") ){
		CCXP ccx = CCXtoCL(ctx);
		if( CCXactive(ccx) ){
			IStr(ics,128);
			FILE *tmp;
	getParam(AVStr(mssg->h_incctype),"charset",AVStr(ics),sizeof(ics),0);
			if( ics[0] ){
				/* Content-Type:charset */
				CCX_setindflt(ccx,ics);
			}
			tmp = TMPFILE("SSI-include");
			CCX_file(ccx,fp,tmp);
			fclose(fp);
			fflush(tmp);
			fseek(tmp,0,0);
			fp = tmp;
		}

		if(strcasestr(mssg->h_incctype,"text/plain")){
			int ch;
			fputs("<Pre>",body);
			/* v9.9.11 140809d, customizable PRE by #plainpre STYLE */
			fputs("<Font face=\"courier new\" color=#000000>",body);
			fputs("<Font id=plainpre>",body);
			while( (ch = getc(fp)) != EOF ){
				if( ch == '<' )
					fputs("&lt;",body);
				else	putc(ch,body);
			}
			fputs("</Font>",body);
			fputs("</Font>",body);
			fputs("</Pre>\n",body);
		}else
		copyfile1(fp,body);
	}
	fclose(fp);
}

extern const char *TIMEFORM_UXDATE;
int unamef(PVStr(uname),PCStr(fmt));
/*
int builtincmd(FILE *out,PCStr(command)){
*/
int builtincmd(FILE *out,PCStr(command),DGC*ctx,Mssg *mssg,PCStr(path)){
	IStr(com,256);
	IStr(arg,256);
	const char *cp;
	const char *fmt;
	int rcode;

	cp = valuescanY(command,AVStr(com),sizeof(com));
	while( isspace(*cp) ) cp++;
	valuescanY(cp,AVStr(arg),sizeof(arg));

	if( streq(com,"date") ){
		int now = time(0);
		IStr(tm,128);

		if( *arg == '+' )
			fmt = arg+1;
		else	fmt = TIMEFORM_UXDATE;
		StrftimeLocal(AVStr(tm),sizeof(tm),fmt,now,0);
		fprintf(out,"%s\n",tm);
		return 1;
	}
	if( streq(com,"uname") ){
		if( isWindowsCE() ){
			IStr(un,256);
			unamef(AVStr(un),"");
			fprintf(out,"WindowsCE %s\n",un);
			return 1;
		}
	}
	if( streq(com,"pushbase") ){
		IGNRETS getcwd(mssg->h_pushcwd,sizeof(mssg->h_pushcwd));
		rcode = chdir_lnk(path,arg,out);
		if( rcode == 0 ){
			IStr(cwd,1024);
			IGNRETS getcwd(cwd,sizeof(cwd));
			strcpy(mssg->h_pushbase,cwd);
			return 1;
		}else{
			return -1;
		}
	}
	if( streq(com,"popbase") ){
		if( mssg->h_pushbase[0] ){
			rcode = chdir(mssg->h_pushcwd);
			clearVStr(mssg->h_pushbase);
			return 1;
		}else{
			return -1;
		}
	}
	return 0;
}
/*
void SSI_exec(DGC*ctx,const char *ev[],PCStr(tag),PCStr(type),PCStr(command),FILE *htfp,Mssg *mssg)
*/
int copyfileTimeout(FILE *in,FILE *out,int mtimeout,int pid);
void SSI_exec(DGC*ctx,PCStr(path),const char *ev[],PCStr(tag),PCStr(type),PCStr(command),FILE *htfp,Mssg *mssg)
{	FILE *body = mssg->m_body;

	FILE *fpv[2];
	int pid,xpid;
	int popenx(PCStr(command),PCStr(mode),FILE *io[2]);
	int NoHangWait();

	if( streq(type,"cmd") ){
		extern char **environ;
		char **sev;
		CStr(swd,1024);
		CStr(nwd,1024);
		refQStr(dp,nwd);

		/*
		if( builtincmd(body,command) ){
		*/
		if( builtincmd(body,command,ctx,mssg,path) ){
			return;
		}
		/* 9.9.2 cwd by "pushbase" is not (maybe should not be)
		 * applied to external commands.
		 */

		strcpy(nwd,path);
		if( dp = strrpbrk(nwd,"/\\") ){
			truncVStr(dp);
		}
		IGNRETS getcwd(swd,sizeof(swd));
		IGNRETZ chdir(nwd);
		sv1log("SSI chdir(%s) <- %s\n",nwd,swd);
		sev = environ;
		environ = (char**)ev;
		pid = popenx(command,"r",fpv);
		environ = sev;
		IGNRETZ chdir(swd);

		if( 0 < pid ){
			if( fpv[1] && fpv[1] != fpv[0] ) fclose(fpv[1]);
			/*
			copyfile1(fpv[0],body);
			*/
			copyfileTimeout(fpv[0],body,(int)(SSI_TIMEOUT*1000),pid);
			if( fpv[0] ) fclose(fpv[0]);
			xpid = NoHangWait();
		}
	}else
	if( streq(type,"cgi") ){
	}else
	if( streq(type,"virtual") ){
	}else{
		fprintf(body,"(SSI-UNKNOWN-%s-%s)",tag,type);
	}
}
static void eval_paramvalue(DGC*ctx,const char *ev[],PCStr(tagp),PCStr(type),PCStr(fname),FILE *htfp,Mssg *mssg,PCStr(str),PVStr(val),int siz)
{	FILE *body = mssg->m_body;
	int off,rcc;
	char fc;
	const char *fp;
	refQStr(vp,val); /**/
	const char *xp;
	const char *tp;
	CStr(fmt,256);
	CStr(xtag,256);
	CStr(xtype,256);
	CStr(xval,256);

	valuescanX(str,AVStr(fmt),sizeof(fmt));
	cpyQStr(vp,val);
	xp = val + siz - 1;
	for( fp = fmt; vp < xp && (fc = *fp); ){
		xtag[0] = 0;
		if( fc == '$' && strncmp(fp,"${",2) == 0 ){
			tp = wordscanY(fp+2,AVStr(fmt),sizeof(fmt),"^}");
			if( *tp == '}' ){
				if( strchr(fmt,':') ){
					scan_field1(fmt,AVStr(xtag),sizeof(xtag),
						AVStr(xval),sizeof(xval));
					strcpy(xtype,"virtual");
				}else{
					strcpy(xtag,"echo");
					strcpy(xtype,"var");
					strcpy(xval,fmt);
				}
			}
		}else
		if( fc == '<' && strncmp(fp,"<!--#",5) == 0 ){
			tp = wordscanY(fp+5,AVStr(fmt),sizeof(fmt),"^>");
			if( *tp == '>' ){
				xp = wordScan(fmt,xtag);
				while( isspace(*xp) ) xp++;
				xp = wordscanY(xp,AVStr(xtype),sizeof(xtype),"^=");
				if( *xp == '=' ) xp++;
				xp = valuescanX(xp,AVStr(xval),sizeof(xval));
			}
		}
		if( xtag[0] ){
			if( strcaseeq(xtag,"echo") ){
				SSI_getenv(ctx,ev,tagp,type,xval,
					htfp,mssg,QVStr(vp,val),siz-(vp-val));
			}else
			if( strcaseeq(xtag,"fsize")
			 || strcaseeq(xtag,"flastmod")
			 || strcaseeq(xtag,"include") ){
				off = ftell(body);
				SSI_file(ctx,ev,xtag,xtype,xval,"",htfp,mssg);
				fseek(body,off,0);
				rcc = fread((char*)vp,1,siz-(vp-val),body);
				setVStrEnd(vp,rcc);
				fseek(body,off,0);
				Ftruncate(body,off,0);
			}
			fp = tp + 1;
			vp += strlen(vp);
		}else{
			setVStrPtrInc(vp,*fp++);
		}
	}
	setVStrEnd(vp,0);
}

/*
 * <META HTTP-EQUIV=Date content="${DATE_GMT}">
 * <META HTTP-EQUIV=Date content="${flastmod:URL}">
 * <META HTTP-EQUIV=Content-Length content="<!--#fsize virtual=URL -->">
 */
void META_eval(DGC*ctx,const char *ev[],PCStr(tagp),PCStr(type),PCStr(fname),FILE *htfp,Mssg *mssg)
{	const char *cp;
	CStr(fvalue,256);
	char fc;
	const char *sp;
	refQStr(dp,fvalue); /**/

	if( !strcaseeq(type,"HTTP-EQUIV") ){
		return;
	}

	fvalue[0] = 0;
	if( cp = strcasestr(tagp,"content=") ){
		cp += 8;
		eval_paramvalue(ctx,ev,tagp,type,fname,htfp,mssg,
			cp,AVStr(fvalue),sizeof(fvalue));
	}
	if( strcaseeq(fname,"Referer") ){
		CStr(b,1024);
		sprintf(b,"<META %s=Referer CONTENT=\"%s\">\r\n",type,fvalue);
		fputs(b,mssg->m_body);
		return;
	}

	cpyQStr(dp,fvalue);
	for( sp = fvalue; fc = *sp; sp++ ){
		if( fc == '\r' || fc == '\n' ){
			setVStrPtrInc(dp,' ');
			while( isspace(sp[1]) )
				sp++;
		}else	setVStrPtrInc(dp,fc);
	}
	setVStrEnd(dp,0);

	if( strcaseeq(fname,"Status") )
		sprintf(mssg->h_status,"%s\r\n",fvalue);
	else
	if( strcaseeq(fname,"Content-Type") )
	{	CCXP ccx = CCXtoCL(ctx);
		if( CCXactive(ccx) ){
			IStr(cs,128);
			getParam(AVStr(fvalue),"charset",AVStr(cs),sizeof(cs),0);
			if( cs ){
				CCX_setindflt(ccx,cs);
			}
		}
		sprintf(mssg->h_contype,"%s\r\n",fvalue);
	}
	else	Xsprintf(TVStr(mssg->h_header),"%s: %s\r\n",
			fname,fvalue);
}

typedef const char *(*scanMetaFuncP)(DGC*ctx,PCStr(attr),PVStr(cont),PCStr(tagp),PVStr(contp),PCStr(nextp));
void scan_metahttp(DGC*ctx,PVStr(line),scanMetaFuncP func)
{	int uconv;
	const char *sp;
	const char *np;
	const char *ep;
	const char *tag;
	refQStr(attr,line); /**/
	/*
	const char *cont;
	*/
	refQStr(cont,line);
	CStr(attrb,32);
	/*
	CStr(contb,128);
	*/
	/*
	CStr(contb,512);
	*/
	CStr(contb,1024);

	sp = line;
	while( sp ){
		/*
		uconv = TAGCONV_META;
		*/
		uconv = TAGCONV_META | TAGCONV_XML;
		np = html_nextTagAttrX(NULL,sp,"",VStrNULL,&tag,(const char**)&attr,&uconv);
		if( np == NULL )
			break;

		if( ep = strpbrk(np,">") )	sp = ep + 1; else
		if( ep = strpbrk(np," \t\r\n"))	sp = ep + 1; else
			sp = np;

		if( tag && strncasecmp(tag,"<META",5) == 0 )
		if( attr && strncasecmp(attr,"HTTP-EQUIV=",11) == 0 )
		/*
		if( cont = strcasestr(np,"content=") ){
		*/
		if( cont = strcasestr(tag,"content=") )
		{
			valuescanY(attr+11,AVStr(attrb),sizeof(attrb));
			valuescanY(cont+ 8,AVStr(contb),sizeof(contb));
			/*
			sp = (*func)(ctx,attrb,AVStr(contb),tag,AVStr(attr),sp);
			*/
			sp = (*func)(ctx,attrb,AVStr(contb),tag,AVStr(cont),sp);
			continue;
		}

		if( tag && strncasecmp(tag,"<?xml",5) == 0 )
		if( attr && strncasecmp(attr,"encoding=",9) == 0 ){
			strcpy(attrb,"encoding");
			valuescanX(attr+9,AVStr(contb),sizeof(contb));
			sp = (*func)(ctx,attrb,AVStr(contb),tag,AVStr(attr),sp);
			continue;
		}

		if( sp == np )
			break;
	}
}

char *valueskipJ(PCStr(str));
static const char *seekeot(PCStr(tagp),PCStr(np),int ignspace)
{	const char *sp;
	char sc;
	const char *xp;
	int in2B = 0;

	xp = NULL;
	for( sp = np; sc = *sp; sp++ ){
		if( sc == 033 ){
			if( sp[1] == '$' )
				in2B = 1;
			else
			if( sp[1] == '(' )
				in2B = 0;
		}
		if( in2B ){
			continue;
		}
		if( sc == '"' || sc == '\'' ){
		/*
		if( sc == '"' ){
		*/
			/*
			for( sp++; *sp && *sp != '"'; sp++ );
			*/
			sp = valueskipJ(sp);
			if( *sp == 0 )
				break;
			sc = *sp;
			/*
			continue;
			*/
		}
		if( sc == '-' && strncmp(sp,"-->",3) == 0 )
				 { xp = sp + 3; break; }
		if( sc == '>'   ){ xp = sp + 1; break; }
		if( isspace(sc) ){ xp = sp + 1; }
	}
	if( xp == NULL )
		xp = np;

	if( ignspace ){
		while( isspace(*xp) )
			xp++;
	}
	return xp;
}
/*
int exec_metassi(DGC*ctx,const char *av[],const char *ev[],FILE *fc,FILE *tc,FILE *htfp)
*/

const char *SSI_headCanbeGen = "Refresh,Set-Cookie";
int CTX_clif_port(DGC*ctx);
const char *parameq(PCStr(param),PCStr(name));
const char *DELEGATE_ver();

#define FPRINTF	mssg->h_hleng += Fprintf
static void put_shtmlhead(DGC*ctx,Mssg *mssg,FILE *tc,FILE *infp,int cleng){
	CStr(line,1024);
	FileSize oleng;
	const char *icharset = "";
	const char *ocharset = "";

	if( CTX_clif_port(ctx) == 0 ){
		/* via -Fssi ssi_main() */
		return;
	}
	if( mssg->h_headput ){
		return;
	}
	FPRINTF(tc,"HTTP/%s ",MY_HTTPVER);
	if( mssg->h_status[0] == 0 )
		FPRINTF(tc,"200 OK\r\n");
	else	FPRINTF(tc,"%s",mssg->h_status);

fprintf(tc,"Server: DeleGate/%s\r\n",DELEGATE_ver());

	if( getKeepAlive(ctx,AVStr(line)) )
		FPRINTF(tc,"%s",line);
	else	FPRINTF(tc,"Connection: close\r\n");

	if( CCXactive(CCXtoCL(ctx)) ){
		/*
		const char *CCXidentOut(CCXP ccx);
		ocharset = CCXidentOut(CCXtoCL(ctx));
		if( ocharset && strcaseeq(ocharset,"US-ASCII"))
			ocharset = 0;
		if(ocharset && *ocharset)
		sv1log("-------- identOut[%s]\n",ocharset?ocharset:"");
		if( ocharset == 0 || *ocharset == 0 )
		*/

		CCXoutcharset(CCXtoCL(ctx),&ocharset);
		if( ocharset && *ocharset ){
			IStr(ct,128);
			lineScan(mssg->h_contype,ct);
			sv1log("{C} SSI ctype=%s charset[%s][%s]\n",
				ct,CCXident(CCXtoCL(ctx)),ocharset);
			if( streq(ocharset,"guess") ){
				const char *och;
				if( och = CCXident(CCXtoCL(ctx)) ){
					sv1log("SSI CCX guessed: %s\n",och);
					ocharset = och;
				}
			}else{
				FPRINTF(tc,"Set-Cookie: %s=%s\r\n",
					COOKIE_CLCC,ocharset);
			}
		}else{
		}
	}
	else{
		const char *ich;
		ich = CCX_getindflt(CCXtoCL(ctx));
		if( !streq(ich,"*") ){
			ocharset = ich;
		}
	}

	{	const char *fav1;
		if( fav1 = getFav("$DeleGate-Control-CCX") ){
		    if( strcaseeq(fav1,"INIT") ){
			ocharset = "US-ASCII";
			FPRINTF(tc,"Set-Cookie: DeleGate-Control-SVCC=\r\n");
			FPRINTF(tc,"Set-Cookie: DeleGate-Control-CLCC=\r\n");
		    }
		}
	}
	/*
	int fi;
	for( fi = 0; fi < Fac; fi++ ){
		const char *fa1;
		if( fa1 = parameq(Fav[fi],"HTTP-EQUIV") ){
			IStr(fnam,128);
			IStr(val,8*1024);
			strcpy(val,fa1);
			wordScanY(fa1,fnam,"^:");
			if( isinListX(SSI_headCanbeGen,fnam,"c") ){
				strsubst(AVStr(val),"\r","^M");
				strsubst(AVStr(val),"\n","^J");
				sv1log("SENT HTTP-EQUIV %s\n",val);
				FPRINTF(tc,"%s\r\n",val);
			}
		}
	}
	*/

	FPRINTF(tc,"Content-Type: ");
	if( mssg->h_contype[0] == 0 )
	{
	if( ocharset && *ocharset && !strcaseeq(ocharset,"guess") )
		FPRINTF(tc,"text/html; charset=%s\r\n",ocharset);
	else
		FPRINTF(tc,"text/html\r\n");
	}
	else	FPRINTF(tc,"%s",mssg->h_contype);

	if( 0 < cleng ){
		FPRINTF(tc,"Content-Length: %d\r\n",cleng);
	}
	FPRINTF(tc,"%s",mssg->h_header);
	FPRINTF(tc,"\r\n");
	mssg->h_headput = 1;
}
static FileSize put_shtmlbody(DGC*ctx,Mssg *mssg,FILE *tc,FILE *infp){
	const char *dp;
	/*
	CStr(ochset,64);
	CStr(ichset,64);
	*/
	IStr(ocs,64);
	IStr(ics,64);
	FileSize oleng;
	CCXP ccx = CCXtoCL(ctx);

	/*
	if( strstr(mssg->h_contype," charset=") ){
		dp = strstr(mssg->h_contype," charset=");
		wordscanY(dp+9,AVStr(ochset),sizeof(ochset),"^;\r\n");
		strcpy(ichset,"*");
		if( dp = strstr(mssg->h_incctype," charset=") ){
			wordscanY(dp+9,AVStr(ichset),sizeof(ichset),"^;\r\n");
			if( strcaseeq(ichset,"ISO-2022-JP") )
				strcpy(ichset,"*");
		}
		oleng = CCXfile(ichset,ochset,infp,tc);
	}else{
	*/
	getParam(AVStr(mssg->h_contype),"charset",AVStr(ocs),sizeof(ocs),0);
	getParam(AVStr(mssg->h_incctype),"charset",AVStr(ics),sizeof(ics),0);
	if( ocs[0] ){
		if( ics[0] == 0 ){
			strcpy(ics,CCX_getindflt(CCXtoCL(ctx)));
		}
		if( lCHARSET() ){
			sv1log("{C} SSI body [%s]->[%s]\n",ics,ocs);
		}
		if( strcaseeq(ics,"ISO-2022-JP") )
			strcpy(ics,"*");
		CCX_setindflt(ccx,ics);
		CCX_setoutcode(ccx,ocs);
	}
	if( CCXactive(ccx) ){
		oleng = CCX_file(ccx,infp,tc);
	}else{
		oleng = copyfile1(infp,tc);
	}
	return oleng;
}
static FileSize set_thru(DGC*ctx,Mssg *mssg,FILE *tc){
	FileSize cleng;

	fflush(mssg->m_body);
	fseek(mssg->m_body,0,0);
	put_shtmlhead(ctx,mssg,tc,mssg->m_body,0);
	cleng = put_shtmlbody(ctx,mssg,tc,mssg->m_body);
	fflush(tc);
	mssg->h_savfp = mssg->m_body;
	mssg->m_body = tc;
	/* it should be input to put_shtmlbody() ... */
	return cleng;
}
static void pop_thru(DGC*ctx,Mssg *mssg){
	mssg->m_body = mssg->h_savfp;
	fseek(mssg->m_body,0,0);
	Ftruncate(mssg->m_body,0,0);
}

int CTX_depthExceed(DGC*ctx);
int CTX_depthPeak(DGC*ctx);
int exec_metassi(DGC*ctx,PCStr(path),const char *av[],const char *ev[],FILE *fc,FILE *tc,FILE *htfp)
{	int leng;
	CStr(line,1024);
	CStr(xline,0x10000);
	CStr(yline,0x10000);
	const char *sp;
	const char *np;
	refQStr(xp,xline); /**/
	const char *tagp;
	const char *attrp;
	CStr(tag,256);
	CStr(aname,256);
	CStr(avalue,1024);
	int uconv0,uconv;
	CStr(Status,256);
	CStr(Header,2048);
	int ignspace;
	Mssg mssg;
	FileSize cleng = 0;
	int cleng1;
	CCXP ccx = ctx ? CCXtoCL(ctx) : 0;
	int withccx = ctx ? 0 : -1;
	const char *cp;
	IStr(savbase,256);

	sv1log("## eval META & SSI\n");
	leng = 0;

	push_VBASE(ctx,savbase,sizeof(savbase));
	uconv0 = TAGCONV_SSI | TAGCONV_META;

	bzero(&mssg,sizeof(mssg));
	strcpy(mssg.f_timefmt,TIMEFORM_RFC822);
	mssg.f_timeout = 0;
	mssg.h_favgot = 0;
	mssg.h_fac = 0;
	mssg.h_fav[0] = 0;

	mssg.h_headput = 0;
	mssg.h_hleng = 0;
	mssg.h_savfp = 0;
	mssg.f_counterfmt[0] = 0;
	mssg.t_tagp = 0;
	mssg.t_attrp = 0;
	mssg.h_status[0] = 0;
	mssg.h_contype[0] = 0;
	mssg.h_header[0] = 0;
	mssg.h_incctype[0] = 0;

	mssg.h_basefile = path;
	mssg.h_pushbase[0] = 0;
	mssg.h_pushcwd[0] = 0;
	mssg.m_body = TMPFILE("SSI");

	while( fgets(line,sizeof(line),htfp) != NULL ){
		sp = line;
		xp = xline;
		for(;;){
			uconv = uconv0;
			np = html_nextTagAttrX(NULL,sp,"",VStrNULL,&tagp,&attrp,&uconv);
			if( np == NULL )
				break;

			if( tagp == NULL ){
				fwrite(sp,1,np-sp,mssg.m_body);
				sp = np;
				continue;
			}
			mssg.t_tagp = tagp;
			mssg.t_attrp = attrp;

			fwrite(sp,1,tagp-sp,mssg.m_body);
			ignspace = 0;

			wordScan(tagp,tag);
			aname[0] = 0;
			wordscanY(attrp,AVStr(aname),sizeof(aname),"^=");
			if( np[-1] == '\'' ){
				np = valuescanY(np-1,AVStr(avalue),sizeof(avalue));
				if( *np == '\'' )
					np++;
			}else
			if( np[-1] == '"' ){
				np = valuescanX(np-1,AVStr(avalue),sizeof(avalue));
				if( *np == '"' )
					np++;
			}else	np = valuescanX(np,AVStr(avalue),sizeof(avalue));

			if( strcaseeq(tag,"<!--#echo") ){
				SSI_echo(ctx,ev,tag+5,aname,avalue,htfp,&mssg);
			}else
			if( strcaseeq(tag,"<!--#config") ){
				SSI_config(ctx,ev,tag+5,aname,avalue,htfp,&mssg);
			}else
			if( mssg.h_outsupp ){
				/* disabled output from external command/file */
			}else
			if( strcaseeq(tag,"<!--#include")
			 || strcaseeq(tag,"<!--#fsize")
			 || strcaseeq(tag,"<!--#flastmod")
			){
				/* if it's remote URL, or timed-out include */
				cleng += set_thru(ctx,&mssg,tc);
				SSI_file(ctx,ev,tag+5,aname,avalue,np,htfp,&mssg);
				pop_thru(ctx,&mssg);
			}else
			if( strcaseeq(tag,"<!--#exec") ){
				/*
				SSI_exec(ctx,ev,tag+5,aname,avalue,htfp,&mssg);
				*/
				cleng += set_thru(ctx,&mssg,tc);
				SSI_exec(ctx,path,ev,tag+5,aname,avalue,htfp,&mssg);
				pop_thru(ctx,&mssg);
			}else
			if( strcaseeq(tag,"<META") ){
				ignspace = 1;
				META_eval(ctx,ev,tagp+1,aname,avalue,htfp,&mssg);
			}

			sp = seekeot(tagp,np,ignspace);
			if( CTX_depthExceed(ctx) ){ /* v9.9.12 fix-140814c */
				break;
			}
		}
		if( CTX_depthExceed(ctx) ){ /* v9.9.12 fix-140814c */
			break;
		}
		strcpy(xp,sp);

		if( withccx == 0 ){
		  /* should see META charset ... */
		  for( cp = xline; *cp; cp++ ){
		    if( (*cp & 0x80) || *cp == 033 ){
		      if( CCXguessing(ccx) || CCXactive(ccx) == 0 ){
			CStr(buf,4*1024);
			int off,len,bin;
			strcpy(buf,xline);
			off = ftell(htfp);
			/* get enough data to guess the code */
			fgetsByBlock(TVStr(buf),sizeof(buf)-strlen(buf),htfp,
				0,1,0,1,sizeof(buf),&len,&bin);
			fseek(htfp,off,0);
			if( CCXactive(ccx) ){
				const char *ics;
				ics = CCX_getindflt(ccx);
				if( strcaseeq(ics,"ISO-2022-JP") )
					ics = "*";
				/* might be set with INCHARCODE= */
				CCXcreate(ics,"guess-and-set",ccx);
			}else
			CCXcreate("*","guess-and-set",ccx);
			CCXexec(ccx,buf,strlen(buf),AVStr(yline),sizeof(yline));
			if( CCXwithJP(ccx) ){
				withccx = 1;
			}else{
				withccx = -1;
			}
			sv1log("-- CCX guess-and-set: %d [%s]\n",withccx,
				CCXident(ccx));
			break;
		      }
		    }
		  }
		}
		if( 0 < withccx ){
			CCXexec(ccx,xline,strlen(xline),AVStr(yline),sizeof(yline));
			fputs(yline,mssg.m_body);
			leng += strlen(yline);
		}else{
		fputs(xline,mssg.m_body);
		leng += strlen(xline);
		}
		if( ferror(tc) ){
			sv1log("## SSI client Disconnected[%d]\n",fileno(tc));
			break;
		}
	}

	fflush(mssg.m_body);
	cleng1 = ftell(mssg.m_body);
	fseek(mssg.m_body,0,0);

	put_shtmlhead(ctx,&mssg,tc,mssg.m_body,cleng1);
	cleng += put_shtmlbody(ctx,&mssg,tc,mssg.m_body);
	fclose(mssg.m_body);

	/*
	sv1log("SSI %lldo / %di\n",cleng,leng);
	return cleng;
	*/
	sv1log("SSI head:%d + body:%lldo / %di depth=%d ovf=%d\n",
		mssg.h_hleng,cleng,leng,CTX_depthPeak(ctx),
		CTX_depthExceed(ctx));

	pop_VBASE(ctx,savbase);
	return mssg.h_hleng + cleng;
}
