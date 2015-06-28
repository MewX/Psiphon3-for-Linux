/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1995-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	filetype.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950707	extracted from ftpgw.c
//////////////////////////////////////////////////////////////////////#*/
#include "ystring.h"
#include "dglib.h"

typedef struct {
  const	char	*f_suffix;
	char	 f_gtype;
  const	char	*f_ialt;
  const	char	*f_icon;
  const	char	*f_ctype;
} Filetype;

typedef struct {
	Filetype *fe_filetypes[128]; /**/
	int	fe_filetypex;
	MStr(	fe_Iconbuf,128);
	int	fe_initdone;
} FiletypeEnv;
static FiletypeEnv *filetypeEnv;
#define filetypes	filetypeEnv->fe_filetypes
#define filetypex	filetypeEnv->fe_filetypex
#define Iconbuf		filetypeEnv->fe_Iconbuf
/**/
#define initdone	filetypeEnv->fe_initdone
void minit_filetype()
{
	if( filetypeEnv == 0 )
		filetypeEnv = NewStruct(FiletypeEnv);
}

static const char *dflt_filetypes[] = {
	".txt    :0 :TXT :text       :text/plain",
	".c      :0 :TXT :text       :text/plain",
	".css    :0 :TXT :text       :text/css",
	".curl   :0 :TXT :text       :text/vnd.curl",
	".cur    :0 :TXT :text       :text/vnd.curl",
	".h      :0 :TXT :text       :text/plain",
	".doc    :0 :TXT :text       :application/octet-stream",
	".html   :0 :HTM :text       :text/html",
	".shtml  :0 :HTM :text       :text/html",
	".dhtml  :0 :HTM :text       :text/html",
	".htm    :0 :HTM :text       :text/html",
	".xml    :0 :HTM :text       :text/xml",
	".js     :0 :JS  :text       :text/javascript",
	".warc   :0 :HTM :text       :application/warc",
	".webarchive :0 :HTM :text   :application/warc",
	".ps     :0 :PS  :document   :application/postscript",
	".ppt    :I :PPT :document   :application/vnd.ms-powerpoint",
	".pptx   :I :PPT :document   :application/vnd.openxmlformats-officedocument.presentationml.presentation",
	".ico    :I :ICO :image      :image/x-icon",
	".bmp    :I :BMP :image      :image/bmp",
	".xbm    :I :XBM :image      :image/x-xbitmap",
	".gif    :g :GIF :image      :image/gif", 
	".png    :I :PNG :image      :image/png",
	".jpg    :I :JPG :image      :image/jpeg",
	".mpg    :I :MPG :movie      :video/mpeg",
	".mov    :I :MOV :movie      :video/quicktime",
	".avi    :I :MOV :movie      :video/avi",
	".au     :9 :AUD :sound      :audio/basic",
	".tar    :9 :TAR :tar        :application/octet-stream",
	".uu     :6 :UUE :uu         :application/octet-stream",
	".gz     :9 :ZIP :gzip       :application/octet-stream",
	".Z      :9 :CMP :compressed :application/octet-stream",
	".iso    :I :ISO :binary     :application/octet-stream",
	".hqx    :4 :HQX :binhex     :application/mac-binhex40",
	".bat    :0 :BAT :text       :text/plain",
	".exe    :9 :EXE :binary     :application/octet-stream",
	".dll    :9 :DLL :binary     :application/octet-stream",
	".pac    :0 :PAC :text       :application/x-ns-proxy-autoconfig",
	".swf    :I :SWF :image      :application/x-shockwave-flash",
	"README  :0 :TXT :text       :text/plain",
	"INDEX   :0 :TXT :text       :text/plain",
	"HELP    :0 :TXT :text       :text/plain",
	"/       :1 :DIR :directory  :text/html",
	".conf   :0 :TXT :text       :text/plain",
	".cnf    :0 :TXT :text       :text/plain",
	0
};

int scan_FILETYPE(DGC*_,PCStr(filetype))
{	CStr(suffix,64);
	CStr(gtype,64);
	CStr(alt,64);
	CStr(icon,64);
	CStr(ctype,128);
	CStr(str,128);
	int nitem;
	Filetype *ft;

	nitem = Xsscanf(filetype,"%[^:]:%[^:]:%[^:]:%[^:]:%[^:]",AVStr(suffix),AVStr(gtype),AVStr(alt),AVStr(icon),AVStr(ctype));
	if( 5 <= nitem ){
		if( elnumof(filetypes) <= filetypex ){
			return -1;
		}
		ft = NewStruct(Filetype);
		filetypes[filetypex++] = ft;
		wordScan(suffix,str); ft->f_suffix = StrAlloc(str);
		wordScan(gtype,str);  ft->f_gtype  = str[0];
		wordScan(alt,str);    ft->f_ialt   = StrAlloc(str);
		wordScan(icon,str);   ft->f_icon   = StrAlloc(str);
		wordScan(ctype,str);  ft->f_ctype  = StrAlloc(str);
	}else{
		printf("??FILETYPE=\"%s\"??\n",filetype);
	}
	return 0;
}

static void init_types()
{	int fx;
	const char *filetype;

	if( initdone++ != 0 )
		return;

	for( fx = 0; filetype = dflt_filetypes[fx]; fx++ )
		scan_FILETYPE(0L,filetype);
}
char *strrcasestr(const char*,const char*);
static int suffix(PCStr(path),PCStr(sfx))
{	const char *sp;
	int len;

	if( sp = strrcasestr(path,sfx) ){
		len = strlen(sfx);
		if( sp[len] == 0 ) return 1;
		if( sp[len] == '~' && sp[len+1] == 0 ) return 1;
	}
	return 0;
}
const char *filename2ctype(PCStr(path))
{	int ci;
	Filetype *ft;

	init_types();
	for( ci = 0; ft = filetypes[ci]; ci++ ){
		if( suffix(path,ft->f_suffix) )
			return ft->f_ctype;
	}
	return 0;
}
/*
int filename2gtype(PCStr(name))
*/
int filename2gtypeX(PCStr(name))
{	int ci;
	Filetype *ft;

	init_types();
	for( ci = 0; ft = filetypes[ci]; ci++ ){
		if( suffix(name,ft->f_suffix) )
			return ft->f_gtype;
	}
	return 0;
}
int filename2gtype(PCStr(name)){
	int gt;
	if( gt = filename2gtypeX(name) )
		return gt;
	return '9';
}
char *filename2icon(PCStr(path),const char **ialt)
{	int ci;
	Filetype *ft;

	init_types();
	for( ci = 0; ft = filetypes[ci]; ci++ ){
		if( suffix(path,ft->f_suffix) ){
			if( ialt ) *ialt = ft->f_ialt;
			strcpy(Iconbuf,ft->f_icon);
			goto EXIT;
		}
	}
	if( path[0] == 0
	 || path[strlen(path)-1] == '/'
	 || strcmp(path,".") == 0
	 || strcmp(path,"..") == 0
	){
		if( ialt ) *ialt = "DIR";
		strcpy(Iconbuf,"directory");
	}else{
		if( ialt ) *ialt = "UNK";
		strcpy(Iconbuf,"unknown");
	}
EXIT:
	Xstrcat(AVStr(Iconbuf),".gif");
	return Iconbuf;
}

int fileMaybeText(PCStr(path))
{	const char *ctype;

	if( ctype = filename2ctype(path/*,0L*/) )
		if( strncasecmp(ctype,"text/",5) != 0 )
			return 0;
	return 1;
}
int fileSeemsBinary(PCStr(path))
{	char gtype;

	if( gtype = filename2gtypeX(path) ){
		if( strchr("9Ig",gtype) )
			return 1;
		else	return -1;
	}
	return 0;
}
