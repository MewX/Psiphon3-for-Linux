/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-1999 Yutaka Sato
Copyright (c) 1994-1999 Electrotechnical Laboratry (ETL), AIST, MITI

Permission to use, copy, and distribute this material for any purpose
and without fee is hereby granted, provided that the above copyright
notice and this permission notice appear in all copies.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	gopher.c (GOPHER [RFC1XXX] proxy)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
	The DeleGate for the Gopher+ protocol rewrites selectors in reponses
	of:
		1. request for directory type
		2. request for search type
		3. request for any type with INFO requset(postfixed with "!")
History:
	940303	created
//////////////////////////////////////////////////////////////////////#*/
#include "delegate.h"
#include "proc.h"
#include "file.h"

#define SELSZ	2048
#define OBUFSIZ	0x2000	/* should be smaller than 0x10000 for NEWS-OS */

#define IS_TEXT(gtype)		(gtype=='0')
#define IS_DIR(gtype)		(gtype=='1')
#define IS_SEARCH(gtype)	(gtype=='7')

int is_redirected_selector(PCStr(sel));
void del_DGlocalheader(Connection *Conn);
int CTX_get_clientgtype(Connection *Conn);
int gopher_EXPIRE(Connection *Conn,PCStr(url));
void delegate_selector(Connection *Conn,PVStr(xselector),PCStr(host),int iport,int gtype);
void putAncestorAnchor(Connection *Conn,FILE *dst,PCStr(proto),PCStr(host),int port,PCStr(path),int hidepass);

int proxyable_gtype(int gtype)
{
	return !strchr("38T",gtype);
}

static int is_INFO(PCStr(req))
{	const char *tab;

	if( strlen(req) )
	if( tab = strrchr(req,'\t') )
		return tab[1] == '!';
	return 0;
}
static int is_DIR(PCStr(req))
{	const char *dp;

	if( dp = strpbrk(req,"\t\r\n") )
		if( dp[-1] == '/' )
			return 1;
	return 0;
}

int decomp_dirent(PVStr(line),PVStr(attr),const char **uname,const char **selector,const char **host,int *iport,const char **ext);

/*
 *	Put Directory Entity redirecting it to me.
 */
static int gopher_fputs(Connection *Conn,int rgtype,PCStr(request),xPVStr(line),FILE *fp)
{	CStr(bline,2048);
	CStr(iline,2048);
	char egtype;

	strcpy(bline,line);
	setPStr(line,bline,sizeof(bline));
	egtype = *line;

	if( BORN_SPECIALIST || ACT_SPECIALIST )
	if(IS_DIR(rgtype)||is_DIR(request)||IS_SEARCH(rgtype)||is_INFO(request))
	if( egtype != '.' && egtype != '-' && egtype != ' '
	 && egtype != '8' && egtype != 'T'
	){
		CStr(xline,2048);
		CStr(attr,256);
		const char *Uname;
		const char *selector;
		const char *host;
		int   iport;
		const char *ext;
		CStr(xselector,SELSZ);
		CStr(myhost,SELSZ);
		int  myport;

		strcpy(xline,line);
		egtype = decomp_dirent(AVStr(xline),AVStr(attr),
			&Uname,&selector,&host,&iport,&ext);
		if( egtype == 0 )
			goto PUT;

		strcpy(xselector,selector);
		if( proxyable_gtype(egtype) )
			delegate_selector(Conn,AVStr(xselector),host,iport,egtype);

		if( ACT_SPECIALIST && !META_SPECIALIST ){
			strcpy(myhost,DELEGATE_LHOST);
			myport = DELEGATE_LPORT;
		}else	myport = ClientIF_H(Conn,AVStr(myhost));

		sprintf(line,"%s%c%s\t%s\t%s\t%d%s",
			attr,egtype,Uname,xselector,myhost,myport,ext);
	}
PUT:
	if( BORN_SPECIALIST || ACT_SPECIALIST || ACT_TRANSLATOR )
	if( CTX_cur_codeconvCL(Conn,VStrNULL) ){
		CTX_line_codeconv(Conn,line,AVStr(iline),"x-gopher/dirent");
		setPStr(line,iline,sizeof(iline));
	}
	return fputs(line,fp);
}

static int Modified(Connection *Conn,int cdate,PCStr(req))
{	static Connection *MConn;
	CStr(sel,SELSZ);
	FILE *fs;
	CStr(line,1024);
	CStr(mdate,256);
	CStr(scdate,256);
	int modified;

	if( MConn == 0 )
		MConn = NewStruct(Connection);
	*MConn = *Conn;
	Conn = MConn;
	if( connect_to_serv(Conn,FromC,ToC,0) < 0 )
		return 0;

	Xsscanf(req,"%[^\t\r\n]",AVStr(sel));
	Xsprintf(TVStr(sel),"\t!\r\n\r\n");
	IGNRETP write(ToS,sel,strlen(sel));

	fs = fdopen(FromS,"r");

	StrftimeGMT(AVStr(scdate),sizeof(scdate),TIMEFORM_GOPHER,cdate,0);
	modified = 1;
	while( fgetsTIMEOUT(AVStr(line),sizeof(line),fs) != NULL ){
		if( strncasecmp(" Mod-Date:",line,9) == 0 ){
			sv1log("Mod-Date: %s\n",line);
			if( Xsscanf(line,"%*[^<]<%[^>]",AVStr(mdate)) ){
				modified = (0 < strcmp(mdate,scdate));
				sv1log("Mod-Date: %s > %s = %d\n",
					mdate,scdate,modified);
				if( modified )
					sv1log("Modified\n");
				else	sv1log("NOT Modified\n");
			}
			break;
		}
		if( streq(line,".\r\n") )
			break;
	}
	fclose(fs);
	close(ToS);
	return modified;
}

static int readout_cache(Connection *Conn,PCStr(req),int gtype,FILE *cachefp,FILE *tc)
{	CStr(line,2048);
	int totalc = 0;

	rewind(cachefp);
	if( IS_DIR(gtype) || is_DIR(req) || IS_SEARCH(gtype) || is_INFO(req) ){
		CTX_check_codeconvSP(Conn,1);
		while( fgetsTIMEOUT(AVStr(line),sizeof(line),cachefp) ){
			totalc += strlen(line);
			gopher_fputs(Conn,gtype,req,AVStr(line),tc);
		}
	}else
	if( IS_TEXT(gtype) )
		totalc = CCV_relay_text(Conn,cachefp,tc,NULL);
	else	totalc = copy_fileTIMEOUT(cachefp,tc,NULL);
	fflush(tc);
	return totalc;
}

static int fgets_selector(Connection *Conn,PVStr(str),int size,FILE *fp)
{	char gtype;
	char cgtype;
	CStr(rproto,64);
	CStr(rserver,MaxHostNameLen);
	int riport;

	if( DDI_fgetsFromC(Conn,AVStr(str),size,fp) == NULL )
		return 0;

	sv1log("GOPHER SELECTOR: %s",str);

	if( *str == 0 || strchr(" \t\r\n",*str) != 0 )
	if( D_SELECTOR[0] ){
		CStr(tmp,128);

		strcpy(tmp,str);
		sprintf(str,"%s%s",D_SELECTOR,tmp);
		sv1log("GOPHER SELECTOR: %s",str);
	}

/*	if( BORN_SPECIALIST ) */
	if( BORN_SPECIALIST || ACT_SPECIALIST )
	if( CTX_url_derefer(Conn,"gopher",AVStr(str),VStrNULL,AVStr(DELEGATE_FLAGS),AVStr(rproto),AVStr(rserver),&riport) ){

/* if rproto != "gopher" then it's ERROR because gopher client cannot
 * receive response from non-gopher server */

set_realsite(Conn,"gopher",rserver,riport);

/* obsolete, but used in connect_to_serv() ... */
strcpy(DFLT_PROTO,rproto);
strcpy(DFLT_HOST,rserver);
DFLT_PORT = riport;

		add_DGheader(Conn,D_SERVER,"%s://%s:%d",rproto,rserver,riport);
		log_PATH(Conn,">");
		sv1log("GOPHER REMOTE > [%s] %s://%s:%d %s",
			DELEGATE_FLAGS,rproto,rserver,riport,str);
	}

	gtype = get_gtype(str,AVStr(str));
	if( cgtype = CTX_get_clientgtype(Conn) ) /* sent from client */
		gtype = cgtype;
	else	CTX_set_clientgtype(Conn,gtype);
	add_DGinputs(Conn,"%s",str);
	return gtype;
}

static int cache_Path(PCStr(host),int iport,int gtype,PCStr(req),PVStr(path))
{	CStr(selector,2048);
	const char *cache_dir;
	CStr(cachefile,2048);
	CStr(ext,256);
	const char *rp;
	const char *dp;
	refQStr(cp,cachefile); /**/

	setVStrEnd(path,0);
	strcpy(selector,"?");

	if( (cache_dir = cachedir()) == 0 )
		return 0;

	cp = Sprintf(AVStr(cachefile),"%s/%s/%s",cache_dir,"gopher",host);
	if( iport != serviceport("gopher") )
		cp = Sprintf(AVStr(cp),":%d",iport);

	selector[0] = ext[0] = 0;
	Xsscanf(req,"%*c/%[^\r\n\t]\t%[^\r\n\t]",AVStr(selector),AVStr(ext));

	if( selector[0] == 0 ){
		sv1log("empty selector, request = %s",req);
		rp = req;
		if( *rp == '/' )
			rp++;

		if( IS_DIR(gtype) && strchr("\r\n\t",rp[0]) )
			;
		else	return 0;
	}

	if( IS_DIR(gtype) ){
		if( selector[0] )
			cp = Sprintf(AVStr(cp),"/%s/",selector);
		else	cp = Sprintf(AVStr(cp),"/");

		if( dp = strchr(req,'\t') ){
			strcpy(ext,"?");
			Xsscanf(dp+1,"%[^\r\n\t ]",AVStr(ext));
			strcat(cp,ext);
		}else	strcat(cp,"=");

		strcpy(path,cachefile);
		return 1;
	}
	if( gtype && strchr(GOPHER_CACHE_ITEM,gtype) ){
		Sprintf(AVStr(cp),"/%s%s",selector,ext);
		strcpy(path,cachefile);
		return 1;
	}
	return 0;
}

static int relay_response(Connection *Conn,PCStr(req),int gtype,FILE *fs,FILE *tc,FILE *cachefp);

int service_gopher(Connection *Conn)
{	FILE *fc,*tc,*fs;
	FILE *cachefp;
	char gtype;
	CStr(req,2048);
	CStr(line,0x10000);
	CStr(o_buff,OBUFSIZ);
	CStr(c_buff,OBUFSIZ);
	const char *server = DFLT_HOST;
	int iport = DFLT_PORT;
	int useCache;
	CStr(cpath,2048);
	int cdate;
	int totalc;

	fc = fdopen(FromC,"r");
	if( fc == NULL )
		Exit(-1,"fdopen(FromC=%d) failed\n",FromC);
	setbuf(fc,NULL);

	tc = fdopen(ToC,"w");
	if( tc == 0 )
		Exit(-1,"fdopen(ToC=%d) failed\n",ToC);
	setbuffer(tc,o_buff,sizeof(o_buff));

	if( (gtype = fgets_selector(Conn,AVStr(req),sizeof(req),fc)) == 0 ){
		sv1log("GOPHER null REQUEST ?\n");
		return -1;
	}

	if( !service_permitted(Conn,"gopher" /*,FromC*/) ){
		CStr(myhp,MaxHostNameLen);

		ClientIF_HP(Conn,AVStr(myhp));
		fprintf(tc,"--1\r\n");
		fprintf(tc,"1 Forbidden by DeleGate on `%s'.\r\n",myhp);
		fprintf(tc,"0 Proxy Gopher Server %s\r\n",DELEGATE_version());
		fprintf(tc,".\r\n");
		fcloseLinger(tc);
		fclose(fc);
		return -1;
	}

cpath[0] = 0;
	setupConnect(Conn);
	if( without_cache() )
		useCache = 0;
	else	useCache = cache_Path(server,iport,gtype,req,AVStr(cpath));
	cachefp = NULL;
	cdate = -1;

/* 941010 if( useCache && !BORN_SPECIALIST ){ */
	if( useCache ){
		int cretry = 0;
		int expire = gopher_EXPIRE(Conn,server);
		int dontWaitCache = DontWaitCache;
		set_DG_EXPIRE(Conn,expire);

	retry_read:
		if( cachefp != NULL ){
			fclose(cachefp);
			cachefp = NULL;
		}
		cdate = -1;
		if( 5 < cretry++ )
			goto give_up;

		if( !DontReadCache )
		if( cachefp = cache_fopen_rd("GOPHER",AVStr(cpath),expire,&cdate) ){
			if( lock_for_rd("GOPHER",cretry,cpath,cachefp) != 0 ){
				sleep(CACHE_RDRETRY_INTERVAL);
				goto retry_read;
			}

			sv1log("GOPHER <= [%s] %s %d %s",cpath, server,iport,req);
			fgetsTIMEOUT(AVStr(line),sizeof(line),cachefp);
			if(line[0]=='-' && line[1]=='-'){
				sv1log("GOPHER <= ??? %s",line);
				cache_delete(cpath);
				goto retry_read;
			}
			totalc = readout_cache(Conn,req,gtype,cachefp,tc);
			fclose(cachefp); /* unlock Shared lock */

			fflush(tc); set_linger(fileno(tc),DELEGATE_LINGER);
			sv1log("GOPHER %d bytes of cached data transfered\n",totalc);
			return 0;
		}
		if( cachefp = cache_fopen_rw("GOPHER",AVStr(cpath)) ){
			if( file_lock_wr("GOPHER",cachefp) != 0 ){
				if( !DontReadCache && !dontWaitCache ){
					sleep(CACHE_WRRETRY_INTERVAL);
					goto retry_read;
				}else{
					fclose(cachefp);
					cachefp = NULL;
				}
			}else{
				DontWaitCache = 1;
				if( !DontReadCache && !dontWaitCache ){
					if( cdate != -1 )
					/*if( isGopherPlus(server) )*/
					if( !Modified(Conn,cdate,req) ){
						ftouch(cachefp,time(0));
						goto retry_read;
					}
				}
				setbuffer(cachefp,c_buff,sizeof(c_buff));
			}
		}
	} give_up:

	if( 0 < FromS ){
		sv1log("Already Connected To the Server: %d\n",FromS);
		IGNRETP write(ToS,req,strlen(req));
	}else{

/* to syncronize ? */
/* add_DGinputs(Conn,"\r\n"); */
/* This disturbs real Gopher+ server and causes premature EOF */

		if( connect_to_serv(Conn, FromC,ToC, 1) < 0 )
		{
			fprintf(tc,"--2\r\n");
			fprintf(tc,"DeleGate: connection to %s:%d failed.\n",
				DFLT_HOST,DFLT_PORT);
			fflush(tc);
			return -1;
		}
	}

	if( toMaster )
		sv1log("GOPHER -> (%s:%d) %s",server,iport,req);
	else{
		sv1log("GOPHER => (%s:%d) %s",server,iport,req);
		std_setsockopt(ToS);
	}

	fs = fdopen(FromS,"r");
	if( fs == NULL ){
		sv1log("Error fdopen(%d) failed\n",FromS);
		return -1;
	}

/* Send selector message if the server is a real server, otherwise
 * the message to the Mediator has sent in connect_to_server.
 */
/* It comes to be suppried in the connect_to_server.
   if( !toMaster ) write(ToS,req,strlen(req)); */

	totalc = relay_response(Conn,req,gtype,fs,tc,cachefp);
	sv1log("GOPHER %d bytes of data transfered\n",totalc);

	close(ToS);

	if( cachefp ){
		if( totalc <= 0 )
			cache_delete(cpath);
		else{
			sv1log("written to [%s]\n",cpath);
			Ftruncate(cachefp,0,1);
		}
		fclose(cachefp); /* unlock Exclusive lock */
	}
	return 0;
}

static int relay_response(Connection *Conn,PCStr(req),int gtype,FILE *fs,FILE *tc,FILE *cachefp)
{	int error,totalc,rcc;
	CStr(head,32);
	CStr(line,2048);

	error = 0;
	totalc = 0;
	if( IS_DIR(gtype) || is_DIR(req) || IS_SEARCH(gtype) || is_INFO(req) ){
		CTX_check_codeconvSP(Conn,1);
		for(;;){
			line[0] = 0;
			if( fgetsTIMEOUT(AVStr(line),sizeof(line),fs) == NULL ){
				error = 1;
				sv1log("GOPHER << premature EOF\n");

				/* Gopher+ */
				if( cachefp )
					gopher_fputs(Conn,gtype,req,CVStr("--2\r\n"),tc);
				break;
			}
			if( line[0] == '-' ){
				error = 1;
				if( cachefp )
				sv1log("error: %s",line);
			}

			totalc += strlen(line);
			gopher_fputs(Conn,gtype,req,AVStr(line),tc);
			fflush(tc);
			if( cachefp )
				fputs(line,cachefp);

			if( streq(line,".\r\n") ){
				totalc -= 3;
				break;
			}
		}
	}else
	if(  IS_TEXT(gtype) ){
		if( (totalc = CCV_relay_text(Conn,fs,tc,cachefp)) < 0 )
			error = 1;
	}else{
		rcc = freadTIMEOUT(AVStr(head),1,sizeof(head),fs);
		if( rcc == 0 )
			error = 1;
		else{
			/* Gopher+ */
			if( head[0] == '-' )
				error = 1;
			fwriteTIMEOUT(head,1,rcc,tc);
			if( cachefp )
			fwrite(head,1,rcc,cachefp);

			if( (totalc = copy_fileTIMEOUT(fs,tc,cachefp)) < 0 )
				error = 1;
		}
	}
	if( error && (0 < totalc) )
		totalc = -totalc;

	fcloseLinger(tc);
	Verbose("%d bytes put.\n",totalc);
	return totalc;
}

int decomp_dirent(PVStr(line),PVStr(attr),const char **uname,const char **selector,const char **host,int *iport,const char **ext)
{	const char *dp;
	int egtype;

	setVStrEnd(attr,0);
	egtype = *line;
	if( egtype == '+' ){
		if( dp = strchr(line,':') ){
			truncVStr(dp); dp++;
			strcpy(attr,line);
			strcat(attr,":");
			if( *dp == ' ' ){
				strcat(attr," ");
				dp++;
			}
			strcpy(line,dp);
			egtype = *line;
		}
	}
	dp = line + 1;
	*uname = dp;
	if(dp=strchr(dp,'\t')){ truncVStr(dp);dp++; *selector = dp; }else return 0;
	if(dp=strchr(dp,'\t')){ truncVStr(dp);dp++; *host = dp;     }else return 0;
	if(dp=strchr(dp,'\t')){ truncVStr(dp);dp++; *iport=atoi(dp);}else return 0;
	if(dp=strchr(dp,'\t')){ *ext = dp;               }
			else  { *ext = "\r\n";	         }

	return egtype;
}

static int isGopherPlus(PCStr(host))
{	CStr(path,1024);
	const char *cache_dir;

	cache_dir = cachedir();
	sprintf(path,"%s/%s/+",cache_dir,"gopher",host);
	if( fileIsflat(path) )
		return 1;
	sprintf(path,"%s/%s/$",cache_dir,"gopher",host);
	if( fileIsflat(path) )
		return 1;
	return 0;
}

static int dirent2html(Connection *Conn,FILE *fs,FILE *tc,PCStr(iconbase))
{	CStr(dirent,2048);
	CStr(cdirent,2048);
	CStr(html,2048);
	CStr(attr,256);
	char gtype;
	const char *uname;
	const char *selector;
	const char *host;
	const char *ext;
	CStr(hostport,MaxHostNameLen);
	CStr(xsel,SELSZ);
	const char *space;
	int iport;
	refQStr(hp,html); /**/
	CStr(url,SELSZ);
	const char *img;
	const char *alt;
	int lines,gplus,error;
	int do_conv;
	int totalc = 0;

	gplus = 0;
	lines = 0;
	error = 0;
	do_conv = CTX_check_codeconvSP(Conn,1);

	/* Avoid X-Mosaic bug (?) which specially treat '?' character
	 * in within first 2 bytes (?)
	 */
	space = "- ";

	while( fgetsTIMEOUT(AVStr(dirent),sizeof(dirent),fs) != NULL ){
		totalc += strlen(dirent);
		if( streq(dirent,".\r\n") )
			break;
		if( lines == 0 && dirent[0] == '-' && dirent[1] == '-' )
			error = 1;
		lines++;

		if( do_conv ){
			CTX_line_codeconv(Conn,dirent,AVStr(cdirent),"text/html");
			strcpy(dirent,cdirent);
		}

		gtype = decomp_dirent(AVStr(dirent),AVStr(attr),
			&uname,&selector,&host,&iport,&ext);

		if( gtype == 0 ){
			Verbose("%s",dirent);
			continue;
		}
		if( host == 0 || *host == 0 ){
			fprintf(tc,"%s<BR>\n",dirent);
			continue;
		}

		switch( gtype ){
		    case '0': alt="[TXT]"; img="text.gif";	break;
		    case '1': alt="[DIR]"; img="directory.gif";	break;
		    case '2': alt="[???]"; img="unknown.gif";	break;
		    case '3': alt="[ERR]"; img="unknown.gif";	break;
		    case '4': alt="[HEX]"; img="binhex.gif";	break;
		    case '5': alt="[BIN]"; img="binary.gif";	break;
		    case '6': alt="[UUE]"; img="uu.gif";	break;
		    case '7': alt="[IDX]"; img="index.gif";	break;
		    case '8': alt="[TEL]"; img="telnet.gif";	break;
		    case '9': alt="[BIN]"; img="binary.gif";	break;
		    case 'g': alt="[GIF]"; img="image.gif";	break;
		    case 'I': alt="[IMG]"; img="image.gif";	break;
		    case 'T': alt="[TEL]"; img="telnet.gif";	break;
		    default:  alt="[???]"; img="unknown.gif";	break;
		}

		nonxalpha_escapeX(selector,AVStr(xsel),sizeof(xsel));
		if( iport == 0 || iport == serviceport("gopher") )
			sprintf(hostport,"%s",host);
		else	sprintf(hostport,"%s:%d",host,iport);

		if( gtype == '8' || gtype == 'T' )
			sprintf(url,"telnet://%s/%s",hostport,xsel);
		else{
			if( is_redirected_selector(xsel) && GOPHER_ON_HTTP )
				sprintf(url,"http://%s/%s",hostport,xsel);
			else{
			sprintf(url,"gopher://%s/%c%s",hostport,gtype,xsel);
			redirect_url(Conn,url,AVStr(url));
			}
		}

		hp = html;
		hp = Sprintf(AVStr(hp),"<IMG ALT=\"%s\" SRC=\"%s%s\" ALIGN=TOP>",alt,
			iconbase,img);
		hp = Sprintf(AVStr(hp),"<A HREF=\"%s\">",url);
		hp = Sprintf(AVStr(hp),"%s%s</A><BR>\n",space,uname);
		fputs(html,tc);
	}
	fprintf(tc,"<HR>\n");
	if( gplus )
		fprintf(tc,"[Gopher+]");
	/* if( charset ) fprintf("[charset=%s]",charset); */

	putFrogForDeleGate(Conn,tc,"[%d line%s]",lines,1<lines?"s":"");
	fflush(tc);
	return totalc;
}

int HttpGopher(Connection *Conn,int vno,int svsock,PCStr(server),int iport,int gtype,PCStr(path))
{	int msock;
	FILE *tc,*fs;
	const char *ctype;
	CStr(xpath,2048);
	CStr(iconbase,1024);
	int totalc;
	CStr(request,2048);
	CStr(dserv,256);
	int toHTML;

	del_DGlocalheader(Conn); /* expects raw/transparent gopher server */
	nonxalpha_unescape(path,AVStr(xpath),1);
	path = xpath;
	sprintf(request,"%s\r\n",path);

	tc = fdopen(dup(ToC),"w");

	sprintf(dserv,"Gopher/HTTP gateway ETL-DeleGate/%s",DELEGATE_ver());
	if( gtype == '7' ){
		CStr(req,2048);
		const char *dp; /* not "const" but fixed length */

		if( strchr(path,'?') == 0 ){
			sv1log("GENERATED Searchable Gopher Index\n");
			setConnDone(Conn);
			totalc = putHttpHeaderV(Conn,tc,vno,dserv,"text/html",(char*)0,0,0,0);
			fprintf(tc,"<B>Searchable Gopher Index</B>\n<ISINDEX>\n");
			totalc += putFrogForDeleGate(Conn,tc,"");
			fflush(tc);
			goto EXIT;
		}
		strcpy(req,path);
		if( dp = strchr(req,'?') )
			*(char*)dp = '\t';
		sprintf(request,"%s\r\n",req);
	}
	if( streq(request,"/\r\n") )
		strcpy(request,"\r\n");

	if( (msock = svsock) == -1 )
	if( (msock = connect_to_serv(Conn,FromC,ToC,0)) < 0 ){
		totalc = -1;
		goto EXIT;
	}

	IGNRETP write(msock,request,strlen(request));
	Verbose("Gopher/HTTP: %s",request);
	setConnDone(Conn);

	fs = fdopen(msock,"r");
/* setbuf(fs,NULL); */

	switch( gtype ){
		case '0': ctype = "text/plain";	break;
		case '1':
		case '7': ctype = "text/html";	break;
		case 'g': ctype = "image/gif";	break;
		case 'I': ctype = "image/gif";	break;
		case '-': ctype = "text/plain";	break;
		default:
		case '9': ctype = "application/octet-stream"; break;
	}

	if( streq(ctype,"text/plain") && plain2html() ){
		toHTML = 1;
		totalc = 11;
		ctype = "text/html";
	}else{
		toHTML = 0;
		totalc = 0;
	}
	putHttpHeaderV(Conn,tc,vno,dserv,ctype,(char*)0,0,0,0);
	if( toHTML )
		fputs("<PRE>",tc);

	if( DELEGATE_IMAGEDIR )
		strcpy(iconbase,DELEGATE_IMAGEDIR);
	else	getCERNiconBase(Conn,AVStr(iconbase));

	if( gtype == '0' ){
		totalc += CCV_relay_text(Conn,fs,tc,NULL);
	}else
	if( gtype == '1' || gtype == '7' ){
		CStr(hostport,MaxHostNameLen);
		CStr(gpath,2048);

		HostPort(AVStr(hostport),"gopher",server,iport);
		fprintf(tc,"<I> GopherMenu </I> ");
		fprintf(tc,"<B>\n");
/*
fprintf(tc,"gopher://%s/%c%s\n",hostport,gtype,path);
*/
		if( strcmp(path,"/") == 0 )
			gpath[0] = 0;
		else	sprintf(gpath,"%c%s",gtype,path);
		putAncestorAnchor(Conn,tc,"gopher",server,iport,gpath,0);

		fprintf(tc,"</B>\n");
		fprintf(tc,"<HR>\n");
		totalc += dirent2html(Conn,fs,tc,iconbase);
	}else{
		fflush(tc);
/*
		totalc += relay_svcl(Conn,-1,ToC,msock,-1,1,512);
*/
		totalc += copy_fileTIMEOUT(fs,tc,NULL);
	}
	if( toHTML )
		fputs("</PRE>",tc);
	fcloseLinger(tc);
	tc = NULL;
	Verbose("GOPHER: %d bytes put.\n",totalc);

	fclose(fs);
EXIT:
	if( tc != NULL )
		fcloseTIMEOUT(tc);
	return totalc;
}
