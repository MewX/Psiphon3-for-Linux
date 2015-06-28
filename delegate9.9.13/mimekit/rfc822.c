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
Program:	rfc822.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	941008	extracted from nntp.c
	950312	encode/decode parts in a multipart message
	951029	extracted from mime.c of DeleGate
//////////////////////////////////////////////////////////////////////#*/
#include "config.h"
#define DOFGSZ
#include "mime.h"
char *nextField(PCStr(field),int ignEOH);
void RFC822_strip_lwsp(PCStr(src),PVStr(dst),int size);
int replace_charset_value(PVStr(ctype),PCStr(charset),int force);

#define getFieldValue(str,fld,buf,siz) getFieldValue2(str,fld,buf,siz)

char *findField(PCStr(head),PCStr(field),const char **value)
{	const char *nsp;
	const char *csp;
	const char *fsp;
	int flen;

	if( field == NULL || field[0] == 0 )
		flen = 0;
	else	flen = strlen(field);

	for( csp = head; *csp; csp = nsp ){
		if( flen == 0 )
			while( *csp && *csp != ':' && *csp != ' ' )
				csp++;

		if( flen == 0 || strncasecmp(csp,field,flen) == 0 )
		if( csp[flen] == ':' || csp[flen] == ' ' ){
			if( flen == 0 )
				fsp = head;
			else{
				fsp = csp;
				csp += flen;
			}
			while( *csp == ' ' ) csp++;
			if( *csp == ':' ) csp++;
			while( *csp == ' ' ) csp++;
			if( value )
				*value = (char*)csp;
			return (char*)fsp;
		}
		if( nsp = strchr(csp,'\n') )
			nsp++;
		else	return 0;
	}
	return 0;
}

int rmField(PVStr(head),PCStr(field))
{	const char *fp;
	const char *np;
	int nf;

	nf = 0;
	while( fp = findField(head,field,NULL) ){
		if( np = strchr(fp,'\n') )
			ovstrcpy((char*)fp,np+1);
		else	truncVStr(fp);
		nf++;
	}
	return nf;
}

char *findFieldValue(PCStr(head),PCStr(field))
{	const char *value;

	if( findField(head,field,&value) )
		return (char*)value;
	else	return NULL;
}

char *RFC822_valuescan(PCStr(vp),PVStr(value),int size)
{	char ch;
	refQStr(bp,value); /**/
	int cc;
	int pch = -1;

	alertVStr(value,size);
	for( cc = 1; cc < size && (ch = *vp++); cc++ ){
		if( ch == '\r' )
			continue;

		if( ch == '\n' ){
			if( *vp == ' ' || *vp == '\t' )
				continue;
			break;
		}
		if( ch == '\t' )
			ch = ' ';

		if( ch == ' ' && pch == ' ' )
			continue;
		pch = ch;

		setVStrPtrInc(bp,ch);
	}
	setVStrEnd(bp,0);
	return (char*)vp;
}

char *getFieldValue2(PCStr(head),PCStr(field),PVStr(value),int size)
{	const char *vp;

	if( vp = findFieldValue(head,field) ){
		RFC822_valuescan(vp,BVStr(value),size);
		return (char*)value;
	}
	setVStrEnd(value,0);
	return NULL;
}

void RFC822_decompField2(PCStr(head),PVStr(fname),PVStr(value),int size)
{	const char *hp;

	if( fname != NULL ){
		hp = wordscanY(head,BVStr(fname),64,"^ :");
		if( *hp == ' ' || *hp == ':' )
			hp++;
		RFC822_valuescan(hp,BVStr(value),size);
	}else
	if( value != NULL )
		getFieldValue(head,"",BVStr(value),size);
}

static void fgetsContLines(FILE *fp,PVStr(line),int siz){
	refQStr(lp,line);
	int rem;

	lp = line + strlen(line);
	rem = siz - (lp - line);
	while( 2 < rem ){
		if( fgets(lp,rem,fp) == NULL )
			break;
		if( *lp == ' ' || *lp == '\t' || *lp == '#' ){
			lp += strlen(lp);
			rem = siz - (lp - line);
		}else{
			setVStrEnd(lp,0);
			break;
		}
	}
}
char *fgetsHeaderField(FILE *hfp,PCStr(name),PVStr(value),int size)
{	CStr(line,1024);
	const char *vp;
	int len;
	int found;
	int off;

	len = strlen(name);
	found = 0;
	setVStrEnd(value,0);

	off = ftell(hfp);
	for(;;){
		if( isWindowsCE() ){
			if( fgets(line,sizeof(line),hfp) == NULL )
				break;
			if( line[0] == 0 || isEOR(line) )
				break;
		}else
		if( RFC822_fgetsHeaderField(AVStr(line),sizeof(line),hfp) == NULL )
			break;
		if( line[0] == '\r' || line[0] == '\n' )
			break;
		if( strncasecmp(line,name,len) == 0 ){
			if( isWindowsCE() ){
				fgetsContLines(hfp,AVStr(line),sizeof(line));
			}
			vp = line + len;
			while( *vp == ' ' )
				vp++;
			if( *vp == ':' ){
				found++;
				vp++;
				RFC822_strip_lwsp(vp,BVStr(value),size);
			}
		}
	}
	fseek(hfp,off,0);

	if( found )
		return (char*)value;
	else	return NULL;
}

static int strsubstr(PCStr(n1),PCStr(n2))
{
	return strstr(n1,n2) == n1 || strstr(n2,n1) == n2;
}
int (*NNTP_nodematch)(const char*,const char*) = strsubstr;

int findXref(FILE *afp,int (*matchfunc)(const char*,const char*),PCStr(host),PVStr(xref),int size)
{	CStr(line,1024);
	CStr(node,256);
	const char *dp;
	char dc;
	const char *ep;
	int off,found;

	if( matchfunc == NULL )
		matchfunc = strsubstr;

	setVStrEnd(xref,0);
	off = ftell(afp);
	found = 0;

	while( fgets(line,sizeof(line),afp) != NULL ){
		if( line[0] == '\r' || line[0] == '\n' )
			break;
		if( line[0] == '.' )
		if( line[1] == '\r' || line[1] == '\n' )
			break;

		if( isspace(line[0]) )
			continue;

		if( (dp = strchr(line,':')) == 0 )
			continue;
		truncVStr(dp); dp++;
		if( strcasecmp(line,"Xref") != 0 )
			continue;

		while( *dp && isspace(*dp) )
			dp++;

		wordscanX(dp,AVStr(node),sizeof(node));
		if( !(*matchfunc)(host,node) ) 
			continue;

		if( ep = strpbrk(dp,"\r\n") )
			truncVStr(ep); /* must treat folded line ... */

		strncpy(xref,dp,size-1); setVStrEnd(xref,size-1);
		found = 1;
		break;
	}
	fseek(afp,off,0);
	return found;
}

void selectXref(PCStr(host),PCStr(xref1),PVStr(xref2))
{	const char *sp;
	refQStr(dp,xref2); /**/
	const char *xp;
	CStr(name,512);
	CStr(host1,512);
	char ch;
	int getit;
	int len;

	len = strlen(host);
	sp = xref1;
	getit = 0;

	while( ch = *sp ){
		if( ch != ' ' && ch != '\t' ){
			getit = 0;
			if( strncasecmp(sp,"Xref",4) == 0 )
			if( xp = strchr(sp,':') ){
				wordscanX(xp+1,AVStr(host1),sizeof(host1));
				if( strncasecmp(host1,host,len) == 0 )
				if( host1[len] == 0 || host1[len] == '.' )
					getit = 1;
			}
		}
		while( ch = *sp ){
			assertVStr(xref2,dp);
			sp++;
			if( getit )
				setVStrPtrInc(dp,ch);
			if( ch == '\n' )
				break;
		}
	}
	setVStrEnd(dp,0);
}

static const char *separator(PCStr(field))
{
	if( strcasecmp(field,"To")==0 || strcasecmp(field,"Cc")==0 )
		return ", ";
	if( strcasecmp(field,"Received") == 0 )
		return "; ";
	return " ";
}

int RFC821_skipheader(FILE *afp,FILE *out,PCStr(field))
{	CStr(line,1024);
	const char *lp;
	const char *dp;
	CStr(selected,1024);
	int flen,rcode,nputs;

	rcode = EOF;
	selected[0] = 0;
	nputs = 0;
	if( field != NULL )
		flen = strlen(field);
	else	flen = 0;

	while( fgets(line,sizeof(line),afp) != NULL ){
		if( line[0] == '\r' || line[0] == '\n' ){
			rcode = 0;
			break;
		}
		if( line[0] == '.' )
		if( line[1] == '\r' || line[1] == '\n' )
			break;

		if( out != NULL ){
		    if( field == NULL )
			fputs(line,out);
		    else{
			if( selected[0] == 0 ){
				if( line[flen] != ':' )
					continue;
				if( strncasecmp(line,field,flen) != 0 )
					continue;
				for( lp = line+flen+1; *lp; lp++ )
					if( !isspace(*lp) )
						break;
				if( nputs++ != 0 )
					fputs(separator(field),out);
				if( dp = strpbrk(line,"\r\n\f") )
					truncVStr(dp);
				fputs(lp,out);
			}else{
				if( isspace(line[0]) ){
					fputs(" ",out);
					fputs(line+1,out);
				}else	selected[0] = 0;
			}
		    }
		}
	}
	return rcode;
}
int RFC821_skipbody(FILE *afp,FILE *out,xPVStr(line),int size)
{	CStr(linebuf,1024);
	int rcc;

	if( line == NULL ){
		setPStr(line,linebuf,sizeof(linebuf));
		size = sizeof(linebuf);
	}
	setVStrEnd(line,0);
	rcc = 0;
	for(;;){
		if( fgets(line,size,afp) == NULL ){
			setVStrEnd(line,0);
			break;
		}
		if( line[0] == '.' )
		if( line[1] == '\r' || line[1] == '\n' )
			break;

		rcc += strlen(line);
		if( out != NULL )
			fputs(line,out);
	}
	return rcc;
}

UTag RFC822_readHeaderU(FILE *in,int seeEOR){
	int bsize = MAX_MIMEHEAD;
	UTag Ubuff;
	defQStr(buff);
	defQStr(lp);

	Ubuff = UTalloc(SB_CONN,bsize,1);
	cpyQStr(buff,Ubuff.ut_addr);
	cpyQStr(lp,buff);

	for(;;){
		if( bsize <= lp-buff+2 ){
			syslog_ERROR("ERROR: too large header > 0x%X\n",bsize);
			break;
		}
		if( fgets(lp,bsize-(lp-buff),in) == NULL )
			break;
		if( lp[0] == '\r' || lp[0] == '\n' )
			break;

		if( seeEOR )
		if( lp[0] == '.' && (lp[1] == '\r' || lp[1] == '\n') )
			break;

		lp += strlen(lp);
	}
	return Ubuff;
}
char *RFC822_readHeader(FILE *in,int seeEOR)
{	CStr(buff,MAX_MIMEHEAD);
	refQStr(lp,buff); /**/

	for(;;){
		if(sizeof(buff) <= lp-buff+2){ /* fix-140604c */
			syslog_ERROR("too large header\n");
			break;
		}
		if( fgets(lp,sizeof(buff)-(lp-buff),in) == NULL )
			break;
		if( lp[0] == '\r' || lp[0] == '\n' )
			break;

		if( seeEOR )
		if( lp[0] == '.' && (lp[1] == '\r' || lp[1] == '\n') )
			break;

		lp += strlen(lp);
	}
	return stralloc(buff);
}

static int charset_namelen(PCStr(name))
{	const char *np;
	int nc;

	for( np = name; nc = *np; np++ )
		if( nc != '_' )
		if( nc != '-' && !isalnum(nc) )
			break;
	return np - name;
}

void myMIMEversion(PVStr(ver))
{
	sprintf(ver,"1.0 (generated by MimeKit/%s)",MimeKit_Version);
}

int copyHeader(PVStr(dst),PCStr(src),int eos){
	int cc = 0;
	refQStr(dp,dst);
	const char *sp = src;
	char ch;

	while( ch = *sp++ ){
		cc++;
		if( dp ) setVStrPtrInc(dp,ch);
		if( ch != '\n' )
			continue;
		while( ch = *sp ){
			if( ch != '\r' && ch != '\n' )
				break;
			sp++;
			syslog_ERROR("removed empty line in head [0x%X]\n",ch);
		}
	}
	if( dp && eos && dp != sp ) setVStrEnd(dp,0);
	return cc;
}

char *strSeekEOHX(PCStr(head),int len);
char *strSeekEOH(PCStr(head))
{
	return strSeekEOHX(head,0);
}
char *strSeekEOHX(PCStr(head),int len)
{	const char *hp;
	const char *hx = 0;
	char ch;
	int top;

	top = 1;
	if( len ){
		hx = head + len;
	}
	for( hp = head; ch = *hp; hp++ ){
		if( hx && hx <= hp ){
			return NULL;
		}
		if( top ){
			if( ch == '\r' || ch == '\n' )
				break;
			if( ch == '.' && (hp[1] == '\r' || hp[1] == '\n') )
				break;
		}
		top = (ch == '\n');
	}
	return (char*)hp;
}
void insert_ctype(PVStr(head),PCStr(ctype))
{	refQStr(ctp,head); /**/
	CStr(EOL,4);
	CStr(ver,128);
	CStr(tmp,MAX_MIMEHEAD);

	tmp[0] = 0;
	if( strstr(head,"\r\n") )
		strcpy(EOL,"\r\n");
	else	strcpy(EOL,"\n");

	ctp = strSeekEOH(head);
	strcpy(tmp,ctp);

	if( findFieldValue(head,"MIME-Version") == NULL ){
		myMIMEversion(AVStr(ver));
		sprintf(ctp,"MIME-Version: %s%s",ver,EOL);
		ctp += strlen(ctp);
	}
	sprintf(ctp,"Content-Type: %s%s",ctype,EOL);
	strcat(ctp,tmp);
}

int get_charset(PCStr(ctype),PVStr(chset),int size)
{	const char *csp;
	int len;

	if( csp = strcasestr(ctype,"charset=") ){
		csp += strlen("charset=");
		if( *csp == '"' )
			csp++;
		len = charset_namelen(csp);
		if( size < len+1 )
			QStrncpy(chset,csp,size);
		else	QStrncpy(chset,csp,len+1);
		return len;
	}
	return 0;
}

int replace_charset(PVStr(head),PCStr(charset))
{	refQStr(ctp,head); /**/

	if( charset == NULL )
		return 0;

	if( (ctp = findFieldValue(head,"Content-Type")) == NULL ){
		CStr(ctype,1024);
		sprintf(ctype,"text/plain; charset=%s",charset);
		insert_ctype(BVStr(head),ctype);
		return 0;
	}
	return replace_charset_value(AVStr(ctp),charset,0);
}

int replace_charset_value(PVStr(ctype),PCStr(charset),int force)
{	refQStr(csp,ctype); /**/
	refQStr(cst,ctype); /**/
	CStr(tmp,MAX_MIMEHEAD);

	if( csp = strcasestr(ctype,"charset=") ){
		csp += strlen("charset=");
		if(*csp == '"')
			csp++;
		if( strncasecmp(csp,charset,strlen(charset)) == 0 )
			return 0;
		cst = csp + charset_namelen(csp);
		strcpy(tmp,cst);
		if( erase_charset_param(AVStr(tmp),VStrNULL) ){
			syslog_ERROR("erased dup. charset in %s",ctype);
		}
		/*
		strcpy(csp,charset);
		*/
		copyHeader(AVStr(csp),charset,1);
		strcat(csp,tmp);
	}else{
		if( (cst = strpbrk(ctype,";\r\n")) == 0 ){
			if( force )
				cst = (char*)ctype + strlen(ctype);
			else	return 0;
		}
		strcpy(tmp,cst);
		sprintf(cst,"; charset=%s",charset);
		copyHeader(AVStr(cst),cst,1);
		strcat(cst,tmp);
	}
	return 1;
}

int erase_charset_param(PVStr(ctype),PVStr(charset))
{	const char *sp;
	const char *np;
	const char *pat;
	defQStr(cset); /*alt*/
	CStr(csetb,32);
	int len;

	if( charset )
		setQStr(cset,charset,(UTail(charset)-charset)+1);
	else	setQStr(cset,csetb,sizeof(csetb));

	pat = "charset=";
	len = strlen(pat);
	for( sp = ctype; *sp; sp++ )
	if( *sp == ';' ){
		while( isspace(sp[1]) )
			sp++;
		if( strncasecmp(sp+1,pat,len) == 0 ){
			np = valuescanX(sp+1+len,AVStr(cset),sizeof(csetb));
			ovstrcpy((char*)sp,np);
			return np - sp;
		}
	}
	return 0;
}

int replaceFieldValue(PVStr(head),PCStr(field),PCStr(value))
{	refQStr(esp,head); /**/
	CStr(tmp,MAX_MIMEHEAD);
	char ch;
	refQStr(np,head); /**/
	const char *EOL;

	if( (esp = findFieldValue(head,field)) == NULL ){
		np = strSeekEOH(head);
		strcpy(tmp,np);
		if( strstr(head,"\r\n") )
			EOL = "\r\n";
		else	EOL = "\n";
		sprintf(np,"%s: %s%s%s",field,value,EOL,tmp);
		/*
		sprintf(np,"%s: %s\r\n%s",field,value,tmp);
		*/
		return 0;
	}

	if( strncasecmp(esp,value,strlen(value)) == 0 )
	{
		lineScan(esp,tmp);
		if( strcasecmp(tmp,value) == 0 )
		return 0;
	}

	/*
	for( np = esp; ch = *np; np++ )
		if( ch == '\r' || ch == '\n' )
			break;
	*/
	np = nextField(esp,0);
	if( head < np && np[-1] == '\n' ){
		np--;
		if( head < np && np[-1] == '\r' )
			np--;
	}
	strcpy(tmp,np);
	/*
	strcpy(esp,value);
	*/
	copyHeader(AVStr(esp),value,1);
	strcat(esp,tmp);
	return 1;
}

void RFC822_addHeaderField(PVStr(dst),PCStr(src))
{	refQStr(tp,dst); /**/

	if( (tp = strstr(dst,"\r\n\r\n")) && tp[4] == 0  ){
		/*
		Xstrcpy(QVStr(tp+2,dst),src);
		*/
		copyHeader(DVStr(tp,2),src,1);
		strcat(tp,"\r\n");
	}else{
		int len = copyHeader(VStrNULL,src,0);
		if( len != strlen(src) ){
			Xmemmove(DVStr(dst,len),dst,strlen(dst)+1);
			copyHeader(AVStr(dst),src,0);
		}else
		Strins(BVStr(dst),src);
	}
}

int replaceContentType(PVStr(head),PCStr(type))
{	refQStr(ctp,head); /**/
	const char *cst;
	CStr(tmp,MAX_MIMEHEAD);
	const char *tp;

	ctp = findFieldValue(head,"Content-Type");
	if( ctp == NULL ){
		tp = stralloc(head);
		sprintf(head,"Content-Type: %s\r\n%s",type,tp);
		free((char*)tp);
		return 0;
	}
	if( (cst = strpbrk(ctp,";\r\n")) == 0 )
		return -1;
	strcpy(tmp,cst);
	strcpy(ctp,type);
	strcat(ctp,tmp);
	return 1;
}

char *RFC822_fgetsHeaderField(PVStr(line),int size,FILE *fp)
{	refQStr(lp,line); /**/
	int rcc,rem,ch;
	
	if( fgets(line,size,fp) == NULL )
		return NULL;
	cpyQStr(lp,line);
	if( *lp == 0 || *lp == '\r' || *lp == '\n' || isEOR(lp) )
		return (char*)line;

	rcc = strlen(line);
	lp = (char*)line + rcc;
	rem = size - rcc;

	while( 80 < rem ){
		ch = getc(fp);
		if( ch == EOF )
			break;
		if( ch != ' ' && ch != '\t' && ch != '#' ){
			ungetc(ch,fp);
			break;
		}
		setVStrPtrInc(lp,ch); setVStrEnd(lp,0); rem--;
		if( fgets(lp,rem,fp) == NULL )
			break;
		rcc = strlen(lp);
		lp += rcc;
		rem -= rcc;
	}
	if( lp == line )
		return NULL;
	else	return (char*)line;
}

char *nextField(PCStr(field),int ignEOH)
{	const char *np;
	char nc;
	int top;

	top = 0;
	for( np = field; nc = *np; np++ ){
		if( top ){
			if( nc == ' ' || nc == '\t' )
				top = 0;
			else
			if( !ignEOH || (nc != '\n' && nc != '\r') )
				break;
		}else{
			if( nc == '\n' )
				top = 1;
			else	top = 0;
		}
	}
	return (char*)np;
}

void filterFields(PCStr(spec),PVStr(head))
{	const char *sp;
	CStr(field,1024);
	CStr(aval,1024);
	const char *hp;
	const char *bp;
	const char *tp;
	int pass,match;
	int plen,flen;
	defQStr(headbuf); /*alloc*/
	defQStr(hbp); /*alloc*//**/

	pass = 0;
	sp = spec;

	for( sp = spec; *sp; sp = nextField(sp,1) ){
		if( strncasecmp(sp,"Pass/",5) == 0 ){
			pass = 1;
			setQStr(headbuf,stralloc(head),strlen(head)+1);
			cpyQStr(hbp,headbuf);
			break;
		}
	}
	if( pass )
		plen = 5;
	else	plen = 7;

	for( sp = spec; *sp; sp = nextField(sp,1) ){
		if( pass ){
			if( strncasecmp(sp,"Pass/",5) != 0 )
				continue;
		}else{
			if( strncasecmp(sp,"Remove/",7) != 0 )
				continue;
		}

		fieldScan(sp+plen,field,aval);
		flen = strlen(field);

		for( hp = head; *hp; ){
			match = 0;
			if( strncasecmp(hp,field,flen) == 0 )
			if( hp[flen] == ':' )
			if( strstr(&hp[flen+1],aval) )
				match = 1;

			tp = nextField(hp,0);
			if( pass ){
				if( match ){
					for( bp = hp; *bp && bp != tp; bp++ )
						setVStrPtrInc(hbp,*bp);
				}
				hp = tp;
			}else{
				if( match )
					ovstrcpy((char*)hp,tp);
				else	hp = tp;
			}

			if( *hp == '\r' || *hp == '\n'
			 || *hp == '.' && (hp[1] == '\r' || hp[1] == '\n') )
				break;
		}
	}
	if( pass ){
		setVStrEnd(hbp,0);
		strcpy(hbp,strSeekEOH(head));
		strcpy(head,headbuf);
		free((char*)headbuf);
	}
}

int removeField1(PVStr(head),PCStr(field)){
	refQStr(fi1,head);
	refQStr(fi2,head);

	fi1 = (char*)field;
	if( fi2 = nextField(fi1,0) ){
		strcpy(fi1,fi2);
		return 1;
	}
	return 0;
}
int removeFields(PVStr(head),PCStr(field),int wild)
{	refQStr(dp,head); /**/
	const char *sp;
	char ch;
	int flen,top,skip;
	int nrem = 0;

	flen = strlen(field);
	top = 1;
	skip = 0;
	for( sp = head; ch = *sp; sp++ ){
		if( top ){
			if( strncmp(sp,field,flen) == 0
			 && (wild || (sp[flen]==':'||sp[flen]==' ')) )
			{
				skip = 1;
				nrem++;
			}
			else
			if( ch != ' ' && ch != '\t' )
				skip = 0;
		}
		if( !skip )
			setVStrPtrInc(dp,ch);

		if( ch == '\n' )
			top = 1;
		else	top = 0;
	}
	setVStrEnd(dp,0);
	return nrem;
}

/*
 *    MATCHFIELDS
 *	Returns the first "field" which match with the "spec":
 *	  [Tail/] field [*] : [ivalue]
 */
const char *matchFields(PCStr(spec),PCStr(field),PCStr(ivalue))
{	const char *afield;
	const char *avalue;
	CStr(aval,1024);
	int tail = 0;

	afield = findField(spec,field,&avalue);
	if( afield == NULL )
		return "";
	do{
		if( tail = strncmp(afield,"Tail/",5) == 0 )
			afield += 5;

		getFieldValue(afield,field,AVStr(aval),sizeof(aval));
		if( tail ){
			if( strtailstr(ivalue,aval) != NULL )
				return (char*)afield;
		}else{
			if( strstr(ivalue,aval) != NULL )
				return (char*)afield;
		}
	} while( afield = findField(afield+1,field,&avalue) );
	return NULL;
}

void relayRESPBODY(FILE *fs,FILE *tc,PVStr(line),int size)
{
	for(;;){
		setVStrEnd(line,0);
		if( fgets(line,size,fs) == NULL )
			break;
		if( isEOR(line) )
			break;
		fputs(line,tc);
	}
}

void RFC822_strip_lwsp(PCStr(src),PVStr(dst),int size)
{	const char *sp;
	refQStr(dp,dst); /**/
	char sc;
	char pc;
	char nc;
	const char *dx;
	int nonsp;

	nonsp = 0;
	pc = 0;
	alertVStr(dst,size);
	dx = dst + size - 1;
	for( sp = src; sc = *sp; sp++ ){
		if( dx <= dp )
			break;
		if( sc == '\r' || sc == '\n' ){
			nonsp = 0;
		}else
		if( sc == '\t' || sc == ' ' ){
			if( dp == dst )
				continue;
			nc = sp[1];
			if( nc == '\r' || nc == '\n' || nc == '\0' )
				continue;
			if( pc != ' ' ){
				pc = ' ';
				setVStrPtrInc(dp,pc);
			}
		}else{
			nonsp++;
			pc = sc;
			setVStrPtrInc(dp,pc);
		}
	}
	setVStrEnd(dp,0);
}

void RFC822_strip_commentX(PCStr(in),PVStr(out),int siz)
{	const char *sp;
	refQStr(dp,out); /**/
	const char *xp;
	char sc;
	int lev;

	lev = 0;
	alertVStr(out,siz);
	xp = out + siz - 1;

	for( sp = in; sc = *sp; sp++ ){
		if( xp <= dp )
			break;
		if( sc == '(' )
			lev++;
		else
		if( sc == ')' ){
			lev--;
			if( lev == 0 && (sp[1] == ' ' || sp[1] == '\t') )
				sp++;
		}else
		if( lev == 0 ){
			setVStrPtrInc(dp,sc);
		}
	}
	setVStrEnd(dp,0);
}

/*
 * any non-ASCII (7bit x multi-bytes code) strings must be ignored...
 * but such strings are expected to be encoded in MIME...
 */
void RFC822_addresspartX(PCStr(in),PVStr(out),int siz)
{	CStr(buff,2048);
	const char *sp;
	refQStr(dp,out); /**/
	const char *xp;
	CStr(inx,2048);
	unsigned char sc;

	MIME_strHeaderEncode(in,AVStr(inx),sizeof(inx)); /* non-ASCII escaped */
	RFC822_strip_commentX(inx,AVStr(buff),sizeof(buff));
	alertVStr(out,siz);
	xp = out + siz - 1;

	for( sp = buff; sc = *sp; sp++ ){
		if( xp <= dp )
			break;
		if( sc == '<' ){
			cpyQStr(dp,out);
			for( sp += 1; sc = *sp; sp++ ){
				if( isspace(sc) )
					continue;
				if( sc == '>' )
					break;
				setVStrPtrInc(dp,sc);
			}
			break;
		}else
		if( isspace(sc) )
			continue;
		else{
			setVStrPtrInc(dp,sc); 
		}
	}
EXIT:
	setVStrEnd(dp,0);
}


void msg_charcount(FILE *fp,int chcount[])
{	int off;
	CStr(line,1024);
	CStr(xline,1024);
/* bad for BCGCC
	int ccx[64],oc,ci,ch;
*/
	CStr(ccx,64);
	int oc,ci,ch;
	int uu;

	off = ftell(fp);
	CCXcreate("*","E",(CCXP)ccx);
	for( ci = 0; ci < 256; ci++ )
		chcount[ci] = 0;

	/* skip the header if necessary... */

	uu = 0;
	while( fgets(line,sizeof(line),fp) ){
		if( uu_skip(&uu,line) )
			continue;

		oc = CCXexec((CCXP)ccx,line,strlen(line),AVStr(xline),sizeof(xline));
		for( ci = 0; ci < oc; ci++ ){
			ch = 0xFF & xline[ci];
			if( ch == '!' ){
				/* count only '!' at the end of sentense ... */
				if( ci == 0 ) /* maybe "diff" ountput ... */
					continue;
				if( strchr("!? <\t\r\n",xline[ci+1]) == 0 )
					continue;
			}
			chcount[ch] += 1;
		}
	}
	fseek(fp,off,0);
}

extern int (*MIME_mapPosterAddr)(PCStr(maddr),PVStr(xmaddr));
extern int (*MIME_mapMessageId)(PCStr(xref),PCStr(msgid),PVStr(xmsgid));
extern int (*MIME_makeEmailFP)(PVStr(ocrc),PCStr(addr));
extern int (*MIME_makeEmailCX)(PVStr(ocrc),PCStr(wf),PCStr(addr));
const char *MIME_mapPosterBase = "mbox@host.domain";
const char *MIME_nomapMailAddrs;
const char *MIME_nomapMailAddrsFields;

int nomapMailAddr(PCStr(addr)){
	if( MIME_nomapMailAddrs == 0 )
		return 0;
	if( isinListX(MIME_nomapMailAddrs,addr,"cs") ){
/*
 fprintf(stderr,"-- Nomap[%s][%s]\n",MIME_nomapMailAddrs,addr);
*/
		return 1;
	}
/*
 fprintf(stderr,"-- Domap[%s][%s]\n",MIME_nomapMailAddrs,addr);
*/
	return 0;
}
/*
void mapEmailAddr(PCStr(spec),PCStr(addr),PVStr(xaddr),int xsiz)
*/
void mapEmailAddr(PCStr(field),PCStr(spec),PCStr(addr),PVStr(xaddr),int xsiz)
{	const char *dp;
	refQStr(xp,xaddr); /**/
	const char *fp;
	char fc;
	const char *op;
	CStr(ocrc,32);
	CStr(oloc,256);
	CStr(ohost,256);
	CStr(odomL,256);
	CStr(odom1,256);
	CStr(odomU,256);
	CStr(odomT,256);
	CStr(ogdom,256);
	CStr(odfull,256);
	int xrem,os;
	int nomap = 0;

	if( strtailstr(addr,MIME_mapPosterBase) ){
		strcpy(xaddr,addr);
		return;
	}
	dp = wordscanY(addr,AVStr(oloc),sizeof(oloc),"^@");
	if( *dp == '@' ){
		if( MIME_nomapMailAddrsFields == 0 ){
			if( strchr(MIME_nomapMailAddrs,':') ){
				IStr(addrs,1024);
				IStr(fields,128);
				fieldScan(MIME_nomapMailAddrs,addrs,fields);
				MIME_nomapMailAddrs = stralloc(addrs);
				MIME_nomapMailAddrsFields = stralloc(fields);
			}
		}
		/*
		nomap = nomapMailAddr(dp+1);
		*/
		nomap = nomapMailAddr(addr);
		if( nomap )
		if( strcaseeq(field,"Reply-To") ){
			strcpy(xaddr,addr);
			return;
		}
		if( nomap )
		if( MIME_nomapMailAddrsFields != 0 ){
			/* 9.9.1: NNTPCONF=nomapemail:{emails}[:{fields}]
			 * Apply "nomapemail" to specified fields.
			 * "nomapemail" is introduced in 9.0.6 to be applied
			 * to any filed and body by default as described in
			 * Manual.htm but it is implemented to be applied
			 * only to Reply-To from the beginning...
			 */
			if( streq(MIME_nomapMailAddrsFields,"*")
			 || streq(MIME_nomapMailAddrsFields,"{*}")
			 || isinListX(MIME_nomapMailAddrsFields,field,"c") ){
				strcpy(xaddr,addr);
				return;
			}
		}
	}
	if( MIME_mapPosterAddr )
	if( (*MIME_mapPosterAddr)(addr,AVStr(xaddr)) ){
		return;
	}
	ohost[0] = odomL[0] = 0;
	odom1[0] = odomU[0] = odomT[0] = 0;
	ogdom[0] = odfull[0] = 0;
	if( *dp == '@' ){
		if( nomap ){
			strcpy(xaddr,addr);
			return;
		}
		wordScan(dp+1,odfull);
		wordScan(dp+1,ohost);
		wordScan(dp+1,ogdom);
		generic_domain(AVStr(ogdom)); /* registered domain part */
		if( dp = strstr(ohost,ogdom) )
			truncVStr(dp);
		if( dp = strrchr(ohost,'.') ){
			truncVStr(dp);
			wordScan(dp+1,odomL);
		}
		if( dp = strchr(ogdom,'.') )
			wordScan(dp+1,odomU);
		if( dp = strrchr(ogdom,'.') )
			wordScan(dp+1,odomT);
		wordscanY(ogdom,AVStr(odom1),sizeof(odom1),"^.");
	}
	/*
	syslog_ERROR("### [%s] @ [%s] [%s] [%s] [%s]\n",
		oloc,ohost,odomL,odom1,ogdom);
	*/

	cpyQStr(xp,xaddr);
	xrem = xsiz;
	for( fp = spec; fc = *fp; fp++ ){
		op = 0;
		if( fc != '%' ){
			op = fp;
			os = 1;
		}else{
			CStr(wf,128);
			refQStr(wp,wf);

			if( (fc = *++fp) == 0 )
				break;
			while( isdigit(fc) ){
				setVStrPtrInc(wp,fc);
				fc = *++fp;
			}
			setVStrEnd(wp,0);

			/* l@h.L.r.U.c */
			switch( fc ){
			  case '%': op = "%"; break;
			  case 'X': op = ocrc; /* CRC32(addr) */
				if( MIME_makeEmailCX )
				  (*MIME_makeEmailCX)(AVStr(ocrc),wf,addr);
				else	strcpy(ocrc,"(%X)");
				break;
			  case 'B': op = ocrc; /* CRC32(addr) */
				if( MIME_makeEmailFP )
				  (*MIME_makeEmailFP)(AVStr(ocrc),addr);
				else	strcpy(ocrc,"(%B)");
				break;
			  case 'l': op = oloc; break; /* l */
			  case 'h': op = ohost; break; /* h */
			  case 'L': op = odomL; break; /* L */
			  case 'r': op = odom1; break; /* r */
			  case 'u': op = odomU; break; /* U.c */
			  case 'c': if( strlen(odomT) == 2 ) op = odomT;
				break; /* c */
			  case 't': op = odomT; break; /* c */
			  case 'g': op = ogdom; break; /* r.U.c */
			  case 'f': op = odfull; break; /* h.L.r.U.c */
			}
			if( op )
				os = strlen(op);
		}
		if( op == 0 )
			continue;

		xrem -= os;
		if( xrem < 1 ){
			syslog_ERROR("mapEmailAddr overflow %d: %s[%s]%d\n",
				xsiz,xaddr,op,os);
			break;
		}
		Bcopy(op,xp,os);
		xp += os;
	}
	setVStrEnd(xp,0);
	/*
	syslog_ERROR("### -> [%s]\n",xaddr);
	*/
}

/*
void rewriteEmailAddr(PVStr(head),PCStr(field),PCStr(spec))
*/
void rewriteMessageID(PVStr(head),PCStr(field),PCStr(spec),int bodyonly){
	const char *val;
	refQStr(bp,head);
	const char *np;
	CStr(oid,1024);
	CStr(nid,1024);
	CStr(xref,1024);

	truncVStr(xref);
	if( bodyonly  ){
		val = head;
	}else{
		val = findFieldValue(head,field);
		if( val == NULL ){
			return;
		}
		if( strcaseeq(field,"Message-ID") ){
			const char *xf;
			xf = findFieldValue(head,"Xref");
			if( xf != NULL ){
				Xsscanf(xf,"%*s %s",AVStr(xref));
			}
		}
	}

	for( bp = (char*)val; *bp; bp++ ){
		if( *bp == '\n' ){
			if( !isspace(bp[1]) )
				break;
		}
		if( *bp == '<' && bp[1] != 0 ){
			bp++;
			np = wordScanY(bp,oid,"^>");
			if( *np == '>' ){
				truncVStr(nid);
				if( MIME_mapMessageId
				&&(*MIME_mapMessageId)(xref,oid,AVStr(nid)) ){
					strsubst(AVStr(bp),oid,nid);
/*
 fprintf(stderr,"------- mapped msgid[%s][%s]\n",oid,nid);
*/
				}else{
				}
				bp = strchr(bp,'>');
				if( bp == 0 )
					break;
			}
		}
	}
}

int rewriteEmailAddr(PVStr(head),PCStr(field),PCStr(spec))
{	CStr(from,256);
	CStr(addr,256);
	CStr(xaddr,256);
	const char *val;
	refQStr(dp,from); /**/
	int rew;

	val = findFieldValue(head,field);
	if( val == NULL )
		return 0;
	RFC822_valuescan(val,AVStr(from),sizeof(from));
	if( strneq(head,"From ",5) && val == head+5 ){
		wordScan(head+5,addr);
	}else
	RFC822_addresspartX(from,AVStr(addr),sizeof(addr));

	mapEmailAddr(field,spec,addr,AVStr(xaddr),sizeof(xaddr));

	/*
	ofrom[0] = 0;
	if( curAnum )
		SPRINTF(ofrom,"%d.%s",curAnum,curGroup);
	else
	if( getFV(head,"Message-ID",msgid) ){
		val = msgid;
		if( *val == '<' ) val++;
		if( vp = strchr(val,'>') )
			*vp = 0;
		quotedFrom(val,ofrom);
	}
	*/

	if( dp = strstr(from,addr) ){
		if( sizeof(from) <= strlen(from)+strlen(xaddr)-strlen(addr) ){
			syslog_ERROR("rewriteEmailAddr overflow: %s [%s][%s]\n",
				from,addr,xaddr);
			setVStrEnd(xaddr,strlen(addr));
		}
		strsubst(AVStr(dp),addr,xaddr);
	}else	strcpy(from,xaddr);

	rew = replaceFieldValue(BVStr(head),field,from);
	return rew;
}

/*
static quotedFrom(PCStr(from),PVStr(qfrom))
{	const char *fp;
	refQStr(qfp,qfrom);
	char ch;

	qfp = qfrom;
	for( fp = from; ch = *fp; fp++ ){
		if( IS_GROUPNAMECH(ch) ){
			setVStrPtrInc(qfp,ch);
		}else{
			if( ch == '+' ) strcpy(qfp,"++"); else
			if( ch == '@' ) strcpy(qfp,"+."); else
					sprintf(qfp,"+%02x",ch&0xFF);
			qfp += strlen(qfp);
		}
	}
	*qfp = 0;
}
*/

char *strchr1B(PCStr(str),char ch){
	const char *sp;
	char ch1;
	int in2B = 0;
	for( sp = str; ch1 = *sp; sp++ ){
		if( ch1 == 033 ){
			if( sp[1] == '$' && sp[2] != 0 ){
				in2B = 1;
				sp += 2;
				continue;
			}else
			if( sp[1] == '(' && sp[2] != 0 ){
				in2B = 0;
				sp += 2;
				continue;
			}
		}
		if( ch1 == ch && !in2B )
			return (char*)sp;
	}
	return NULL;
}
int maskPhoneNumber(PVStr(line));
int scanAddrInBody(int mask,PCStr(spec),PVStr(line))
{	refQStr(top,line); /**/
	const char *atp;
	const char *endp;
	const char *bgnp;
	const char *dp;
	char ch;
	char nch;
	CStr(addr,256);
	CStr(xaddr,256);
	int rew;
	int dot,susp,type,next;

	rew = 0;
	if( mask & MA_PHONE ){ /* in body ... */
		rew = maskPhoneNumber(BVStr(line));
	}
	if( (mask & (MA_EMAIL|MA_MSGID)) == 0 ){
		return rew;
	}

	for( cpyQStr(top,line); ; top = (char*)atp+1 ){
		/*
		atp = strchr(top,'@');
		*/
		atp = strchr1B(top,'@');
		if( atp == 0 )
			break;

		dot = 0;
		for( endp = atp+1; ch = *endp; endp++ ){
			if( ch == '.' )
				dot++;
			else
			if( isalnum(ch) || ch == '-' || ch == '_' ){
			}else{
				break;
			}
		}
/*
 fprintf(stderr,"-- dot=%d %X %s\n",dot,ch,top);
*/
		if( dot == 0 ){
			if( ch == '>' ){
				/* can be an informal Message-ID or
				 * anonymized domain
				 */
			}else
			continue;
		}
		switch( ch ){
			case '>':
				if( endp[1] == '>' )
					type = 5;
				else	type = 1;
				break;
			case ']':
			case ')': type = 2; break;
			case '(': type = 3; break;
			case ' ':
				if( endp[1] == '(' ) type = 3; else
				if( isalpha(endp[1])) type = 4; else
					type = 5;
/*
					continue;
*/
				break;
			case 033:
				if( endp[1] != '$' ) continue;
				type = 5;
				break;
			case '^':
				if( endp[1] != 'M' ) continue;
				type = 5;
				break;
			case '|':
			case '<':
			case '&':
			case ',':
			case '\t':
			case '\r':
			case '\n':
				type = 5;
				break;
			case '\\':
				if( endp[1] == '\'' ) type = 6; else
				if( endp[1] == '"' ) type = 7; else
					continue;
				break;
			case '\'': type = 6; break;
			case '"': type = 7; break;
			case ':':
			case '/': /* in URL */
				type = 8;
				break;
			default: continue;
		}
/*
 fprintf(stderr,"-- type=%d %s\n",type,top);
*/
		/*
		sv1log("##TR## %d %s",type,top);
		*/

		susp = 0;
		if( type == 1 ){
			if( endp[1] != ' ' )
				susp++;
		}

		for( bgnp = atp-1; top <= bgnp; bgnp-- )
		switch ( ch = *bgnp ){
		  case '=':
			/* might be ADMIN=foo@bar or so */
			goto EOA;
		  case '-':
		  case '.':
		  case '_':
			susp += 1;
			break;
		  case '+':
			susp += 2;
			break;
		  case '$':
			susp += 10;
			break;
		  case '%':
			break;

		  case '\'':
			if( type == 6 ) goto EOA;
			goto NEXT;
		  case '"':
			if( type == 7 || type == 3 ) goto EOA;
			goto NEXT;
		  case ':':
			if( type == 1 ){
				type = 8;
				goto EOA;
			}
			if( type == 2 || type == 3 || type == 4 ) goto EOA;
			if( type == 7 ) goto EOA;
			if( type == 5 || type == 8 ) goto EOA;
			goto NEXT;
		  case ',':
			if( type == 5 || type == 6 || type == 7 ) goto EOA;
			goto NEXT;
		  case '/':
			if( type == 2 || type == 5 || type == 8 ) goto EOA;
			goto NEXT;
		  case ';':
		  case ')':
		  case ']':
			if( type == 5 ) goto EOA;
			goto NEXT;
		  case '|':
		  case '>':
			/* cite in body */
			if( type == 3 || type == 4 || type == 5 ) goto EOA;
		  default:
			if( ch == '(' ){ /* ISO-2022-JP */
				nch = bgnp[1];
				if( nch == 'B' || nch == 'J' ){
					if( top < bgnp && bgnp[-1] == 033 ){
						bgnp += 1;
						ch = ' ';
						goto EOA;
					}
				}
			}
			if( ch == '^' && bgnp[1] == 'I' ){
				bgnp++;
				ch = ' ';
				goto EOA;
			}
			if( ch=='<' || isspace(ch) || ch=='(' )
			{
				goto EOA;
			}
			if( ch == '[' && (type == 2||type == 3) )
				goto EOA;

			if( isalpha(ch) ){
				nch = bgnp[1];
				if( islower(ch) && isupper(nch) )
					susp += 2;
			}else
			if( isdigit(ch) ){
				nch = bgnp[1];
/*
				susp += 1;
*/
				if( !isdigit(nch) && strchr("@-",nch)==0 )
				{
				/* if it's a valid MessageID, it is mapped
				 * in the MIME_mapMessageId(), so it is not
				 * misunderstood as an Email address
				 */
				if( MIME_mapMessageId == 0 )
					susp += 2;
				}
			}else{
				goto NEXT;
			}
		} EOA:
		if( bgnp < top ){
			ch = 0;
		}
/*
 fprintf(stderr,"-- type=%d %X %s\n",type,ch,top);
*/
		if( type == 4 || type == 5 ){
			if( bgnp < top
			 || ch == '>'
			 || ch == '|'
			){
				ch = ' ';
			}
		}
		if( type == 4 ){
			if( ch == '=' || ch == ':' )
				type = 5;
		}

		switch( type ){
			case 1:
				if( ch == ' ' )
				if( top < bgnp && bgnp[-1] == ':' )
					break;
				if( ch != '<' ) goto NEXT; break;
			case 2:
				if( ch != '/' )
				if( ch != ':' )
				if( ch != '=' )
				if( ch != ' ' )
				if( ch != '\t' )
				if( ch != '[' )
				if( ch != '(' ) goto NEXT; break;
			case 3: break;
			case 4:
				if( ch != '\t' )
				if( ch != ' ' ) goto NEXT; break;
			case 5:
				if( ch != '>' )
				if( ch != ';' )
				if( ch != ']' )
				if( ch != ')' )
				if( ch != '/' )
				if( ch != '|' )
				if( ch != ',' )
				if( ch != ':' )
			        if( ch != ' ' )
			        if( ch != '\t' )
				if( ch != '(' )
				if( ch != '=' ) goto NEXT; break;
			case 6:
				if( ch != ',' )
				if( ch != ':' )
				if( ch != ' ' )
				if( ch != '\'' ) goto NEXT; break;
			case 7:
				if( ch != ',' )
				if( ch != ':' )
				if( ch != '=' )
				if( ch != '"' ) goto NEXT; break;
			case 8:
				if( ch != ' ' )
				if( ch != '=' )
				if( ch != ':' )
				if( ch != 0 )
				if( ch != '/' ) goto NEXT; break;
		}

		if( type == 1 && MIME_mapMessageId ){ /* map Message-Id */
			linescanX(bgnp+1,AVStr(addr),endp-bgnp);
			if( (*MIME_mapMessageId)("",addr,AVStr(xaddr)) ){
				if( (mask & MA_MSGID) == 0 ){
					goto NEXT;
				}
				strsubst(AVStr(top),addr,xaddr);
				atp = strchr(bgnp,'>');
				if( atp == NULL )
					break;
				goto NEXT;
			}
		}
		if( (mask & MA_EMAIL) == 0 ){
			goto NEXT;
		}
		if( type == 1 ){ /* could be <Message-Id> */
			if( (dp = strstr(top,"in <"))
			 || (dp = strstr(top,"message <"))
			 || (dp = strstr(top,"article <"))
			){
				if( dp == top || isspace(dp[-1]) )
					susp += 10;
			}
			if( bgnp == top )
				susp += 3;

			if( 5 <= susp ){
				goto NEXT;
			}
		}
if(0)
		if( type == 4 ){
			if( strstr(endp," writes") != endp
			 && strstr(endp," wrote") != endp
			 && strstr(endp," said") != endp
			)
				goto NEXT;
		}

		if( bgnp[1] == '@' ){ /* no local part ... as @echo. */
			goto NEXT;
		}
		linescanX(bgnp+1,AVStr(addr),endp-bgnp);
		mapEmailAddr("_Body",spec,addr,AVStr(xaddr),sizeof(xaddr));

		/*
		sv1log("##TR## [%s][%s]\n",addr,xaddr);
		*/
		next = strchr(atp+1,'@') != 0;
		strsubst(AVStr(top),addr,xaddr);
		rew++;
		if( !next )
			break;

		atp = strstr(top,xaddr);
		if( atp == NULL )
			break;
		if( strlen(atp) < strlen(xaddr) )
			break;
		atp += strlen(xaddr);
NEXT:;
	}
	return rew;
}

static scanListFunc rewaddr1(PCStr(where),PVStr(head),PCStr(spec),PCStr(fnam)){
	if( strcaseeq(where,"Message-ID")
	 || strcaseeq(where,"X-Resent-Message-ID")
	 || strcaseeq(where,"In-Reply-To")
	 || strcaseeq(where,"References") ){
		if( fnam ){
			if( strcaseeq(fnam,where) )
			rewriteMessageID(BVStr(head),where,spec,1);
		}else{
			rewriteMessageID(BVStr(head),where,spec,0);
		}
	}else
	if( fnam ){
		if( strcaseeq(where,fnam) ){
			CStr(fn,128);
			sprintf(fn,"%s:",fnam);
			Strins(BVStr(head),fn);
			rewriteEmailAddr(BVStr(head),where,spec);
			ovstrcpy((char*)head,head+strlen(fn));
		}
	}
	else	rewriteEmailAddr(BVStr(head),where,spec);
	return 0;
}
void MIME_rewriteHeader(PCStr(poster),PCStr(rewaddr),PVStr(head),PCStr(fnam)){
	const char *fmtp;
	CStr(wheb,256);
	const char *sdom;
	const char *ta;

	if( rewaddr == 0 || *rewaddr == 0 ){
		return;
	}
	sdom = MIME_mapPosterBase;
	if( poster && *poster ){
		MIME_mapPosterBase = poster;
	}

	fmtp = wordscanY(rewaddr,AVStr(wheb),sizeof(wheb),"^:");
	if( *fmtp != ':' ){
		return;
	}
	strtolower(wheb,wheb);
	scan_commaListL(wheb,0,scanListCall rewaddr1,BVStr(head),fmtp+1,fnam);

	if( MC_ANON_MSGID ){
		if( !isinListX(wheb,"Message-ID","c") )
		rewriteMessageID(BVStr(head),"Message-ID",fmtp+1,0);
		if( !isinListX(wheb,"X-Resent-Message-ID","c") )
		rewriteMessageID(BVStr(head),"X-Resent-Message-ID",fmtp+1,0);
		if( !isinListX(wheb,"References","c") )
		rewriteMessageID(BVStr(head),"References",fmtp+1,0);
		if( !isinListX(wheb,"In-Reply-To","c") )
		rewriteMessageID(BVStr(head),"In-Reply-To",fmtp+1,0);
	}
	if( MC_ANON_FROM ){
		if( !isinListX(wheb,"From","c") )
		rewriteEmailAddr(BVStr(head),"From",fmtp+1);
		if( !isinListX(wheb,"Sender","c") )
		rewriteEmailAddr(BVStr(head),"Sender",fmtp+1);
		if( !isinListX(wheb,"Reply-To","c") )
		rewriteEmailAddr(BVStr(head),"Reply-To",fmtp+1);
		if( !isinListX(wheb,"Return-Path","c") )
		rewriteEmailAddr(BVStr(head),"Return-Path",fmtp+1);

		if( !isinListX(wheb,"Cc","c") )
		rewriteEmailAddr(BVStr(head),"Cc",fmtp+1);
		/* To too ? */
	}

	MIME_mapPosterBase = sdom;
}

const char *findParam(PCStr(params),PCStr(name),int cookie,const char **nextp){
	const char *pp;
	const char *dp;
	/*
	CStr(name1,64);
	*/
	CStr(name1,128);
	CStr(val1,16*1024);
	int siz = sizeof(val1);
	int cont;

	if( *params == 0 || *params == '\r' || *params == '\n' ){
		return 0;
	}
	pp = params;
	while( isspace(*pp) )
		pp++;
	while( *pp != 0 ){
		dp = wordscanY(pp,AVStr(name1),sizeof(name1),"^=;\r\n");
		if( strlen(name1) == sizeof(name1)-1 ){
			fprintf(stderr,"getParamX() too-long-name[%s]\n",name1);
		}
		if( *dp == '=' ){
			if( cookie ){
				dp = wordscanY(dp+1,AVStr(val1),siz,"^;\r\n");
			}else{
				dp = valuescanX(dp+1,AVStr(val1),siz);
				if( *dp == '"' )
					dp++;
			}
			if( strcaseeq(name1,name) ){
				if( nextp ){
					if( *dp == ';' )
						dp++;
					*nextp = dp;
				}
				return pp;
			}
		}
		while( *dp == ' ' )
			dp++;
		if( *dp == ';' ){
			dp++;
			cont = 1;
		}else	cont = 0;
		while( isspace(*dp) && *dp != '\r' && *dp != '\n' )
			dp++;
		if( cont && (*dp == '\r' || *dp == '\n') ){
			cont = 0;
		}

		pp = (char*)dp;
		while( isspace(*pp) )
			pp++;
		if( cont == 0 ){
			/* don't scan next header field */
			/* the parameter might be in HTML TAG */
			break;
		}
	}
	return 0;
}

int extractParam(PVStr(head),PCStr(fname),PCStr(pname),PVStr(pvalue),int pvsize,int del)
{	const char *field1;
	const char *fn;
	const char *fv;
	const char *pp;
	const char *dp;
	const char *ep;
	const char *sp;
	CStr(buf,1024);
	int plen,len;
	CStr(vbuf,8*1024);
	int vsiz = sizeof(vbuf);
	int vlen;
	int cookie;

	plen = strlen(pname);
	cookie = strcaseeq(pname,"Cookie");
	for( field1 = head; *field1; ){
		fn = findField(field1,fname,&fv);
		if( fn == NULL )
			break;
		field1 = nextField(fn,0);
		RFC822_valuescan(fv,AVStr(buf),sizeof(buf));

		/*
		pp = strstr(buf,pname);
		*/
		pp = findParam(buf,pname,cookie,0);
		if( pp && pp[plen] == '=' ){
			dp = pp + plen + 1;
			/*
			if( *dp == '"' ){
				ep = wordscanY(dp+1,BVStr(pvalue),pvsize,"^\"");
				if( *ep == '"' ) ep++;
			}else	ep = wordscanY(dp,BVStr(pvalue),pvsize,"^;\r\n");
			*/
			if( *dp == '"' ){
				ep = wordscanY(dp+1,AVStr(vbuf),vsiz,"^\"");
				if( *ep == '"' ) ep++;
			}else	ep = wordscanY(dp,AVStr(vbuf),vsiz,"^;\r\n");
			vlen = strlen(vbuf);
			if( pvsize <= vlen ){
				syslog_ERROR("truncate-Param: %d -> %d: %s\n",
					vlen,pvsize-1,vbuf);
				setVStrEnd(vbuf,pvsize-1);
			}
			strcpy(pvalue,vbuf);

			if( del ){
				if( *ep == ';' ) ep++;
				if( *ep == ' ' ) ep++;
				ovstrcpy((char*)pp,ep);
				for( sp = buf; *sp; sp++ ){
					if( !isspace(*sp) )
						break;
				}
				if( *sp == 0 ){
					/* become empty */
					ovstrcpy((char*)fn,field1);
				}else{
					len = ep - pp;
					pp = strstr(fv,pname);
					ovstrcpy((char*)pp,pp+len);
				}
			}
			return 1;
		}
	}
	return 0;
}

#define URLSZ (16*1024)
int getParamX(PVStr(params),PCStr(name),PVStr(val),int siz,int del,int cookie){
	refQStr(pp,params);
	const char *dp;
	/*
	CStr(name1,32);
	*/
	/*
	CStr(name1,64);
	*/
	CStr(name1,128);
	CStr(val1,URLSZ);
	int ndel = 0;
	int cont;
	int rvsiz = siz;

	setVStrEnd(val,0);
	if( *params == 0 || *params == '\r' || *params == '\n' ){
		return 0;
	}
	pp = params;
	while( isspace(*pp) )
		pp++;
	while( *pp != 0 ){
		dp = wordscanY(pp,AVStr(name1),sizeof(name1),"^=;\r\n");
		if( strlen(name1) == sizeof(name1)-1 ){
			fprintf(stderr,"getParamX() too-long-name[%s]\n",name1);
		}
		if( *dp == '=' ){
			int siz = sizeof(val1);
			if( cookie ){
				dp = wordscanY(dp+1,AVStr(val1),siz,"^;\r\n");
			}else{
			dp = valuescanX(dp+1,AVStr(val1),siz);
			if( *dp == '"' )
				dp++;
			}
			if( strcaseeq(name1,name) ){
				int len = strlen(val1);
				if( rvsiz <= len ){
					syslog_ERROR("truncate Param: %d -> %d: %s\n",
						len,rvsiz-1,val1);
					setVStrEnd(val1,rvsiz-1);
				}
				strcpy(val,val1);
			}
		}
		while( *dp == ' ' )
			dp++;
		if( *dp == ';' )
		{
			dp++;
			cont = 1;
		}else	cont = 0;
		/*
		while( isspace(*dp) )
		*/
		while( isspace(*dp) && *dp != '\r' && *dp != '\n' )
			dp++;
		if( cont && (*dp == '\r' || *dp == '\n') ){
			cont = 0;
		}

		if( del && strcaseeq(name1,name) ){
			ovstrcpy((char*)pp,dp);
			ndel++;
		}else{
			pp = (char*)dp;
		}
		while( isspace(*pp) )
			pp++;
		if( cont == 0 ){
			/* don't scan next header field */
			/* the parameter might be in HTML TAG */
			break;
		}
	}
	return ndel;
}
int getParam(PVStr(params),PCStr(name),PVStr(val),int siz,int del){
	return getParamX(BVStr(params),name,BVStr(val),siz,del,0);
}
int delParam(PVStr(params),PCStr(name)){
	refQStr(pp,params);
	const char *dp;
	CStr(name1,32);
	CStr(val1,URLSZ);
	int ndel = 0;

	pp = params;
	while( *pp != 0 ){
		dp = wordscanY(pp,AVStr(name1),sizeof(name1),"^=;\r\n");
		if( *dp == '=' ){
			dp = valuescanX(dp+1,AVStr(val1),sizeof(val1));
			if( *dp == '"' )
				dp++;
		}
		if( *dp == ';' )
			dp++;

		/*
		while( isspace(*dp) )
		*/
		while( isspace(*dp) && *dp != '\r' && *dp != '\n' )
			dp++;
		if( strcaseeq(name1,name) ){
			ovstrcpy((char*)pp,dp);
			ndel++;
		}else{
			pp = (char*)dp;
		}
		if( *dp == '\r' || *dp == '\n' ){
			while( *dp == '\r' || *dp == '\n' )
				dp++;
			if( *dp != ' ' && *dp != '\t' )
				break;
		}
	}
	return ndel;
}

int maskPhoneNumber(PVStr(line)){
	const char *sp;
	int ch;
	int ncol;
	int ndig;
	int ndel;
	char teln[256];
	char teli[256];
	char teld[256];
	char *tels[256];
	char digs[256]; /* digits in each chunk */
	int digx; /* the last chunk */
	int ldig; /* last chunk (must be 4) */
	int nrew; /* rewritten */
	int di;

	sp = line;
	nrew = 0;

NEXT:
	ncol = ndig = ldig = ndel = 0;
	digs[digx=0] = 0;
CONT:

	for(; ch = *sp; sp++ ){
	  switch( ch ){
	    case '0': case '1': case '2': case '3': case '4':
	    case '5': case '6': case '7': case '8': case '9':
		teli[ndig] = digs[digx];
		tels[ndig] = (char*)sp;
		teln[ncol++] = teld[ndig++] = ch;
		ldig++;
		digs[digx]++;
		if( 16 <= ndig )
			goto FOUND;
		break;
	    case '+':
		if( ncol == 0 ){
			teln[ncol++] = ch;
			ndel++;
		}else{
			ncol = ndig = ndel = 0;
			digs[digx=0] = 0;
		}
		ldig = 0;
		break;
	    case '/':
	    case '-':
		if( ncol != 0 ){
			teln[ncol++] = ch;
			ndel++;
			if(ndig){ digs[++digx] = 0; }
		}else{
			ncol = ndig = ndel = 0;
			digs[digx=0] = 0;
		}
		ldig = 0;
		break;
	    case ' ':
	    case '\t':
		if( 0 < ncol && 9 <= ndig ){
			if( !isdigit(sp[1]) ){
				goto FOUND;
			}
		}
		if( 0 < ncol && (isdigit(sp[1]) || sp[1] == '(') ){
			int pch = teln[ncol-1];
			if( 0 < ndel && 9 <= ndig ){
				goto FOUND;
			}
			if( ndig <= 9 && isdigit(pch) ){
				teln[ncol++] = ch;
				ndel++;
				if(ndig) digs[++digx] = 0;
			}
		}else{
			ncol = ndig = ndel = 0;
			digs[digx=0] = 0;
		}
		ldig = 0;
		break;

	    case 033:
	    case '\r':
	    case '\n':
		if( 0 < ndel && 9 <= ndig || ndig == 10 && ndel == 0 ){
			goto FOUND;
		}
		ncol = ndig = ndel = 0;
		digs[digx=0] = 0;
		break;
	    case '(':
		if( 0 < ndel && 9 <= ndig ){
			goto FOUND;
		}
		if( 10 <= ndig && ldig == 4 ){
			goto FOUND;
		}
	    case ')':
		teln[ncol++] = ch;
		ndel++;
		ldig = 0;
		if(ndig) digs[++digx] = 0;
		break;
	    default:
		if( 0 < ndel && 9 <= ndig ){
			goto FOUND;
		}
		ncol = ndig = ndel = 0;
		digs[digx=0] = 0;
		ldig = 0;
		break;
	    }
	} FOUND:

	if( 0 < ndel && 9 <= ndig && ndig < 16
	 || ndig == 10 && ndel == 0 ){
		char maskc = 'X';
		teln[ncol] = 0;
		teld[ndig] = 0;

		if( ldig != 4 && ndig != 10 ){
			/* might be foreign phone number */
			if( teln[0] == '+' && 10 <= ndig
			){
				maskc = 'F';
			}else
			if( sp[0] != 0 && isdigit(sp[1]) ){
				sp++;
				goto CONT;
			}

			*tels[ndig-0-1] = maskc;
			for( di = 1; di < 10 && di < ndig; di++ ){
				*tels[ndig-di-1] = '0';
			}
			nrew++;
		}else{
			teln[ncol] = 0;
			teld[ndig] = 0;

			if( 10 <= ndig && teli[ndig-10] == 0
			 && teld[ndig-10]=='0'
			 && teld[ndig-9]!='0'
			 && (ldig == 4 || ldig == 5)
			){
				maskc = '1';
			}else
			if( 9 <= ndig && teli[ndig-9] == 0
			 && teld[ndig-9]=='0'
			 && teld[ndig-8]!='0'
			 && ldig == 4
			){
				maskc = '2';
			}else
			if( 11 <= ndig && teli[ndig-11] == 0
			 && teld[ndig-11]=='8'
			 && (teld[ndig-10]=='1'||teld[ndig-10]=='8')
			 && tels[ndig-10]+1 < tels[ndig-9]
			){
				maskc = '3';
			}else
			if( 10 <= ndig && teli[ndig-10] == 0
			 && teld[ndig-10]=='8'
			 && teld[ndig-9]=='1'
			 && tels[ndig-9]+1 < tels[ndig-8]
			){
				maskc = '4';
			}else
			if( 11 <= ndig && teli[ndig-11] == 0
			 && teld[ndig-11]=='0'
			 && teld[ndig-10]!='0'
			){
				maskc = '5';
			}else
			if( digx == 2
			 && digs[0]==3
			 && digs[1]==3
			 && digs[2]==4
			){
				maskc = '6';
			}else
			if( ndig == 10
			 && ndel == 0
			 && teld[0] == '0' && teld[1] != '0'
			){
				maskc = '7';
			}else
			if( teln[0] == '+' && 10 <= ndig
			){
				maskc = 'f';
			}else
			{
				if( sp[0] != 0 && isdigit(sp[1]) ){
					sp++;
					goto CONT;
				}
				goto NEXT;
			}
			if( ldig != 4 ){
			}
			*tels[ndig-0-1] = maskc;
			for( di = 1; di < 10 && di < ndig; di++ ){
				*tels[ndig-di-1] = '0';
			}
			nrew++;
		}
		goto NEXT;
	}
	return nrew;
}

#define BASE32A "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
int enBase32(PCStr(src),int sbits,PVStr(dst),int dsiz){
	int si;
	int di = 0;
	int bits = 0;
	int out = 0;
	int put = -1;
	int sx;

    if( sbits % 8 == 0 ){
	int slen;
	slen = sbits / 8;
	for( si = 0; si < slen && di+1 < dsiz; si++ ){
		sx = 0xFF & src[si];
		switch( bits ){
		  case 0: put =      sx>>3;  out = (0x07&sx)<<2; bits=3; break;
		  case 1: put = out|(sx>>4); out = (0x0F&sx)<<1; bits=4; break;
		  case 2: put = out|(sx>>5); out = (0x1F&sx)<<0; bits=5; break;
		  case 3: put = out|(sx>>6); out = (0x3F&sx)<<0; bits=6; break;
		  case 4: put = out|(sx>>7); out = (0x7F&sx)<<0; bits=7; break;
		}
		setVStrElem(dst,di,BASE32A[put]);
		di++;
		if( 5 <= bits ){
			switch( bits ){
			  case 5: put = out; bits = 0; break;
			  case 6: put = out>>1; out= (out&1)<<4; bits=1; break;
			  case 7: put = out>>2; out= (out&3)<<3; bits=2; break;
			}
			setVStrElem(dst,di,BASE32A[put]);
			di++;
		}
	}
	if( 0 < bits ){
		setVStrElem(dst,di,BASE32A[out]);
		di++;
	}
    }else{
	int bit;
	for( si = 0; si < sbits && di+1 < dsiz; si++ ){
		bit = (src[si/8] >> (7 - si%8)) & 1;
		out |= bit << (4 - bits);
		bits++;
		if( bits == 5 ){
			setVStrElem(dst,di,BASE32A[out]);
			out = 0;
			bits = 0;
			di++;
		}
	}
	if( 0 < bits ){
		setVStrElem(dst,di,BASE32A[out]);
		di++;
	}
    }

	setVStrElem(dst,di,0);
	return di;
}
int deBase32(PCStr(src),int slen,PVStr(dst),int dsiz){
	int si;
	int di = 0;
	int bits = 0;
	int bit;
	int out = 0;
	int sx;
	int put = -1;

	for( si = 0; si < slen && di+1 < dsiz; si++ ){
		sx = src[si];
		if( 'A' <= sx && sx <= 'Z' ) sx = sx - 'A'; else
		if( 'a' <= sx && sx <= 'z' ) sx = sx - 'a'; else
		if( '2' <= sx && sx <= '7' ) sx = sx - '2' + 26;
		else{
			break;
		}
		switch( bits ){
		  case 0:		     out  = sx << 3; bits = 5; break;
		  case 1:		     out |= sx << 2; bits = 6; break;
		  case 2:		     out |= sx << 1; bits = 7; break;
		  case 3: put = out|sx;      out  = 0;       bits = 0; break;
		  case 4: put = out|(sx>>1); out  = sx << 7; bits = 1; break;
		  case 5: put = out|(sx>>2); out  = sx << 6; bits = 2; break;
		  case 6: put = out|(sx>>3); out  = sx << 5; bits = 3; break;
		  case 7: put = out|(sx>>4); out  = sx << 4; bits = 4; break;
		}
		if( 0 <= put ){
			setVStrElem(dst,di,put);
			di++;
			put = -1;
		}
	}
	if( 0 <= out ){
		setVStrElem(dst,di,out);
		di++;
	}
	setVStrElem(dst,di,0); /* not necessary for binary data */
	return di;
}
