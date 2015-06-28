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
Program:	url.c (rewrite for relayed-URL in the HTML)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

    REWRITING RULE

      Uniform rewriting rule for URLs to be gatewayed by HTTP is:

	N://H:P/F  <=> http://${delegate}/-_-N://H:P/F

      Special rewriting rule for Gopher URL to be gatewayed by Gopher is:

	G://H:P/gF <=> G://${delegate}/g-_-G://H:P/gF

History:
	March94	created
	941224	changed the rewriting rule
//////////////////////////////////////////////////////////////////////#*/
#include "delegate.h"
#include "file.h"
#include "url.h"
#include <ctype.h>

int   reserve_url(Connection *Conn);
const char *CTX_get_modifires(Connection *Conn);
void  CTX_set_modifires(Connection *Conn,PCStr(modifires));
int   hostcmp_lexical(PCStr(h1),PCStr(h2),int cacheonly);
int   scan_CODECONV(PCStr(spec),PCStr(what),int local);
const char *CTX_changeproxy_url_to(Connection*ctx,PCStr(myhostport),PCStr(method),PVStr(url),PVStr(proxy));

int ENABLE_ODGU = 0;
int GOPHER_ON_HTTP = 1;

#define TAGTRACE 0

extern int URICONV_ANY;
extern int URICONV_FULL;
extern int URICONV_MOUNT;
extern int URICONV_NORMAL;
extern int URICONV_PARTIAL;
extern int TAGCONV_nKILL;
extern int TAGCONV_META;
extern int TAGCONV_KILL;
extern int TAGCONV_APPLET;
extern int TAGCONV_JAVA;
extern char TAGCONV_TAGEND[];
extern int URL_SEARCH;

typedef struct {
	int	u_dummy;
} UrlEnv;
UrlEnv *urlEnv;
void minit_url(){
	if( urlEnv == 0 ){
		urlEnv = (UrlEnv*)malloc(sizeof(UrlEnv));
		URL_SEARCH = URL_IN_HEAD | URL_IN_HTML_TAG;

	}
}

/*
 *	SEARCH URL REFERENCE IN HTML
 *	(half done and dangerous X-<)
 */

static int isBASE(PCStr(tag))
{
	if( tag != NULL && strncasecmp(tag,"<BASE",5) == 0 && isspace(tag[5]) )
		return 1;
	return 0;
}

static void uritrace(PCStr(where),PCStr(tag),PCStr(src))
{	CStr(word,6);
	CStr(line,50);

	if( tag )
		FStrncpy(word,tag);
	else	strcpy(word,"?");
	lineScan(src,line);
	if( 2 <= LOGLEVEL )
	fprintf(stderr,"URL in %s %-6s %s\n",where,word,line);
}

/*
#define iscomtag(p)   ((p[0]=='!' && p[1]=='-' && p[2]=='-' && p[3]=='#')?4:0)
*/
#define iscomtag(p) \
	(p[0]=='?'?1:((p[0]=='!'&&p[1]=='-'&&p[2]=='-'&&p[3]=='#')?4:0))
#define isAlpha(ch)	( 'a'<=ch && ch<='z' || 'A'<=ch && ch<='Z' )
#define isSpace(ch)	( ch==' '||ch=='\t'||ch=='\r'||ch=='\n' )

static int isSite(PCStr(site))
{	const char *sp;
	char ch;
	int ok;

	ok = 0;
	if( !isAlpha(*site) ) goto EXIT;
	ok = 1;
	for( sp = site+1; ch = *sp; sp++ ){
		switch( ch ){
			case '/': goto EXIT;
			case '.': break;
			case '-': break;
			default:
				if( !isdigit(ch) )
				if( !isAlpha(ch) ){ ok = 0; goto EXIT; }
		}
	}
EXIT:
	return ok;
}
static int isPath(PCStr(path))
{	const char *pp;
	char ch;
	int ok;

	ok = 0;
	if( !isAlpha(*path) ) goto EXIT;
	ok = 1;
	for( pp = path+1; ch = *pp; pp++ ){
		switch( ch ){
			case '\'':
			case '"':
			case '?':
			case '/': goto EXIT;
			case '.': break;
			case '-': break;
			case '_': break;
			default:
				if( !isdigit(ch) )
				if( !isAlpha(ch) ){ ok = 0; goto EXIT; }
		}
	}

EXIT:
	return ok;
}

int isFullURL(PCStr(url));
#define isAbsFullURL(s) ( \
	   *s == '/' && (s[1]=='/' && isSite(&s[2]) || isPath(&s[1])) \
	|| *s == '.' && s[1]=='.' && s[2]=='/' \
	|| isAlpha(*s) && isFullURL(s) \
)

#define isJSop(ch)	(ch == '(' || ch == ',' || ch == '=' || ch == '+')
#define isCSSu(s)	(strncasecmp(s,"url(",4) == 0)

static const char *isURLinJavaScript(PCStr(str),char qchp[])
{	char ch;
	const char *sp;
	const char *tp;

	sp = str;
	tp = sp;
	ch = *sp;

	if( ch == '(' ){
		/* 9.9.8 for ({url:"..." */
		if( strncaseeq(sp+1,"{url:",5) ){
			ch = sp[1+5];
			if( ch == '"' || ch == '\'' ){
				*qchp = ch;
				if( sp[7] == '/' || isAbsFullURL((sp+7)) ){
					return sp+7;
				}
			}
		}
	}
	if( isJSop(ch) ){
		ch = *++sp;
		while( isSpace(ch) )
			ch = *++sp;

		if( strneq(sp,"&#39;",5) ){ /* escaped quote char. */
			*qchp = ';';
			sp += 5;
			if( isAbsFullURL(sp) ){
				return sp;
			}
		}else
		if( ch == '"' || ch == '\'' ){
			*qchp = ch;
			ch = *++sp;
			if( isAbsFullURL(sp) ){
				/*
				uritrace("#x# JavaScript","",str);
				*/
				return sp;
			}
		}
	}
	return 0;
}

#define quotech		Ctx->r_tagctx.r_curquote
#define inScript	Ctx->r_tagctx.r_curscript[0]
#define inStyle		Ctx->r_tagctx.r_curstyle[0]

static void getTagCtx(Referer *Ctx,PCStr(ref),PCStr(p))
{
	if( strncasecmp(p,"SCRIPT",6) == 0 ){
		char ch;
		ch = p[6];
		if( isSpace(ch) || ch=='>' ){
			if( ref[1] == '/' )
				inScript = 0;
			else	inScript = 1;
		}
	}
	if( strncasecmp(p,"STYLE",5) == 0 ){
		char ch;
		ch = p[5];
		if( isSpace(ch) || ch=='>' ){
			if( ref[1] == '/' )
				inStyle = 0;
			else	inStyle = 1;
		}
	}
}
static const char *findURLinHTML(Referer *Ctx,PCStr(tag),PCStr(ref))
{	const char *up;
	const char *p;
	char qch;
	char ch;
	CStr(word,8);
	CStr(line,64);

	up = 0;
	qch = 0;

	/*
	 * Script in Attribute value
	 * it could be the value of attribute to be converted (attrTobeConv)
	 */
	if( URL_SEARCH & URL_IN_ATTR_STYLE )
	if( strncasecmp(ref,"STYLE=",6) == 0 ){
		p = ref + 6;
		qch = 0;
		if( *p == '"' || *p == '\'' )
			qch = *p++;
		for(; *p && *p != qch; p++ ){
			if( isCSSu(p) ){
				up = p+4;
				if( *up == '\'' || *up == '"' )
				{
					qch = *up;
					up++;
				}

				if( *up != '#' && isAbsFullURL(up) ){
					uritrace("#A# StylesATTR",tag,ref);
					goto FOUND;
				}
			}
		}
	}

	if( URL_SEARCH & URL_IN_ATTR_SCRIPT )
	if( tag && strncaseeq(tag,"<INPUT",6) && strncaseeq(ref,"VALUE=",6) ){
		uritrace("#B# NOT-ScriptATTR",tag,ref);
	}else
	for( p = ref; ch = *p; p++ ){
		if( isspace(ch) || ch=='"' || ch=='\'' || ch=='>' || ch=='<' )
			break;
		if( isJSop(ch) ){
			if( up = isURLinJavaScript(p,&qch) ){
				uritrace("#B# ScriptATTR",tag,ref);
				goto FOUND;
			}
		}
	}
	return 0;

FOUND:
	quotech = qch;
	return up;
}
static const char *isURLinEmbeded(Referer *Ctx,PCStr(tag),PCStr(str))
{	const char *up;
	char ch;

	ch = *str;
	if( URL_SEARCH & URL_IN_HTML_SCRIPT )
	if( inScript && isJSop(ch) ){
		if( up = isURLinJavaScript(str,&quotech) ){
			uritrace("#C# ScriptHTML",tag,str);
			return up;
		}
	}

	if( URL_SEARCH & URL_IN_HTML_STYLE )
	if( inStyle && isCSSu(str) ){
		up = str+4;
		if( *up == '\'' || *up == '"' )
			quotech = *up++;

		uritrace("#D# StylesHTML",tag,str);
		return up;
	}
	return 0;
}
static const char *findURLinJavaScript(Referer *Ctx,PCStr(str))
{	char pch;
	char ch;
	const char *up;
	const char *sp;

	pch = 0;
	for( sp = str; ch = *sp; ){
		if( isJSop(ch) ){
			if( up = isURLinJavaScript(sp,&quotech) ){
				uritrace("#E# JavaScript","file",sp);
				return up;
			}
		}
		pch = ch;
		if( *sp ) sp++;
	}
	return 0;
}
static const char *findURLinCSS(Referer *Ctx,PCStr(str))
{	const char *tp;
	const char *np;
	const char *up;
	CStr(line,512);

	for( tp = str; tp && *tp; tp = np ){
		lineScan(tp,line);
		if( strcasestr(line,"url(") ){
			up = strcasestr(tp,"url(") + 4;
			if( *up == '"' || *up == '\'' )
				quotech = *up++;

			uritrace("#F# StyleSheet","file",tp);
			return up;
		}
		if( np = strpbrk(tp,"\r\n") ){
			while( *np ){
				if( *np != '\r' && *np != '\n' )
					break;
				np++;
			}
		}
	}
	return 0;
}
/*
static const char *isXMLNS(PCStr(tag),PCStr(str))
*/
#define isXMLNS(tag,str) isURLinXMLattr(Ctx,tag,str)

static char strcasestrlen(PCStr(str1),PCStr(str2)){
	const char *s1 = str1;
	const char *s2 = str2;
	int eqlen;
	for( eqlen = 0; *s1++ == *s2++; eqlen++);
	if( *s2 == 0 )
		return eqlen;
	else	return 0;
}
/*
 *   xmlns[:namespace-prefix]="namespaceURI"
 * RDF URI Reference (URIref)
 * http://www.w3.org/TR/rdf-primer/
 *   rdf:{resource|about|ID|datatype}="URIref"
 *   <rdf:xxxx {resource|about|ID|datatype}="URIref" ...>
 */
#define isRDFURI(alen,name) (\
	   (alen = strcasestrlen(name,"resource")) \
	|| (alen = strcasestrlen(name,"about")) \
	|| (alen = strcasestrlen(name,"ID")) \
	|| (alen = strcasestrlen(name,"datatype")) \
)

static const char *isURLinXMLattr(Referer *Ctx,PCStr(tag),PCStr(str))
{	const char *sp;
	char ch;
	int dlen;
	int alen = 0;
	int canbeURI = 0;

	sp = str;
	while( isspace(*sp) )
		sp++;
	/*
	if( strncasecmp(sp,"xmlns:",6)==0 ){
		for( sp = sp+6; ch = *sp; sp++ ){
	*/
	if( dlen = strcasestrlen(sp,"xmlns") ){
		if( sp[dlen] == ':' )
			dlen++;
		canbeURI = 1;
	}else
	if( (dlen = strcasestrlen(sp,"rdf:")) && isRDFURI(alen,sp+dlen) ){
		canbeURI = 2;
	}else
	if( strcasestrlen(tag,"rdf:") && isRDFURI(alen,sp) ){
		dlen = 0;
		canbeURI = 3;
	}
	if( canbeURI ){
		if( lURLFIND() ){
			CStr(tagb,128);
			CStr(line,128);
			wordScan(tag,tagb);
			lineScan(sp,line);
			fprintf(stderr,"{U}XML %d [%-7s] %d+%d %s\n",
				canbeURI,tagb,dlen,alen,line);
		}
		for( sp = sp+dlen+alen; ch = *sp; sp++ ){
			if( ch == '=' )
			{
				if( sp[1] == '"' || sp[1] == '\'' ){
					quotech = *++sp;
				}
				return sp+1;
			}
			if( 0 < alen ){
				break;
			}
			if( ch == '>' || ch == ' ' )
				break;
		}
	}
	return 0;
}

int HTML_attrTobeConv(PCStr(attr),PCStr(tag),int *uconvp);
const char *html_nextTagAttrX(void *vBase,PCStr(html),PCStr(ctype),PVStr(rem),const char **tagp,const char **attrp,int *convmaskp)
{	Referer *Base = (Referer*)vBase;
	const char *top;
	const char *str;
	const char *tag;
	const char *attr;
	const char *ref;
	const char *attrtailp;
	unsigned char ch;
	const char *hp;
	int len;
	int convmask;
	int cvmb;
	int isendtag;
	const char *atp;
	CStr(fname,32);
	int NoAttr = 0; /* scan tags without attr. too */

	Referer Ctxb,*Ctx=&Ctxb;
	int qconvmask;
	int uriconv;
	const char *up;

	if( *html == 0 ){
		return 0;
	}
	if( convmaskp && (*convmaskp & TAGCONV_JAVA) ){
		NoAttr |= 1;
	}
	if( TAGCONV_nKILL ){
		NoAttr |= 2;
	}

	bzero(Ctx,sizeof(Referer));
	top = NULL;
	tag = NULL;
	attr = NULL;
	str = html;
	if( convmaskp ) convmask = *convmaskp;

	if( convmaskp ){
		qconvmask = *convmaskp;
	}else{
		qconvmask = 0;
	}
	if( qconvmask == 0 ){
		qconvmask = 0xFFFFFFFF;
	}
	uriconv = qconvmask & (URICONV_ANY|TAGCONV_META);

	if( ctype == 0 || *ctype == 0 ){
		if( Base )
			ctype = Base->r_cType;
		if( ctype == 0 )
			ctype = "";
	}
	if( Base ){
		if( Base->r_tagctx.r_curtag[0] ){
			tag = Base->r_tagctx.r_curtag;
		}
		Base->r_tagctx.r_curquote = 0;
		Ctx->r_tagctx = Base->r_tagctx;
	}else{
		inScript = 0;
		inStyle = 0;
		quotech = 0;
	}


	if( *ctype != 't' && strncasecmp(ctype,"text/",5) != 0 ){
	/* not in message body */
		if( strncasecmp(str,"WWW-Authenticate:",17) == 0
		 || strncasecmp(str,"Proxy-Authenticate:",19) == 0 )
		if( ref = strcasestr(str,"Realm=<") ){
			/* if attrTobeConv() */ {
				attr = str;
				ref += 7;
				top = ref;
				goto exit;
			}
		}
		if( strncasecmp(str,"Location:",9) == 0 
		/*
		 || strncasecmp(str,"Content-Location:",17) == 0 
		*/
		 || strncasecmp(str,"URI:",4) == 0 ){
			ref = strchr(str,':') + 1;
			while( *ref == ' ' )
				ref++;
			if( convmaskp ) *convmaskp = convmask;
			wordScanY(str,fname,"^:");
			if( HTML_attrTobeConv(fname,"Header",convmaskp) ){
				attr = str;
				top = ref;
				goto exit;
			}
		}
	}

	if( strcaseeq(ctype,"text/javascript")
	 || strcaseeq(ctype,"application/x-javascript")
	 || strcaseeq(ctype,"text/x-component")
	){
		if( uriconv )
		if( URL_SEARCH & URL_IN_SCRIPT )
		{
			if( up = findURLinJavaScript(Ctx,str) ){
				if( convmaskp ) *convmaskp = convmask;
				top = up;
				ref = up;
				attr = up;
				goto exit;
			}
		}
		return 0;
	}
	if( strcaseeq(ctype,"text/css") ){
		if( uriconv )
		if( URL_SEARCH & URL_IN_STYLE )
		{
			if( up = findURLinCSS(Ctx,str) ){
				if( convmaskp ) *convmaskp = convmask;
				top = up;
				ref = up;
				attr = up;
				goto exit;
			}
		}
		return 0;
	}
	/*
	if( strcaseeq(ctype,"text/xml") ){
	*/
	if( strcaseeq(ctype,"text/xml")
	 || strcaseeq(ctype,"application/xml")
	 || strcaseeq(ctype,"application/soap+xml")
	){
		const char *sp;

		if( uriconv == 0 || (URL_SEARCH & URL_IN_XML) == 0 )
			return 0;

		if( tag != NULL ){
			if( hp = isXMLNS(tag,str) ){
				top = hp;
				goto exit;
			}
		}
		for( sp = str; ch = *sp; sp++ ){
		    if( ch == '<' ){
			char inattr;
			CStr(dom,32);
			CStr(name,128);
			refQStr(np,name); /**/
			const char *nx;

			if( sp[1] == '/' ){
				isendtag = 1;
				sp++;
			}else	isendtag = 0;
			++sp;
			tag = attr = sp;

			dom[0] = name[0] = 0;
			setQStr(np,name,sizeof(name));
			nx = name + (sizeof(name)-1);
			inattr = 0;
			for(; *sp && (ch = *sp) != '>'; sp++ ){
				if( nx <= np )
					break;

				if( isspace(*sp) ){
					if( hp = isXMLNS(tag,sp) ){
						top = hp;
						goto exit;
					}
					inattr = 1;
				}
				if( inattr == 0 ){
					if( *sp == ':' ){
						strcpy(dom,name);
						np = name;
						attr = (char*)sp+1;
					}else{
						setVStrPtrInc(np,ch);
						setVStrEnd(np,0);
					}
				}
			}
			if( *sp != '>' )
				return 0;
			tag = NULL;
			sp++;

			if( isendtag )
				continue;

			while( isspace(*sp) ) sp++;
			if( *sp == '<' ){ /* maybe a nested entity */
				sp--;
				continue;
			}

			if( strcaseeq(name,"href")
			 || strcaseeq(name,"src")
			 || strcaseeq(name,"dst")
			 || strcaseeq(name,"url")
			 || strcaseeq(name,"link")
			){
				while( isspace(*sp) )
					sp++;
				top = sp;
				goto exit;
			}
		    }
		}
		return 0;
	}

	/*
	 * The following code seems to make redundant search for attribute
	 * even when not in a TAG ...
	 * Maybe it is to cope with not only TAG but also HTTP header ... 
	 * or because multiple attributes are in a TAG but "tagp" is not
	 * restored ? or... most likely,
	 * just because it did not care TAG when it is created originally...
	 */
	atp = NULL;
	for(;;){
		isendtag = 0;
		if( atp == TAGCONV_TAGEND )
			tag = NULL;

/*
Probably this is obsolete, introduced in 2.8.33 where attribute was
naively searched after any white space, and at the top of each line.
After tag symbols has become to be cared, in 6.1.20, such line
beginning with a tag seems to be excluded.
		if( str == html && *str != '<' && *str != '>' )
*/
		if( 0 )
			ref = html;
		else{
			for( ref = str; ch = *ref; ref++ ){
				if( ch == '<' )
				{
					hp = ref + 1;
					if( *hp == '/' ) hp++;
					if( *hp == 's' || *hp == 'S' )
					getTagCtx(Ctx,ref,hp);

					if( len = iscomtag(hp) )
						hp += len;
					if( *hp != 0 && !isalpha(*hp) )
						continue; /* not a tag */
					for(; *hp; hp++ )
						if( !isalpha(*hp) )
							break;
					if( *hp == '>' && NoAttr ){
					 /* 9.9.2 scan <TAG> without attr. as
					  * <EMBED>. Disabled in 7.9.11 by the
					  * !isspace() in the following line.
					  */
					}else
					if( *hp != 0 && !isspace(*hp) )
						continue; /* not a tag */

					tag = ref;
					isendtag = ref[1] == '/';
				}
				else
				if( ch == '>' )
				{
					if( tag != NULL ){
/*
						if( isendtag )
*/
							break;

					/* can be bad for begin tags with
					 * multiple attributes to be rewriten
					 * with "tagp" info. which is not
					 * availabe for secondary or after
					 * attr. in the current implementation.
					 * It must be fixed to make multiple
					 * attributes rewriting.
					(6.1.20)
					(7.6.1) this comment (maybe) about
					"isendtag" seems misunderstanding
					thinking the tag is interpreted right
					succeeding SPACE char.)...?
					Interpreting a tag after closing ">" char.
					seems not to affect any attribute
					rewriting.
					 */
					}
					tag = NULL;
					isendtag = 0;
				}

				if( uriconv )
				if( URL_SEARCH & URL_IN_HTML_EMBED )
				if( up = isURLinEmbeded(Ctx,tag,ref) ){
					if( convmaskp ) *convmaskp = convmask;
					top = up;
					ref = up;
					attr = up;
					goto exit;
				}

				/*
				this should be so, but can be bad for
				TAG-independent attribute rewriting?
				 */
				if( tag == NULL )
					continue;

				if(  isspace(ch) )
					break;
				if( ch == '(' ){
					/* can be a JavaScript function call */
					ref++;
					break;
				}
				if( ch == ';' || ch == '"' || ch == '\'' ){
					ref++;
					break;
				}
			}
		}
			for(; ch = *ref; ref++ )
				if( !isspace(ch) )
					break;

		if( rem != NULL && tag != NULL && *ref == 0 ){
			for( hp = tag+1; *hp; hp++ )
			{
				if( len = iscomtag(hp) ){
					hp += len - 1;
					continue;
				}
				if( !isalpha(*hp) )
					break;
			}
			if( *hp == 0 ){
				sv1log("##truncated tag-name:%s\n",tag);
				goto push;
			}
			while( isspace(*hp) )
				hp++;
			if( *hp == 0 ){
				sv1log("##truncated tag-body:%s\n",tag);
				goto push;
			}
		}
		if( *ref == 0 )
			break;

		if( *ref == '<' && str < ref ){
			str = ref;
			continue;
		}

		if( *ref == '<' )
			tag = ref;

		attr = ref;

		if( *attr == '>' )
			atp = TAGCONV_TAGEND;
		else	atp = attr;

		if( TAGTRACE ){
			CStr(t,9);
			CStr(a,13);
			FStrncpy(a,atp);
			FStrncpy(t,tag?tag:"");
			sv1log("## TAG=%8X[%-8s] ATTR=[%-12s]\n",p2i(tag),t,a);
		}
		attrtailp = 0;
		if( rem != NULL && tag != NULL && isalpha(*atp) ){
			for( hp = atp+1; *hp; hp++ )
				if( !isalpha(*hp) )
					break;
			if( *hp == 0 ){
				sv1log("##truncated attr-name:%s\n",atp);
				goto push;
			}
			while( isspace(*hp) )
				hp++;
			if( *hp == '=' ){
				hp++;
				while( isspace(*hp) )
					hp++;
				quotech = 0;
				if( *hp == '"' || *hp == '\'' ){
					quotech = *hp;
					hp++;
				}
				for(; ch = *hp; hp++ ){
					if( quotech != 0 ){
						if( ch == quotech )
							break;
					}else{
						if( ch == '>' || isspace(ch) )
							break;
					}
				}
			}
			if( *hp == 0 ){
				sv1log("##truncated attr-value:%s\n",atp);
				goto push;
			}
			if( *hp == quotech )
				hp++;
			while( isspace(*hp) )
				hp++;
			attrtailp = hp;
		}

		if( convmaskp ) *convmaskp = convmask;
		len = HTML_attrTobeConv(atp,tag,convmaskp);
		if( len == 0 ){
			str = ref + 1;
			if( (hp = attrtailp) && *hp == 0 ){
				sv1log("##truncated tag-body:%s\n",str);
				goto push;
			}

			if( uriconv )
			if( URL_SEARCH & URL_IN_ATTR_EMBED )
			if( HTML_attrTobeConv(atp,tag,NULL) ){
				/* attribute to be rewritten but is not the
				 * target of current conversion
				 * (ex. BASE attribute is not for PARTIAL)
				 */
			}else
			if( up = findURLinHTML(Ctx,tag,ref) ){
				if( convmaskp ) *convmaskp = convmask;
				top = up;
				ref = up;
				attr = up;
				goto exit;
			}

			continue;
		}
		if( atp == TAGCONV_TAGEND ){
			top = ref;
			goto exit;
		}
		hp = ref + len;

		while( isspace(*hp) )
			hp++;

		switch( *hp ){
			case 0:   goto push;
			case '=': hp++; break;
			default:  str = ref + 1; continue;
		}

		while( isspace(*hp) )
			hp++;

		if( uriconv )
		if( URL_SEARCH & URL_IN_SCRIPTs )
		if( inScript && *hp == '\\' && (hp[1]=='\'' || hp[1]=='"') )
		{
			hp++; /* escaped quote in script */
		}

		if( *hp == '"' || *hp == '\'' )
		{
			quotech = *hp;
			hp++;
		}

push:
		attrtailp = hp;
		if( rem != NULL ){
			for( attrtailp = hp; ch = *attrtailp; attrtailp++ ){
				if( quotech != 0 && ch == quotech
				 || quotech == 0 && (isspace(ch) || ch == '>')
				){
					break;
				}
			}
		}

		if( rem != NULL && *attrtailp == 0 ){
			/* pushing a tag fragment from its begining is
			 * required in recent implementation ...
			 */
			if( tag && strlen(tag) < 1024
			 && tag != Base->r_tagctx.r_curtag ){
				strcpy(rem,tag);
				*(char*)tag = 0; /* not "const" but fixed */
			}else
			if( strlen(ref) < 1024 ){
			strcpy(rem,ref);
			*(char*)ref = 0; /* not "const" but fixed */
			}else{
sv1log("#### TOO LONG TO PUSH (%d): %s\n",istrlen(ref),ref);
			}
			top = NULL;
			goto exit;
		}
		top = hp;
		goto exit;
	}
exit:
	if( tagp != NULL )
		*tagp = (char*)tag;
	if( attrp != NULL )
		*attrp = (char*)attr;
	if( Base != NULL ){
		Base->r_tagctx = Ctx->r_tagctx;
		if( tag ){
			wordScan(tag,Base->r_tagctx.r_curtag);
		}else{
			Base->r_tagctx.r_curtag[0] = 0;
		}
	}
	return top;
}

#define html_nextTagAttr(h,c,r,t,a,m) html_nextTagAttrX(referer,h,c,r,t,a,m)

/*
 *	TRANSFORM delegated-URL to NORMAL URL:
 *	Delagation information embedded in the URL is removed, and paresd.
 *	"url" string passed from caller will be over wrote.
 */
static char *printFlags(Connection *Conn,PVStr(s))
{
	return Sprintf(AVStr(s),"=%s=",DELEGATE_FLAGS);
}
const char *endofHOSTPORT = "/? \t\r\n";

void url_rmprefix(PVStr(proto),PVStr(prefix))
{	const char *p;
	int len;
	char dch;

	setVStrEnd(prefix,0);
	if( strstr(proto,NDGU_MARK) == proto ){
		p = proto + strlen(NDGU_MARK);
		dch = *p;
		if( dch == '=' || dch == '/' ){
			for( p++; *p; p++ ){
				if( *p == dch ){
					len = p - proto + 1;
		strncpy(prefix,proto,len); setVStrEnd(prefix,len);
					strcpy(proto,p+1);
					break;
				}
			}
		}
	}
}

int isLoadableURL(PCStr(url))
{
	if( strncasecmp(url,"ftp://",6) == 0
	 || strncasecmp(url,"file:",5) == 0
	 || strncasecmp(url,"data:",5) == 0
	 || strncasecmp(url,"enc:",4) == 0
	 || strncasecmp(url,"myfile:",7) == 0
	 || strncasecmp(url,"builtin:",8) == 0
	 || strncasecmp(url,"http://",7) == 0 )
		return 1;
	return 0;
}

int fromProxyClient(PCStr(url))
{	int from_proxy = 0;
	const char *sp;
	CStr(proto,32);

	if( strncasecmp(url,"http://",  7) == 0 ) return 1;
	if( strncasecmp(url,"nntp://",  7) == 0 ) return 1;
	if( strncasecmp(url,"wais://",  7) == 0 ) return 1;
	if( strncasecmp(url,"ftp://",   6) == 0 ) return 1;
	if( strncasecmp(url,"gopher://",9) == 0 ) return 1;

	if( url[0] != '/' ){
		if( sp = scan_URI_scheme(url,AVStr(proto),sizeof(proto)) ){
			if( strncmp(sp,"://",3) == 0 )
				if( strstr(url,NDGU_MARK) == NULL )
					from_proxy = 1;
		}
	}
	return from_proxy;
}
int is_redirected_url(PCStr(url))
{
	if( strstr(url,ODGU_MARK) ) return 1;
	if( strstr(url,NDGU_MARK) ) return 1;
	return 0;
}
int is_redirected_selector(PCStr(sel))
{
	if( strncmp(sel,NDGU_MARK,strlen(NDGU_MARK)) == 0 )
		return 1;
	return 0;
}

static char *scan_flags(char np[],PVStr(tp),PVStr(flags))
{	const char *fp;

	if( *np == '+' || *np == '-' || *np == '=' ){
		if( fp = strchr(np+1,'=') ){
			truncVStr(fp);
			switch( *np ){
				case '+': onoff_flags(AVStr(flags),np+1,1); break;
				case '-': onoff_flags(AVStr(flags),np+1,0); break;
				case '=': wordscanX(np+1,AVStr(flags),64); break;
			}
			strcpy(tp,fp+1);
			np = (char*)tp;
		}
	}
	return np;
}

static void put_gtype(PVStr(sel),int gtype,int toproxy)
{	CStr(ssel,URLSZ);

	if( !toproxy  || gtype == '7' ){
		if( gtype==' ' || gtype=='\t' || gtype=='\r' || gtype=='\n' )
			gtype = '1';
		strcpy(ssel,sel);
		sprintf(sel,"(:%c:)%s",gtype,ssel);
	}
}
int get_gtype(PCStr(gsel),PVStr(sel))
{	int gtype;
	CStr(path,1024);

	if( gsel[0]=='(' && gsel[1]==':' && gsel[3]==':' && gsel[4]==')' ){
		gtype = gsel[2];
		if( sel ) strcpy(sel,gsel+5);
	}else{
		gtype = gsel[0];
		if( gtype=='\n' || gtype=='\r' || gtype=='\t' || gtype==0 )
			gtype = '1';
		else
		if( Xsscanf(gsel,"%s",AVStr(path)) && path[strlen(path)-1] == '/' )
			gtype = '1';
		else
		if( !strchr("0123456789gIT",gtype) )
			gtype = '9';

		if( sel ) ovstrcpy((char*)sel,gsel);
	}
	return gtype;
}


static scanListFunc scan_modifier1(PCStr(mod1),PVStr(flags))
{
	if( strncmp(mod1,"cc.",3) == 0 )
		scan_CODECONV(mod1+3,CCV_TOCL,1);
	else
	if( strncmp(mod1,"cs.",3) == 0 )
		scan_CODECONV(mod1+3,CCV_TOSV,1);
	else
	if( mod1[0] == 'F' )
		strcpy(flags,mod1+1);
	return 0;
}
static void scan_modifiers(Connection*ctx,PCStr(mods),PVStr(flags))
{
	CTX_set_modifires((Connection*)ctx,mods);
	scan_commaList(mods,0,scanListCall scan_modifier1,AVStr(flags));
}

int scan_protositeport(PCStr(url),PVStr(proto),PVStr(userpasshost),PVStr(port));
int CTX_url_dereferN(Connection*ctx,PCStr(cproto),PVStr(url),PVStr(modifiers),PVStr(flags),PVStr(proto),PVStr(host),int *iportp,xPVStr(durl),int marklen)
{	CStr(protob,URLSZ);
	CStr(port,URLSZ);
	CStr(urlh,URLSZ);
	CStr(modb,1024);
	refQStr(pb,modb); /**/
	char ch;
	refQStr(np,durl); /**/
	char gtype;
	int len,ni;

	if( durl[marklen] == '/' && durl[marklen+1] != '/' ){
		const char *pp;
		setQStr(pb,modb,sizeof(modb));
		for( pp = durl + marklen + 1; ch = *pp++; ){
			assertVStr(modb,pb+1);
			if( ch == ':' )
				break;
			if( ch == '/' )
				break;
			setVStrPtrInc(pb,ch);
			if( isspace(*pp) )
				break;
		}
		if( ch == '/' ){
			setVStrEnd(pb,0);
			if( modifiers != NULL )
				strcpy(modifiers,modb);

			scan_modifiers(ctx,modb,AVStr(flags));
			Xstrcpy(DVStr(durl,marklen),pp);
		}else{
			ovstrcpy((char*)durl+marklen,durl+marklen+1);
		}
	}else
	if( url < durl ){
		refQStr(pp,durl); /**/
		modb[sizeof(modb)-1] = 0;
		pb = &modb[sizeof(modb)-1];

		if( durl[-1] == ')' ){
		    for( pp = (char*)durl - 2; url <= pp; pp-- ){
			if( *pp == '(' ){
				strcpy(pp,durl);
				durl = pp;
				break;
			}
			*(char*)--pb = *pp;
		    }
		}else{
		    for( pp = (char*)durl - 1; url <= pp; pp-- ){
			if( *pp == '/' || isspace(*pp) ){
				ovstrcpy((char*)pp+1,durl);
				durl = pp + 1;
				break;
			}
			*(char*)--pb = *pp;
		    }
		}

		if( pp = strstr(pb,"-.-") ){
			setVStrEnd(pp,0);
			strcpy(urlh,durl);
			sprintf(durl,"%s:///%s%s",NDGU_MARK,pp+3,urlh);
		}
		if( modifiers != NULL )
			strcpy(modifiers,pb);
		scan_modifiers(ctx,pb,AVStr(flags));
	}

	if( &url[1] < durl && strcaseeq(cproto,"http") )
		return 0;

	np = (char*)durl + marklen;
	np = scan_flags((char*)np,AVStr(durl),AVStr(flags));
	unescape_specials(np,":","//");

	port[0] = 0;
	if( strncmp(np,":///",4) == 0 ){
		protob[0] = 0;
		strcpy(host,"localhost");
		*iportp = SERVER_PORT();
		strcpy(durl,np+4);
		return 1;
	}
	if( strncmp(np,"://",3) == 0 )
		ovstrcpy((char*)np,np+1);

	ni = scan_protositeport(np,AVStr(protob),AVStr(host),AVStr(port));

	if( ni == 2 || ni == 3 ){
		refQStr(up,urlh); /**/

		strcpy(proto,protob);
		up = Sprintf(AVStr(up),"%s://%s",proto,host);
		if( proto[0] == 0 )
			strcpy(proto,cproto);
		if( ni == 2 )
			*iportp = serviceport(proto);
		else{	*iportp = atoi(port);
			up = Sprintf(AVStr(up),":%s",port);
		}
		len = up - urlh;

		/* gopher://HP/G-_-gopher://...
		 * seems to no more be supported
		 */
		gtype = 0;
		/* skip "/Gtype" */
		if( streq(cproto,"gopher") && streq(proto,"gopher") ){
			if( np[len] == '/' ){
				len++;
				if( gtype = np[len] )
				if(strchr(endofHOSTPORT,gtype)==NULL){
					len++;
				}
			}
		}
		if( url < durl && durl[-1] == '/' && np[len] == '/' )
			len += 1;
		strcpy(durl,np+len);
		if( gtype )
			put_gtype(AVStr(durl),gtype,0);
		return 1;
	}
	return -1;
}
int CTX_url_dereferO(Connection*ctx,PCStr(cproto),PVStr(url),PVStr(modifiers),PVStr(flags),PVStr(proto),PVStr(host),int *iportp,PVStr(durl),int marklen)
{	const char *hp;
	refQStr(np,durl); /**/
	char gtype;
	int ni;

	np = (char*)durl + marklen;
	np = scan_flags((char*)np,AVStr(durl),AVStr(flags));

	/*
	 *	Gopher		=@=gopher:H:P=Gtype
	 *		'Gtype' is used by Gopher/DeleGates who doesn't know
	 *		what type the requested infomation is.
	 *	Ftp/Gopher	=@=ftp:H:P=Gtype
	 *		'Gtype' may be used to determine whether P is a
	 *		directory or a flat file.
	 *	
	 */
	if( (ni = Xsscanf(np,"%[^:]:%[^:]:%d=%c",AVStr(proto),AVStr(host),iportp,&gtype)) == 4
	 || (ni = Xsscanf(np,"%[^:]:%[^=]=%c",   AVStr(proto),AVStr(host),&gtype)) == 3 )
	{
		if( ni == 3 )
			*iportp = serviceport(proto);
		if( hp = strpbrk(np+strlen(host),endofHOSTPORT) )
			strcpy(durl,hp);
		put_gtype(AVStr(url),gtype,0);
		return 1;
	}

	/*
	 *	Genric     =@=proto:H:P
	 */
	ni = Xsscanf(np,"%[^:]:%[^:/? \t\r\n]:%d",AVStr(proto),AVStr(host),iportp);
	if( 2 <= ni ){
		if( ni == 2 )
			*iportp = serviceport(proto);
		if( hp = strpbrk(np+strlen(host),endofHOSTPORT) )
			strcpy(durl,hp);
		return 1;
	}

	/*
	 *	HTTP-Special /=@=:H:P
	 */
	ni = Xsscanf(np,":%[^:/? \t\r\n]:%d",AVStr(host),iportp);
	if( 1 <= ni ){
		if( ni == 1 )
			*iportp = serviceport("http");
		if( hp = strpbrk(np+strlen(host),endofHOSTPORT) ){
			if( durl[-1] == '/' && hp[0] == '/' )
				strcpy(durl,hp+1);
			else	strcpy(durl,hp);
		}
		return 1;
	}

	setVStrEnd(host,0);
	setVStrEnd(proto,0);
	return 0;
}
int CTX_url_derefer(Connection*ctx,PCStr(cproto),PVStr(url),PVStr(modifiers),PVStr(flags),PVStr(proto),PVStr(host),int *iportp)
{	refQStr(durl,url); /**/
	int rcode;

	if( durl = strstr(url,NDGU_MARK) ){
		rcode = CTX_url_dereferN(ctx,cproto,AVStr(url),AVStr(modifiers),AVStr(flags),AVStr(proto),AVStr(host),iportp,
				AVStr(durl),strlen(NDGU_MARK));
		if( rcode != -1 )
			return rcode;
	}

	if( ENABLE_ODGU )
	if( durl = strstr(url,ODGU_MARK) ){
		rcode = CTX_url_dereferO(ctx,cproto,AVStr(url),AVStr(modifiers),AVStr(flags),AVStr(proto),AVStr(host),iportp,
				AVStr(durl),strlen(ODGU_MARK));
		if( rcode != -1 )
			return rcode;
	}
	return 0;
}

/*
 *  site = user:pass@host:port
 *  site = [ [ user [ : pass ] @ ] hostport ]
 *  unreserved = A-Z a-z 0-9 $-_.!~*'(), 
 *  user = *( unreserved | escaped | ;&=+ )
 *  pass = *( unreserved | escaped | ;&=+ )
 */
char *scan_URI_scheme(PCStr(url),PVStr(scheme),int size)
{	const char *up;
	unsigned char uc;
	int sx;

	sx = 0;
	for( up = url; uc = *up; up++ ){
		if( size <= sx + 1 )
			break;
		if( uc == ':' || isspace(uc) )
			break;
		else	setVStrElemInc(scheme,sx,uc); /**/
	}
	setVStrEnd(scheme,sx); /**/
	return (char*)url + strlen(scheme);
}
char *scan_URI_site(PCStr(url),PVStr(site),int size)
{	CStr(buff,512);
	int len;

	if( size == 0 )
		size = 248; /* 7 bytes for :port-# ... */
	len = sizeof(buff);
	if( size < len )
		len = size;
	QStrncpy(buff,url,len);
	setVStrEnd(site,0);
	Xsscanf(buff,"%[-.A-Za-z0-9:@%%$_!~*'(),;&=+#]",AVStr(site));
	url += strlen(site);
	return (char*)url;
}
void decomp_URL_site(PCStr(site),PVStr(userpasshost),PVStr(port))
{	const char *up;
	const char *pp;

	setVStrEnd(userpasshost,0);
	setVStrEnd(port,0);
	if( up = strrchr(site,'@') ){
		if( pp = strchr(up,':') ){
			truncVStr(pp); pp++;
			strcpy(port,pp);
		}
		strcpy(userpasshost,site);
	}else{
		Xsscanf(site,"%[^:]:%s",AVStr(userpasshost),AVStr(port));
	}
}
void decomp_URL_siteX(PCStr(site),PVStr(userpass),PVStr(user),PVStr(pass),PVStr(hostport),PVStr(host),PVStr(port))
{	const char *userp;
	const char *passp;
	const char *portp;

	strcpy(hostport,site);
	if( userp = strrchr(hostport,'@') ){
		truncVStr(userp); userp++;
		strcpy(userpass,hostport);
		if( passp = strchr(hostport,':') ){
			truncVStr(passp); passp++;
		}else	passp = "";
		nonxalpha_unescape(hostport,AVStr(user),1);
		nonxalpha_unescape(passp,AVStr(pass),1);
		ovstrcpy((char*)hostport,userp);
	}else{
		setVStrEnd(pass,0);
		setVStrEnd(user,0);
		setVStrEnd(userpass,0);
	}

	strcpy(host,hostport);
	if( portp = strchr(host,':') ){
		truncVStr(portp); portp++;
		strcpy(port,portp);
	}else{
		setVStrEnd(port,0);
	}

Verbose("S[%s] = UP[%s]U[%s]P[%s] + HP[%s]H[%s]P[%s]\n",
site, userpass,user,pass, hostport,host,port);
}

const char *scan_userpassX(PCStr(userpass),AuthInfo *ident);
const char *scan_url_userpass(PCStr(server),PVStr(user),PVStr(pass),PCStr(dfltuser))
{	CStr(ub,128);
	CStr(wb,128);
	const char *sp;
	AuthInfo ident;

	sp = scan_userpassX(server,&ident);
	wordScan(ident.i_user,ub);
	textScan(ident.i_pass,wb);
	if( *sp != '@' ){
		strcpy(user,dfltuser);
		setVStrEnd(pass,0);
		return server;
	}
	nonxalpha_unescape(ub,AVStr(user),1);
	nonxalpha_unescape(wb,AVStr(pass),1);
	return sp + 1;
}
int scan_protositeport(PCStr(url),PVStr(proto),PVStr(userpasshost),PVStr(port))
{	const char *sp;
	char ch;
	CStr(site,MaxHostNameLen);

	sp = url;
	if( *sp != '/' )
		sp = scan_URI_scheme(sp,AVStr(proto),64);
	else	setVStrEnd(proto,0);
	if( *sp == ':' )
		sp++;

	if( strncmp(sp,"//",2) == 0 )
		sp += 2;
	else
	if( *sp == '/' )
		sp += 1; /* for IE4.0 */
	else	return 0;

	scan_URI_site(sp,AVStr(site),sizeof(site));
	decomp_URL_site(site,AVStr(userpasshost),AVStr(port));

	if( *port == 0 )
		return 2;
	else	return 3;
}
int url_serviceport(PCStr(url))
{	CStr(proto,32);

	scan_URI_scheme(url,AVStr(proto),sizeof(proto));
	return serviceport(proto);
}

#define SITEC(c) ((c & 0x80) == 0 && 0x20 < c && c != '/' && c != '?')
#define PATHC(c) (c != '\r' && c != '\n')

int decomp_absurlX(PCStr(url),PVStr(proto),PVStr(login),PVStr(upath),int ulen,const char **urlpathpp);
int decomp_absurl(PCStr(url),PVStr(proto),PVStr(login),PVStr(upath),int ulen)
{
	return decomp_absurlX(url,BVStr(proto),BVStr(login),BVStr(upath),ulen,0);
}
int decomp_absurlX(PCStr(url),PVStr(proto),PVStr(login),PVStr(upath),int ulen,const char **urlpathpp)
{	const char *up = url;
	const char *ux;
	CStr(buf,MaxHostNameLen);
	char *bp; /**/
	const char *bx;
	unsigned char uc;

	if( urlpathpp ) *urlpathpp = 0;
	
	if( proto ) setVStrEnd(proto,0);
	if( login ) setVStrEnd(login,0);
	if( upath ) setVStrEnd(upath,0);

	bp = (char*)buf;
	bx = bp + 32 - 1;
	while( bp < bx && (uc = *up) && uc != ':' ){ *bp++ = *up++; } *bp = 0;
	if( proto ) strcpy(proto,buf);
	if( *up++ != ':' ) return 0;
	if( *up++ != '/' ) return 1;
	if( *up++ != '/' ) return 1;

	bp = (char*)buf;
	ux = up + sizeof(buf) - 1;
	while( up < ux && (uc = *up) && SITEC(uc) ){ *bp++ = *up++; } *bp = 0;
	if( login ) strcpy(login,buf);
	if( urlpathpp ) *urlpathpp = (char*)up;
	if( *up == '?' ) ; else
	if( *up++ != '/' ) return 2;

	if( upath == 0 )
		return 3;
	bp = (char*)upath;
	ux = url + (ulen - 1);
	while( up < ux && (uc = *up) && PATHC(uc) ){ *bp++ = *up++; } *bp = 0;

	return 3;
}

int strip_urlhead(PVStr(url),PVStr(proto),PVStr(login))
{	char rc;
	int ni;
	const char *urlpathp = 0;

	ni = decomp_absurlX(url,AVStr(proto),AVStr(login),VStrNULL,0,&urlpathp);
	if( 2 <= ni ){
		if( *urlpathp == '/' )
			ovstrcpy((char*)url,urlpathp);
		else	sprintf(url,"/%s",urlpathp);
	}
	return ni;
}

const char *scan_userpassX(PCStr(userpass),AuthInfo *ident)
{	const char *hp;
	const char *xp;
	const char *pp;
	const char *np;

	bzero(ident,sizeof(AuthInfo));
	lineScan(userpass,ident->i_user);
	ident->i_pass[0] = 0;

	if( xp = strpbrk(ident->i_user,"/?\r\n") )
		truncVStr(xp);
	if( hp = strrchr(ident->i_user,'@') )
		truncVStr(hp);
	if( pp = strchr(ident->i_user,':') ){
		truncVStr(pp);
		wordscanY(pp+1,MVStrSiz(ident->i_pass),"^\r\n");
	}
	if( hp )
		np = &userpass[hp-ident->i_user];
	else	np = &userpass[strlen(userpass)];
	return np;
}
#define EOHN	"^:/? \t\r\n\f\""
int decomp_siteX(PCStr(proto),PCStr(site),AuthInfo *ident)
{	const char *xp;
	const char *pp;

	xp = scan_userpassX(site,ident);
	if( *xp == '@' ){
		site = xp + 1;
	}else{
		ident->i_user[0] = 0;
		ident->i_pass[0] = 0;
	}

	pp = wordscanY(site,MVStrSiz(ident->i_Host),EOHN);
	if( *pp == ':' )
		pp++;
	else	pp = "";
	if( pp[0] )
		return ident->i_Port = atoi(pp);
	else	return ident->i_Port = serviceport(proto);
}
void site_strippass(PVStr(site))
{	const char *xp;
	AuthInfo ident;

	xp = scan_userpassX(site,&ident);
	if( *xp == '@' ){
		sprintf(site,"%s%s",ident.i_user,xp);
	}
}
void url_strippass(PVStr(url))
{	refQStr(sp,url); /**/

	if( sp = strstr(url,"://") )
		site_strippass(QVStr(sp+3,url));
}
int scan_hostportX(PCStr(proto),PCStr(hostport),PVStr(host),int hsiz)
{	int port;
	const char *pp;

	port = 0;
	pp = wordscanY(hostport,AVStr(host),hsiz,EOHN);
	if( *pp == ':' )
		port = atoi(pp+1);
	if( port == 0 )
		port = serviceport(proto);
	return port;
}
int scan_hostport1X(PCStr(hostport),PVStr(host),int hsiz)
{	const char *sp;
	char ch;
	refQStr(dp,host); /**/
	const char *xp = &host[hsiz-1];
	const char *pp;
	int port;

	port = 0;
	pp = 0;

	for( sp = hostport; ch = *sp; sp++ ){
		if( xp <= dp )
			break;
		else
		switch( ch ){
		    case '/': case '?':
		    case ' ': case '\t': case '\r': case '\n': case '\f':
			goto EXIT;

		    case ':':
			/* might be one in "user:pass@host" */
			port = atoi(sp+1);
			pp = dp;
			break;

		    case '@':
			cpyQStr(dp,host);
			port = 0;
			pp = 0;
			break;

		    default:
			if( (ch & 0x80) || ch <= 0x20 )
				goto EXIT;
			if( dp != sp )
				setVStrPtrInc(dp,ch);
			break;
		}
	}
EXIT:
	if( pp ) truncVStr(pp);
	if( *dp != 0 )
		setVStrEnd(dp,0);
	return port;
}
int scan_hostport1pX(PCStr(proto),PCStr(login),PVStr(host),int hsiz)
{	int port;

	port = scan_hostport1X(login,AVStr(host),hsiz);
	if( port == 0 )
		port = serviceport(proto);
	return port;
}
int scan_hostport0(PCStr(hostport),PVStr(host))
{	const char *sp;
	char ch;
	refQStr(dp,host); /**/
	int port;

	port = 0;
	for( sp = hostport; ch = *sp; sp++ ){
		assertVStr(host,dp+1);
		if( ch == ':' ){
			port = atoi(sp+1);
			break;
		}
		if( strchr("/ \t\r\n",ch) )
			break;
		setVStrPtrInc(dp,ch);
	}
	setVStrEnd(dp,0);
	return port;
}
int scan_hostport(PCStr(proto),PCStr(hostport),PVStr(host))
{	int iport;

	iport = scan_hostport0(hostport,AVStr(host));
	if( iport == 0 ){
		iport = serviceport(proto);
		/*
		if( iport == 0 )
		syslog_ERROR("## standard port for `%s' is unknown\n",proto);
		*/
	}
	return iport;
}

/*
 *	EXPAND PARTIAL HTTP-URL TO FULL SPEC URL:
 *	Absolute path in URL which have no http://H:P should be expanded to
 *	full description of URL, that is with http://HOST:PORT.
 *	Relative path will be expanded with http:H:P in the HTTP clients.
 */
char *HostPort(PVStr(hostport),PCStr(proto),PCStr(host),int port)
{
	if( serviceport(proto) != port )
		sprintf(hostport,"%s:%d",host,port);
	else	strcpy(hostport,host);
	return (char*)hostport;
}

#define isSchemeChar(ch)	(isalnum(ch)||(ch)=='+'||(ch)=='-'||(ch)=='.')

int isFullURL(PCStr(url))
{	const char *up;
	char ch;
	CStr(proto,128);
	refQStr(pp,proto); /**/

	if( !isSchemeChar(url[0]) )
		return 0;

	for( up = url; isSchemeChar(ch = *up); up++ )
	{
		if( 32 <= pp - proto )
			break;
		setVStrPtrInc(pp,ch);
	}
	setVStrEnd(pp,0);

	if( up[0] == ':' ){
		if( up[1] == '/' && up[2] == '/' )
			return 1;
		if( localPathProto(proto) && isFullpath(&up[1]) )
			return 1;
		if( streq(proto,"builtin") )
			return 1;
		if( streq(proto,"news") )
			return 1;
		if( streq(proto,"mailto") )
			return 1;
		if( streq(proto,"data") )
			return 1;
	}
	return 0;
}

const char *CTX_changeproxy_url(Connection*ctx,PCStr(clif),PCStr(method),PVStr(url),PVStr(proxy))
{	const char *opt;
	const char *mark;

	if( opt = CTX_changeproxy_url_to(ctx,clif,method,AVStr(url),AVStr(proxy)) )
		return opt;

	if( url[0] == '/' )
	if( (mark = NDGU_MARK) && strncmp(url+1,mark,strlen(mark)) == 0
	 || (mark = ODGU_MARK) && strncmp(url+1,mark,strlen(mark)) == 0 )
		return CTX_changeproxy_url_to(ctx,clif,method,QVStr(url+1+strlen(mark),url),AVStr(proxy));

	return NULL;
}

int url_upathbaselen(PCStr(base),int blen)
{	const char *sp;
	const char *xp;
	const char *tp;
	char tc;
	int nblen;

	sp = 0;
	xp = base + blen;
	for( tp = base; tp < xp; tp++ ){
		tc = *tp;
		if( tc == '?' )
			break;
		if( tc == '/' )
			sp = tp;
	}
	if( sp == 0 )
		nblen = 0;
	else	nblen = (sp+1) - base;
	if( nblen != blen ) 
		sv1vlog("URL BASE = %d/%d [%s]\n",nblen,blen,base);
	return nblen;
}
int scan_url1(PCStr(url),PVStr(values));
static void setBASE(Referer *referer,PCStr(url))
{	CStr(values,URLSZ);
	const char *av[64]; /**/
	const char *v1;
	refQStr(ap,referer->r_altbuf); /**/
	const char *dp;
	int len;
	CStr(burl,URLSZ);

	if( referer->r_altbuf == NULL )
		return;

	if( (len = scan_url1(url,AVStr(values))) <= 0 )
		return;

	strncpy(burl,url,len); setVStrEnd(burl,len);
	sv1log("<BASE HREF=%s>\n",burl);

	stoV(values,64,av,'\n');
	if( v1 = getv(av,"proto")){
		referer->r_sv.u_proto = ap;
		strcpy(ap,v1);
		ap += strlen(ap) + 1;
	}
	if( v1 = getv(av,"host") ){
		referer->r_sv.u_host = ap;
		strcpy(ap,v1);
		ap += strlen(ap) + 1;
	}
	if( v1 = getv(av,"port") )
		referer->r_sv.u_port = atoi(v1);

	if( v1 = getv(av,"path") ){
		referer->r_sv.u_path = ap;
		strcpy(ap,v1);
		ap += strlen(ap) + 1;

	    {
		int blen;
		referer->r_sv.u_base = ap;
		blen = url_upathbaselen(v1,strlen(v1));
		strncpy(ap,v1,blen);
		XsetVStrEnd(AVStr(ap),blen);
		ap += blen + 2;
	    }
	}
}
static void getBASE(Referer *referer,const char **myhp,const char **proto,const char **hostport,const char **host,int *port,const char **base)
{
	if( referer->r_qvbase.u_proto ){ /* v9.9.11 new-140810f, VBASE */
		*myhp = referer->r_qvbase.u_hostport;
		*proto = referer->r_qvbase.u_proto;
		*hostport = referer->r_qvbase.u_hostport;
		*host = referer->r_qvbase.u_host;
		*port = referer->r_qvbase.u_port;
		*base = referer->r_qvbase.u_base;
		return;
	}else
	if( referer->r_vb.u_proto )
		*myhp = referer->r_vb.u_hostport;
	else	*myhp = referer->r_my.u_hostport;

	*proto = referer->r_sv.u_proto;
	*hostport = referer->r_sv.u_hostport;
	*host = referer->r_sv.u_host;
	*port = referer->r_sv.u_port;
	*base = referer->r_sv.u_base;
}

void url_relative(PVStr(relurl),PCStr(absurl),PCStr(baseurl))
{	int ui,nsl;

	nsl = 0;
	for( ui = 0; absurl[ui] && baseurl[ui]; ui++ ){
		if( absurl[ui] != baseurl[ui] )
			break;
		if( absurl[ui] == '/' )
			nsl++;
		if( nsl == 3 )
			break;
	}
	if( nsl == 3 ){
		setVStrEnd(relurl,0);
		return;
	}
	strcpy(relurl,absurl);
}

#define UREND(ch)	(ch=='"' || ch=='>' || isspace(ch) || ch=='\0')
#define CURDIR(u)	(u[0]=='.' && (u[1]=='/' || UREND(u[1])) ? &u[1] : 0)
#define UPDIR(u)	(u[0]=='.' ? CURDIR((&u[1])) : 0)

int urlpath_normalize(PCStr(url),PVStr(rurl))
{	const char *up;
	const char *np;
	refQStr(xp,rurl); /**/
	char uc;
	int norm;

	up = url;
	norm = 0;

	while( uc = *up ){
		assertVStr(rurl,xp+1);
		/*
		 * up points to the top of a URL element
		 */
		if( uc == '/' ){
			if( xp != up )
				setVStrPtrInc(xp,uc);
			else	xp++;
			uc = *++up;
		}
		if( uc == '?' || UREND(uc) ){
			if( xp != up ){
				strcpy(xp,up);
				xp += strlen(xp);
			}
			break;
		}
		if( np = CURDIR(up) ){
			norm++;
			if( *np == '/' )
				np++;
			up = np;
			continue;
		}
		if( np = UPDIR(up) ){
			norm++;
			if( *np == '/' )
				np++;
			up = np;
			if( rurl < xp )
				xp--;
			while( rurl < xp ){
				if( *--xp == '/' ) 
					break;
			} 
			if( *xp == '/')
				xp++;
			setVStrEnd(xp,0);
			continue;
		}

		/*
		 * skip to the top of the next URL element
		 */
		while( uc = *up ){
			if( uc == '/' || uc == '?' || UREND(uc) )
				break;
			if( xp != up )
				setVStrPtrInc(xp,*up++);
			else{
				xp++;
				up++;
			}
		}
	}
	if( xp != up )
		XsetVStrEnd(AVStr(xp),0);

	return xp != up;
}

/*
 * care an abnormal pointer to outer space of the server ...
 * care only "../" at the top of URL to make the normalization be light weight
 */
int url_normalize(PCStr(base),PCStr(url),int *blen)
{	const char *up;
	const char *bp;
	const char *xp;
	int nup,abu;

	/*
	 * "./" should not be stripped ?
	 * when the "base" is not root of the site...
	 * if( !UPDIR(url) ){
	 */
	if( !CURDIR(url) && !UPDIR(url) ){
		*blen = strlen(base);
		return 0;
	}

	bp = base + strlen(base);
	up = url;
	nup = 0;
	abu = 0;
	if( xp = CURDIR(up) ){
		if( *xp != '/' )
			up = xp;
		else	up = xp + 1;
	}
	while( xp = UPDIR(up) ){
		nup++;
		if( bp == base )
			abu = 1;
		else{
			while( base < bp )
				if( *--bp == '/' )
					break;
		}
		if( *xp != '/' ){
			up = xp;
			break;
		}else{
			up = xp + 1;
		}
	}
	if( nup ){
		if( bp == base )
			abu = 1;
		else{
			while( base < bp )
				if( *--bp == '/' )
					break;
		}
	}
	if( abu && LOG_VERBOSE ){
		CStr(ub,32);
		QStrncpy(ub,url,16);
		Verbose("ABNORMAL-URL: base<%s> url<%s>\n",base,ub);
	}
	*blen = bp - base;
	return up - url;
}

int java_conv(PCStr(line),PVStr(xline),int uconvs)
{	int uconv,nconv;
	const char *sp = line;
	const char *np;
	refQStr(xp,xline); /**/
	const char *tagp;
	int len;
	const char *tag;
	CStr(tagb,32);
	const char *tp;
	Referer *referer = 0;

	for( nconv = 0; ; nconv++ ){
		uconv = uconvs;
		np = html_nextTagAttr(sp,"",VStrNULL,&tagp,NULL,&uconv);
		if( np == NULL )
			break;

		if( (uconv & (TAGCONV_KILL|TAGCONV_JAVA)) == 0 )
			break;

		tagb[0] = 0;
		if( tagp != NULL ){
			tp = tagp;
			if( *tp == '<' ){
				tp++;
				if( *tp == '/' )
					tp++;
				wordScanY(tp,tagb,"^ \t\r\n>");
				tag = tagb;
			}
		}

		if( tagp != NULL ){
			if( (uconv & TAGCONV_KILL) && tagb[0] ){
			}else
			if( strncasecmp(tagp,"</APPLET",8) == 0 ) tag = "APPLET"; else
			if( strncasecmp(tagp,"<APPLET", 7) == 0 ) tag = "APPLET"; else
			if( strncasecmp(tagp,"</OBJECT",8) == 0 ) tag = "OBJECT"; else
			if( strncasecmp(tagp,"<OBJECT", 7) == 0 ) tag = "OBJECT"; else
			if( strncasecmp(tagp,"</EMBED", 7) == 0 ) tag = "EMBED";  else
			if( strncasecmp(tagp,"<EMBED",  6) == 0 ) tag = "EMBED";  else
			{
				if( TAGTRACE )
				sv1log("## TAG NOMATCH %s\n",tagp);
				tagp = NULL;
			}
		}

		if( tagp == NULL ){
			len = np - sp;
			Bcopy(sp,xp,len);
			xp += len;
			sp = np;
			continue;
		}

		sv1log("## TAG %s -> killed-%s\n",tag,tag);
		len = tagp+1 - sp;
		Bcopy(sp,xp,len);
		xp += len;
		sp = tagp+1;
		XsetVStrEnd(AVStr(xp),0);

		if( *sp == '/' ){
			sp += 1;
			setVStrPtrInc(xp,'/');
		}
		sp += strlen(tag);
		sprintf(xp,"killed-%s",tag);
		xp += strlen(xp);
	}
	strcpy(xp,sp);
	return nconv;
}

int url_unify_ports = 0;
#define PORT_MARK	"-.-P"
void url_delport(PVStr(url),int *portp)
{	const char *dp; /* not "const" but fixed */
	CStr(port,32);

	if( dp = strstr(url,PORT_MARK) ){
		wordScanY(dp+4,port,"0123456789");
		*portp = atoi(port);
		ovstrcpy((char*)dp,dp+4+strlen(port));
	}
}
#define EOURL	"^ \t\r\n\"'>"
int url_movport(PCStr(url),PVStr(vurl),int siz)
{	refQStr(dp,vurl); /**/
	CStr(proto,64);
	CStr(port,32);
	CStr(xport,32);
	int ilen = 0;

	if( !url_unify_ports )
		return 0;

	wordscanY(url,AVStr(vurl),siz,EOURL);
	if( dp = strstr(vurl,"://") )
	if( dp = strpbrk(dp+3,":/? \t\r\n\"'") )
	if( *dp == ':' ){
		ilen = strlen(vurl);
		wordScanY(dp+1,port,"0123456789");
		if( port[0] ){
			sprintf(xport,"%s%s",PORT_MARK,port);
			ovstrcpy((char*)dp,dp+1+strlen(port));
			if( dp = strpbrk(vurl,"?#") )
				;
			else	dp = (char*)vurl + strlen(vurl);
			Strins(AVStr(dp),xport);
		}
	}
	if( ilen == 0 )
		setVStrEnd(vurl,0);
	return ilen;
}

#define SkipQuoted(where,referer,np,sp,xp) { \
	int qch; \
	int ch; \
	const char *qp; \
	if( qch = referer->r_tagctx.r_curquote ){ \
		for( qp = np; (ch = *qp); qp++ ) \
			if( ch == qch ) \
				break; \
		if( ch == qch && sp <= qp ){ \
			while( ch = *sp ){ \
				setVStrPtrInc(xp,*sp++); \
				if( ch == qch ) \
					break; \
			} \
		} \
	} \
}

void url_absoluteS(Referer *referer,PCStr(line),PVStr(xline),PVStr(rem))
{	const char *myhp;
	const char *proto;
	const char *host;
	int   port;
	const char *base;
	const char *hp;
	CStr(hostportb,MaxHostNameLen);
	const char *sp = line;
	const char *np;
	refQStr(xp,xline); /**/
	int ch;
	const char *tagp;
	int uconv;

	getBASE(referer,&myhp,&proto,&hp,&host,&port,&base);

	for(;;){
		uconv = URICONV_ANY;
		np = (char*)html_nextTagAttr(sp,"",AVStr(rem),&tagp,NULL,&uconv);
		if( np == NULL )
			break;

		/* white spaces in "CDATA" ...
		 * http://www.w3.org/TR/html401/types.html#type-cdata
		 */
		if( referer->r_tagctx.r_curquote ){
			const char *dp = np;
			while( isspace(*dp) )
				dp++;
			if( np < dp ){
				ovstrcpy((char*)np,dp);
			}
			/* space in URL should be cared if it affect MOUNT... */
		}

		if( referer->r_altbuf != NULL && tagp != NULL && isBASE(tagp) ){
			setBASE(referer,np);
			getBASE(referer,&myhp,&proto,&hp,&host,&port,&base);
		}

		ch = np[0];
		((char*)np)[0] = 0; /**/
		strcpy(xp,sp);
		xp += strlen(xp);
		((char*)np)[0] = ch; /**/
		sp = np;

		if( strncasecmp(np,"nntp://-.-/",11) == 0 ){
			sp += 11;
			sprintf(xp,"nntp://%s/",myhp);
		}else
		if( strncasecmp(np,"http://-.-/",11) == 0 ){
			sp += 11;
			sprintf(xp,"http://%s/",myhp);
		}else
		if( isFullURL(np) ){
		}else
		if( strncasecmp(np,"http:/",6) == 0 ){
		    if( np[6] != '/' ){
			sp += 6;
			HostPort(AVStr(hostportb),"http",host,port);
			sprintf(xp,"http://%s/",hostportb);
		    }
		}
		else
		if( ch != '/' && streq(proto,"ftp") )
		{
			/* Relay ftp to the proxy server for non-proxy client,
			 * who see current protocol as HTTP, thus will not
			 * make automatic expansion of relative URL of ftp type.
			 */
			if( ch == '.' && np[1] == '/' )
				sp += 2;
			strcpy(xp,base);
		}
		else
		if( ch == '/' && np[1] != '/' ){
			/* Absolute path without host:port. This will be cause
			 * ignoreing =@=:realhost:realport part in the current
			 * page's URL
			 */
			sp += 1;
			sprintf(xp,"%s://%s/",proto,hp);
		}
		else
		if( ch == '/' && np[1] == '/' ){ /* with host:port */
			sp += 2;
			sprintf(xp,"%s://",proto);
		}
		else
		if( ch == '$' && strncaseeq(np,"${VBASE}",8) ){ /* v9.9.11 new-140809e */
			sp += 8;
			if( referer->r_qvbase.u_proto ){
				UrlX *up = &referer->r_qvbase;
				sprintf(xp,"%s://%s/%s",up->u_proto,
					up->u_hostport,up->u_path);
			}
		}else
		if( ch == '$' && strncaseeq(np,"${SELF}",7) ){ /* v9.9.11 new-140809h */
			sp += 7;
			if( referer->r_requrl.u_path ){
				UrlX *up = &referer->r_requrl;
				sprintf(xp,"%s://%s/%s",up->u_proto,
					up->u_hostport,up->u_path);
			}
		}else
		if( ch == '?' ){ /* 9.9.11 new-140812a */
		    if( (uconv & URICONV_FULL) != 0 ){
			if( (referer->r_flags & UMF_QUERY_FULL) != 0 ){
				UrlX *ux;
				if( referer->r_qvbase.u_path ){
					ux = &referer->r_qvbase;
				}
				else
				if( referer->r_requrl.u_path ){
					ux = &referer->r_requrl;
				}
				else{
					/* should not happen */
				}
				sprintf(xp,"%s://%s/%s",ux->u_proto,
					ux->u_hostport,ux->u_path);
			}
		    }
		}else
		if( ch == '#' ){ /* 9.9.11 new-140727m */
		    if( (uconv & URICONV_FULL) != 0 ){
			/*
			sprintf(xp,"%s://%s/%s",proto,hp,referer->r_sv.u_path+1);
			*/
			sprintf(xp,"%s://%s/%s",proto,hp,referer->r_sv.u_path);
			/* v9.9.12 fix-140814e, setReferer() is fixed to set
			 * r_sv.u_path removing leading '/' of "/upath".  This
			 * was bad because setBASE() by <BASE HREF=URL> set
			 * r_sv.u_path removing leading '/' thus it did not
			 * work by the above "+1".  Anyway, u_path should be
			 * without leading '/' by the definition. And
			 * r_sv.u_path is used nowhere except here currently,
			 * so no side effect will be.
			 */
		    }
		}else
		if( uconv & (URICONV_FULL|URICONV_NORMAL) ){
			int uplen,blen;

/*
			if( *base == '/' ) base++;
*/
			uplen = url_normalize(base,sp,&blen);

			if( *np != '#' )
			if( (uconv & URICONV_FULL) || uplen ){
				sprintf(xp,"%s://%s/",proto,hp);
				sp += uplen;
				if( 0 < blen ){
					xp += strlen(xp);
					strncpy(xp,base,blen);
					XsetVStrEnd(AVStr(xp),blen);
					if( xp[blen-1] != '/' )
						Xstrcpy(QVStr(&xp[blen],xline),"/");
					else	XsetVStrEnd(AVStr(xp),blen);
				}
			}
		}
		if( url_unify_ports ){
			if( *xp ){
				if( strncasecmp(xp,"http://",7) == 0 ){
					CStr(nb,512);
					refQStr(tp,xline); /**/
					const char *up;

					tp = (char*)xp + strlen(xp);
					up = wordscanY(sp,AVStr(tp),256,EOURL);
					if( url_movport(xp,AVStr(nb),sizeof(nb)) ){
						strcpy(xp,nb);
						sp = up;
					}else	setVStrEnd(tp,0);
				}
			}else{
				int ilen;
				if( strncasecmp(np,"http://",7) == 0 ){
					if( ilen = url_movport(np,AVStr(xp),256) )
						sp += ilen;
				}
			}
		}
		xp += strlen(xp);
		SkipQuoted("absolute",referer,np,sp,xp);
	}
	strcpy(xp,sp);
}
void url_absolute(PCStr(myhp),PCStr(proto),PCStr(host),int port,PCStr(base),PCStr(line),PVStr(xline),PVStr(rem))
{	Referer referer;
	CStr(hostport,128);

	bzero(&referer,sizeof(Referer));
	referer.r_my.u_hostport = myhp;
	referer.r_sv.u_hostport = HostPort(AVStr(hostport),proto,host,port);
	referer.r_sv.u_proto = proto;
	referer.r_sv.u_host = host;
	referer.r_sv.u_port = port;
	referer.r_sv.u_base = base;
	setQStr(referer.r_altbuf,NULL,0);
	url_absoluteS(&referer,line,AVStr(xline),AVStr(rem));
}

/*
 *	TRANSFORM URL TO delegated-URL
 *	This function assumes that URLs in the "line" is in FULL-SPEC
 *	format of URL without omittion of protocol-name nor host-port field.
 */
void CTX_url_delegateS(Connection*ctx,Referer *referer,PCStr(line),PVStr(xline),/*char *dgrelay*/int dgrelay)
{	const char *sp = line;
	const char *np;
	refQStr(xp,xline); /**/
	CStr(rurl,URLSZ);
	int ulen;
	int ch;
	int uconv;
	int qch;

	UrlX *ux;
	const char *myproto;
	const char *myhost;
	const char *mypath;
	int myport;

	if( referer->r_qvbase.u_proto ){ /* v9.9.11 new-140810f, VBASE */
		ux = &referer->r_qvbase;
	}else
	if( referer->r_vb.u_proto )
		ux = &referer->r_vb;
	else	ux = &referer->r_my;
	myproto = ux->u_proto;
	myhost = ux->u_host;
	myport = ux->u_port;
	mypath = ux->u_path;


	for(;;){
		uconv = URICONV_ANY & ~(URICONV_FULL | URICONV_PARTIAL);
			/* should be URICONV_MOUNT ? */
		np = (char*)html_nextTagAttr(sp,"",VStrNULL,NULL,NULL,&uconv);
		if( np == NULL )
			break;
		qch = referer->r_tagctx.r_curquote;

		ch = *np;
		*(char*)np = 0;  /**/

		strcpy(xp,sp); xp += strlen(xp);
		*(char*)np = ch; /**/
		sp = np;

		if( ulen = CTX_url_rurlX(ctx,qch,np,AVStr(rurl),myproto,myhost,myport,mypath,dgrelay) )
		if( strncmp(sp+ulen,ODGU_MARK,strlen(ODGU_MARK)) != 0 )
		if( strncmp(sp+ulen,NDGU_MARK,strlen(NDGU_MARK)) != 0 )
		{
			strcpy(xp,rurl);
			sp += ulen;
			xp += strlen(xp);
		}
		SkipQuoted("deleate",referer,np,sp,xp);
	}
	strcpy(xp,sp);
}
void scan_url(PCStr(line),iFUNCP func,void *arg1,void *arg2)
{	const char *sp;
	const char *np;
	const char *tp;
	char tc;
	int ulen;
	Referer *referer = 0;

	sp = line;
	while( np = html_nextTagAttr(sp,"",VStrNULL,NULL,NULL,NULL) ){
		if( tp = strpbrk(np," \t\r\n\">") ){
			ulen = tp - np;
			tc = *tp;
			*(char*)tp = 0;  /**/
			(*func)((char*)np,arg1,arg2);
			*(char*)tp = tc; /**/
			sp = np + ulen;
		}else	break;
	}
}


/*
 *	delegated-URL SYNTHESIZER
 *	Given "attrs" is a NL-separated list of NAME=VALUEs.  This is a
 *	output format of URL parser in the SLL library.
 */

int callback_it(PCStr(proto));
static char *delegate_url(Connection*ctx,PVStr(url),PCStr(attrs),PCStr(ourl),int olen,/*char *dgrelay*/int dgrelay)
{	CStr(abuf,URLSZ);
	const char *av[64]; /**/
	int ac;
	refQStr(up,url); /**/
	const char *proto;
	const char *val;
	const char *hostport;
	const char *delegate;
	const char *dproto;
	const char *path;
	CStr(xpath,URLSZ);
	const char *search;
	const char *gselector;
	CStr(oURLbuf,URLSZ);
	const char *modifiers;

	strcpy(abuf,attrs);
	ac = stoV(abuf,64,av,'\n');

	proto = getv(av,"proto");
	dproto = getv(av,"dproto");
	delegate = getv(av,"delegate");
	if( delegate == 0 )
		return 0;
	hostport = getv(av,"hostport");
	if( hostport == NULL ) hostport = getv(av,"host");
	if( hostport == NULL /* && inScript */ ){
		hostport = "";
	}
	path = getv(av,"path");
	search = getv(av,"search");

if( CTX_mount_url_fromL(ctx,AVStr(url),proto,hostport,path,search,dproto,delegate) )
return (char*)url + strlen(url);

	if( dgrelay == 0 )
		return 0;

	if( proto == 0 )
		return 0;

	if( callback_it(proto) == 0 )
		return 0;

	if( dproto == NULL )
		dproto = "http";

	if( hostport == 0 )
		return 0;

	if( streq(proto,"news") )
		return 0;
	if( streq(proto,"telnet") )
		return 0;

/*
	if( !isRELAYABLE(dgrelay,proto,hostport) )
		return 0;
*/
	if( !isREACHABLE(proto,hostport) )
		return 0;

	if( streq(proto,dproto) )
	if( delegate && hostport && streq(delegate,hostport) )
		return 0; /* no rewriting is necessary */

	if( path && nonxalpha_unescape(path,AVStr(xpath),1) )
		path = xpath;

	gselector = 0;

	strncpy(oURLbuf,ourl,olen); setVStrEnd(oURLbuf,olen);

	cpyQStr(up,url); 
	up = Sprintf(AVStr(up),"%s://",dproto);

	if( !GOPHER_ON_HTTP && streq(proto,"gopher") ){
		up = Sprintf(AVStr(url),"gopher://");
		gselector = getv(av,"path");
		if( gselector == 0 || *gselector == 0 )
			gselector = "1";
	}

	up = Sprintf(AVStr(up),"%s",delegate);
	if( gselector )
		up = Sprintf(AVStr(up),"/%c",*gselector);
	else	up = Sprintf(AVStr(up),"/");

	if( strncmp(ourl,url,strlen(url)) == 0 ){
		/* is this right ?  doesn't it suppress necessary one ? */
		/*Verbose("####### DON'T MAKE DUPLICATE REWRITE: %s\n",url);*/
		return 0;
	}

modifiers = CTX_get_modifires((Connection*)ctx);
/*
if( modifiers[0] && up[-1] == '/' )
	up = Sprintf(up,"%s",modifiers);
else
if( DELEGATE_FLAGS[0] )
if( up[-1] == '/' )
	up = Sprintf(up,"F%s",DELEGATE_FLAGS);
else	up = Sprintf(up,"(F%s)",DELEGATE_FLAGS);
*/

	up = Sprintf(AVStr(up),"%s",NDGU_MARK);

if( modifiers[0] )
up = Sprintf(AVStr(up),"/%s/",modifiers);

	up = Sprintf(AVStr(up),"%s",oURLbuf);
	return (char*)up;
}
void delegate_selector(Connection *Conn,PVStr(xselector),PCStr(host),int iport,int gtype)
{	CStr(dgopher,1024);
	CStr(tmp,1024);
	refQStr(dp,dgopher); /**/

	dp = Sprintf(AVStr(dgopher),NDGU_MARK);
	if( DELEGATE_FLAGS[0] )
		dp = printFlags(Conn,AVStr(dp));

	dp = Sprintf(AVStr(dp),"gopher://%s:%d/%c",host,iport,gtype?gtype:'1');
	strcpy(tmp,xselector);
	sprintf(xselector,"%s%s",dgopher,tmp);
}

char *file_hostpath(PCStr(url),xPVStr(proto),xPVStr(login))
{	CStr(protobuf,128);
	CStr(hostbuf,128);
	const char *path;

	if( strchr(url,':') == NULL )
		return NULL;

	if( proto == NULL )
		setPStr(proto,protobuf,sizeof(protobuf));

	setVStrEnd(proto,0);

	if( login == NULL )
		setPStr(login,hostbuf,sizeof(hostbuf));
	setVStrEnd(login,0);

	Xsscanf(url,"%[a-zA-Z0-9]",AVStr(proto));
	if( !localPathProto(proto) )
		return NULL;

	path = url + strlen(proto);
	if( path[0] != ':' )
		return NULL;
	path += 1;

	if( strncmp(path,"//",2) == 0 ){
		path += 2;
		if( path[0] == '/' )
			strcpy(login,"localhost");
		else{
			Xsscanf(path,"%[^/]",AVStr(login));
			path += strlen(login);
		}
	}
	return (char*)path;
}



/*
 *	SCAN A URL AND EXPANDS IT TO A delegated-URL
 */

#include "SLL.h"
extern SLLRule URL[];

/*
 * the end of url should be detected by the closing char. "qch"
 * like <"> or <'> when the url[-1] is <"> or <'>
 */
int SLLparseURL(int qch,PCStr(srca),const char **nsrcp,putvFunc putv,PVStr(vala),int size,char **nvalp)
{	int rcode;
	char eouc;
	const char *eoup; /* not "const" but fixed */

	eoup = 0;
	if( qch != 0 && (eoup = strchr(srca,qch)) ){
		/*
		... This is not good for rURL*%pat$ matching for attr='URL'
		eoup++;
		*/
		eouc = *eoup;
		*(char*)eoup = 0; /**/
	}else
	if( qch == 0 && (eoup = strpbrk(srca," \t\r\n")) ){
		/* multiple attributes in a single tag may include URL,
		 * so leave the following attribute to be scanned
		 */
		eouc = *eoup;
		*(char*)eoup = 0;
	}

	/*
	 * SLLparse should be given the length of source string.
	 */
	rcode = SLLparse(0,URL,srca,nsrcp,putv,AVStr(vala),size,nvalp);
	if( eoup ){
		*(char*)eoup = eouc; /**/
	}
	return rcode;
}

int CTX_url_rurlX(Connection*ctx,int qch,PCStr(url),PVStr(rurl),PCStr(dproto),PCStr(dhost),int dport,PCStr(dpath),/*char *dgrelay*/int dgrelay)
{	const char *nurl;
	CStr(values,URLSZ);
	CStr(hostport,MaxHostNameLen);
	refQStr(vp,values); /**/
	const char *proto;
	const char *rp;
	const char *tail;
	int len;

	if( strncmp(url,"!-_-",4) == 0 ){
		strcpy(rurl,url+4);
		return strlen(url);
	}

	if( reserve_url((Connection*)ctx) )
		return 0;

	nurl = url;
	cpyQStr(vp,values);
	values[0] = 0;

	setVStrEnd(rurl,0);
	if( SLLparseURL(qch,url,&nurl,SLL_putval,AVStr(vp),URLSZ,(char**)&vp) == 0 ){
		len = nurl - url;
		if( dproto && dproto[0] )
			vp = Sprintf(AVStr(vp),"dproto=%s\n",dproto);

		if( dhost && dhost[0] ){
			if( dproto && dproto[0] )
				HostPort(AVStr(hostport),dproto,dhost,dport);
			else	sprintf(hostport,"%s:%d",dhost,dport);
			if( *dpath != 0 && *dpath != '/' )
			vp = Sprintf(AVStr(vp),"delegate=%s/%s\n",hostport,dpath);
			else
			vp = Sprintf(AVStr(vp),"delegate=%s%s\n",hostport,dpath);
		}
		if((tail = delegate_url(ctx,AVStr(rurl),values,url,len,dgrelay)) == 0)
			return 0;
		return len;
	}
	return 0;
}

int url_partializeS(Referer *referer,PCStr(line),PVStr(xline))
{	const char *myproto;
	const char *myhost;
	int myport;
	const char *sp;
	const char *np;
	refQStr(xp,xline); /**/
	const char *nurl;
	URLStr purl;
	CStr(values,URLSZ);
	const char *av[64]; /**/
	refQStr(vp,values); /**/
	const char *proto;
	const char *host;
	const char *port;
	const char *path;
	const char *search;
	int porti;
	int len;
	int nmod;
	int umask;
	int qch;

	myproto = referer->r_my.u_proto;
	myhost = referer->r_my.u_host;
	myport = referer->r_my.u_port;

	sp = line;
	nmod = 0;

	for(;;){
		umask = URICONV_PARTIAL;
		np = html_nextTagAttr(sp,"",VStrNULL,NULL,NULL,&umask);
		if( np == NULL )
			break;
		qch = referer->r_tagctx.r_curquote;

		len = np - sp;
		Bcopy(sp,xp,len); XsetVStrEnd(AVStr(xp),len);
		xp += len;
		sp = np;
		cpyQStr(vp,values);

		if( umask & URICONV_FULL ){
			/* conflicting, adopt FULL prior to PARTIAL ... */
		}else
		if( SLLparseURL(qch,np,&nurl,SLL_putval,AVStr(vp),URLSZ,(char**)&vp) == 0 ){
			stoV(values,64,av,'\n');
			if( proto = getv(av,"proto") )
			if( host  = getv(av,"host" ) ){
				if( port = getv(av,"port") )
					porti = atoi(port);
				else	porti = serviceport(proto);
				path = getv(av,"path");
				search = getv(av,"search");

				if( porti == myport )
				if( strcaseeq(proto,myproto) )
				if( hostcmp_lexical(host,myhost,1) == 0 ){
					sp += nurl - np;
					setVStrPtrInc(xp,'/');
					if( path )
						strcpy(xp,path);
					else	setVStrEnd(xp,0);
					if( search ){
						xp += strlen(xp);
						setVStrPtrInc(xp,'?');
						strcpy(xp,search);
					}
					nmod++;
				}
			}
		}
		xp += strlen(xp);
		SkipQuoted("partialize",referer,np,sp,xp);
	}
	strcpy(xp,sp);
	return nmod;
}

/*
 *	SCAN A URL-EXTENTION
 */
extern SLLRule URLX[];

void putv(PCStr(t),PCStr(n),int l,PCStr(vb))
{	CStr(buf,1024);

	strncpy(buf,n,l); setVStrEnd(buf,l);
	printf("%s=%s\n",t,buf);
}

int scan_url1(PCStr(url),PVStr(values))
{	const char *nurl;
	refQStr(vp,values); /**/

	nurl = url;
	cpyQStr(vp,values);
	setVStrEnd(values,0);
	if( SLLparse(0,URL,url,&nurl, SLL_putval,AVStr(vp),URLSZ,(char**)&vp ) == 0 )
		return nurl - url;
	return 0;
}
int scan_urlx(PCStr(urlx),PVStr(values))
{	const char *nurlx;
	refQStr(vp,values); /**/

	nurlx = (char*)urlx;
	cpyQStr(vp,values);
	setVStrEnd(values,0);
	if( SLLparse(0,URLX,urlx,&nurlx, SLL_putval,AVStr(vp),URLSZ,(char**)&vp ) == 0 )
		return nurlx - urlx;
	return 0;
}


/*
 *	URL SYNTAX TABLES FOR SLL LIBRARY
 */

static char DIGIT[] = "0123456789";
static char ALPHA[] = "\
abcdefghijklmnopqrstuvwxyz\
ABCDEFGHIJKLMNOPQRSTUVWXYZ\
";

static char ALPHADIGIT[] = "\
abcdefghijklmnopqrstuvwxyz\
ABCDEFGHIJKLMNOPQRSTUVWXYZ\
0123456789\
";

static char ALNUM[] = "\
abcdefghijklmnopqrstuvwxyz\
ABCDEFGHIJKLMNOPQRSTUVWXYZ\
0123456789-\
";

extern char SLL_OTHERWISE[];
#define OTHERWISE SLL_OTHERWISE

/*
static char NALPHA[] = "\
abcdefghijklmnopqrstuvwxyz\
ABCDEFGHIJKLMNOPQRSTUVWXYZ\
0123456789\
$-_.&+\
!*'();, \
";
*/
static char NALPHA[] = "\
abcdefghijklmnopqrstuvwxyz\
ABCDEFGHIJKLMNOPQRSTUVWXYZ\
0123456789\
$-_.&+\
!*'();,\
";

static char XALPHA[] = "\
abcdefghijklmnopqrstuvwxyz\
ABCDEFGHIJKLMNOPQRSTUVWXYZ\
0123456789\
$-_.&+\
!*'():;, %\
";

static char YALPHA[] = "\
abcdefghijklmnopqrstuvwxyz\
ABCDEFGHIJKLMNOPQRSTUVWXYZ\
0123456789\
$-_@.&+\
!~*'():;, %\
";

/* "|" is not in "uric" in RFC2396 but usually used in CGI-Counter for ex. */
static char URIC[] = "\
abcdefghijklmnopqrstuvwxyz\
ABCDEFGHIJKLMNOPQRSTUVWXYZ\
0123456789\
;/?:@&=+$,\
-_.!~*'()\
%\
|\
";

ISRULE( URL	);
ISRULE( HTTP	);
ISRULE( GOPHER	);
ISRULE( FTP	);
ISRULE( FILEP	);
ISRULE( NEWS	);
ISRULE( NNTP	);
ISRULE( WAIS	);
ISRULE( DATAS	);

/*
ISRULE( AFS	);
ISRULE( MAILTO	);
ISRULE( TELNET	);
ISRULE( GENERIC);
*/

ISRULE( HOSTPORT);
ISRULE( PATH);
ISRULE( SEARCH);

ALT(URL)
	{ "proto",	"https",	HTTP,		IGNCASE|PUTGATE}, /* must be before http */
	{ "proto",	"http",		HTTP,		IGNCASE|PUTGATE},
	{ "proto",	"gopher",	GOPHER,		IGNCASE|PUTGATE},
	{ "proto",	"ftp",		FTP,		IGNCASE|PUTGATE},
	{ "proto",	"sftp",		FTP,		IGNCASE|PUTGATE},
	{ "proto",	"file",		FILEP,		IGNCASE|PUTGATE},
	{ "proto",	"news",		NEWS,		IGNCASE|PUTGATE},
	{ "proto",	"nntp",		NNTP,		IGNCASE|PUTGATE},
	{ "proto",	"wais",		WAIS,		IGNCASE|PUTGATE},
	{ "proto",	"data",		DATAS,		IGNCASE|PUTGATE},
/*
	{ "proto",	"afs://",	AFS,		IGNCASE|PUTGATE},
	{ "proto",	"mailto::",	MAILTO,		IGNCASE|PUTGATE},
	{ "proto",	"telnet:",	TELNET,		IGNCASE|PUTGATE},
	{ "proto",	IMM,		GENERIC,	IGNCASE|PUTGATE},
*/
END

SEQ(HTTP)
	{ "://",	"://",		NEXT		},
/*
	{ "hostport",	IMM,		HOSTPORT,	PUTVAL},
*/
	{ "hostport",	IMM,		HOSTPORT,	xOPTIONAL|PUTVAL},
	{ "path",	"/",		PATH,		xOPTIONAL|PUTVAL},
	{ "search",	"?",		SEARCH,		xOPTIONAL|PUTVAL},
END

ISRULE( IALPHA );
ISRULE( DIGITS );
ISRULE( ALPHAS );
ISRULE( NALPHAS);
ISRULE( XALPHAS);
ISRULE( YALPHAS);
ISRULE( DOMLABEL);

SEQ(HOSTNAME)
	{ "name",	IMM,		DOMLABEL	},
	{ "name",	".",		HOSTNAME,	xOPTIONAL},
END
SEQ(HOSTNUMBER)
	{ "num1",	IMM,		DIGITS		},
	{ "num2",	".",		DIGITS		},
	{ "num3",	".",		DIGITS		},
	{ "num4",	".",		DIGITS		},
END
/* try HOSTNUMBER first, not to let 123.123.123.123 be matched with HOSTNAME */
ALT(HOST)
	{ "number",	IMM,		HOSTNUMBER	},
	{ "name",	IMM,		HOSTNAME	},
END
SEQ(PORT)
	{ "number",	IMM,		DIGITS		},
END
SEQ(HOSTPORT)
	{ "host",	IMM,		HOST,		PUTVAL},
	{ "port",	":",		PORT,		xOPTIONAL|PUTVAL},
END

ALT(DOMLABEL2)
	{ "alphadigit",	ALPHADIGIT,	DOMLABEL2,	CHARSET},
	{ "hyphen",	"-",		DOMLABEL	},
	{ "terminate",	OTHERWISE,	SUCCESS		},
END
SEQ(DOMLABEL)
	{ "alphadigit",	ALPHADIGIT,	DOMLABEL2,	CHARSET},
END

SEQ(IALPHA)
	{ "alpha",	ALPHA,		NEXT,		CHARSET	},
	{ "xalphas",	IMM,		NALPHAS,	xOPTIONAL},
END

/*
SEQ(SEARCH1)
	{ "search",	IMM,		XALPHAS,	},
	{ "search",	"+",		SEARCH,		xOPTIONAL},
END
SEQ(SEARCH)
	{ "search",	IMM,		SEARCH1,	xOPTIONAL},
END
*/
SEQ(URICS)
	{ "uric",	URIC,		NEXT,		CHARSET},
	{ "uric",	IMM,		URICS,		xOPTIONAL},
END
SEQ(SEARCH)
	{ "search",	IMM,		URICS,		xOPTIONAL},
END

SEQ(ALPHAS)
	{ "alpha",	ALPHA,		NEXT,		CHARSET},
	{ "alpha",	IMM,		ALPHAS,		xOPTIONAL},
END
SEQ(ALNUMS)
	{ "alnum",	ALNUM,		NEXT,		CHARSET},
	{ "alnum",	IMM,		ALNUMS,		xOPTIONAL},
END
SEQ(NALPHAS)
	{ "nalpha",	NALPHA,		NEXT,		CHARSET},
	{ "nalpha",	IMM,		NALPHAS,	xOPTIONAL},
END
SEQ(XALPHAS)
	{ "xalpha",	XALPHA,		NEXT,		CHARSET},
	{ "xalpha",	IMM,		XALPHAS,	xOPTIONAL},
END
SEQ(YALPHAS)
	{ "yalpha",	YALPHA,		NEXT,		CHARSET},
	{ "yalpha",	IMM,		YALPHAS,	xOPTIONAL},
END

SEQ(PATH1)
	{ "name",	IMM,		YALPHAS,	xOPTIONAL},
	{ "dir",	"/",		PATH,		xOPTIONAL},
END

ALT(PATH)
	{ "path",	IMM,		PATH1		},
	{ "nullpath",	IMM,		SUCCESS		},
END


SEQ(USERPASS)
	{ "user",	IMM,		XALPHAS,	PUTVAL},
	{ "pass",	":",		XALPHAS,	xOPTIONAL|PUTVAL},
	{ "@",		"@",		SUCCESS		},
END
SEQ(LOGIN)
	{ "userpass",	IMM,		USERPASS,	xOPTIONAL|PUTVAL},
	{ "hostport",	IMM,		HOSTPORT,	PUTVAL},
END
SEQ(FTP)
	{ "login",	"://",		LOGIN,		PUTVAL	},
	{ "path",	"/",		PATH,		xOPTIONAL|PUTVAL},
END

SEQ(FILEH)
/*
	{ "host",	IMM,		HOST,		xOPTIONAL|PUTVAL	},
*/
	{ "host",	IMM,		HOSTPORT,	xOPTIONAL|PUTVAL	},
	{ "path",	"/",		PATH,		xOPTIONAL|PUTVAL	},
END
ALT(FILEP)
	{ "file",	"://",		FILEH		},
	{ "path",	":",		PATH,		PUTVAL	},
END

ALT(GROUP1)
	{"name",	".",		GROUP1		},
	{"name",	IMM,		SUCCESS		},
END
SEQ(GROUPx)
	{"name",	IMM,		IALPHA		},
	{"name",	IMM,		GROUP1,		xOPTIONAL},
END
SEQ(ARTICLE)
	{"serial",	IMM,		XALPHAS		},
	{"domain",	"@",		HOST		},
END
ALT(GROUPART)
	{"group",	IMM,		GROUPx,		PUTVAL	},
	{"article",	IMM,		ARTICLE,	PUTVAL	},
END
SEQ(NEWS)
	{"groupart",	":",		GROUPART,	PUTVAL	},
END
SEQ(NNTP)
	{"hostport",	"://",		HOSTPORT,	PUTVAL	},
	{"group",	"/",		GROUPx,		PUTVAL	},
	{"search",	"?",		SEARCH,		xOPTIONAL|PUTVAL},
END

SEQ(DATABASE)
	{"database",	IMM,		XALPHAS,	},
END
SEQ(WAIS)
	{"hostport",	"://",		HOSTPORT,	PUTVAL	},
	{"database",	"/",		DATABASE,	PUTVAL	},
	{"search",	"?",		SEARCH,		xOPTIONAL|PUTVAL},
END
SEQ(DATAS)
	{"typemaj",	":",		SUCCESS,	},
END


ALT(SELECTOR)
	{ "selector",	IMM,		PATH,		},
END

ALT(GTYPE)
	{ "gtype",	DIGIT,		SUCCESS,	CHARSET},
	{ "nullgtype",	IMM,		SUCCESS		},
END

SEQ(GSELECTOR)
	{ "gtype",	IMM,		GTYPE,		PUTVAL},
	{ "selector",	IMM,		SELECTOR,	xOPTIONAL|PUTVAL},
END

SEQ(GOPHER)
	{ "//",		"://",		NEXT		},
	{ "hostport",	IMM,		HOSTPORT,	PUTVAL},
	{ "path",	"/",		GSELECTOR,	xOPTIONAL|PUTVAL},
	{ "search",	"?",		SEARCH,		xOPTIONAL|PUTVAL},
END


ALT(DIGITS1)
	{ "digit",	DIGIT,		DIGITS1,	CHARSET	},
	{ "nondigit",	IMM,		SUCCESS		},
END
ALT(DIGITS)
	{ "digit",	DIGIT,		DIGITS1,	CHARSET	},
END

/*
 *
 */
SEQ(FLAGS1)
	{ "flags",	"=",		ALPHAS,		},
	{ "eoflags",	"=",		SUCCESS		},
END
SEQ(FLAGS2)
	{ "flags",	"+",		ALPHAS,		},
	{ "eoflags",	"=",		SUCCESS		},
END
SEQ(FLAGS3)
	{ "flags",	"(",		ALPHAS,		},
	{ "eoflags",	")",		SUCCESS		},
END
SEQ(FLAGS4)
	{ "flags",	"@",		ALPHAS,		},
	{ "eoflags",	"@",		SUCCESS		},
END
ALT(FLAGS)
	{ "f1",		IMM,		FLAGS1		},
	{ "f2",		IMM,		FLAGS2		},
	{ "f3",		IMM,		FLAGS3		},
	{ "f4",		IMM,		FLAGS4		},
END
SEQ(URLX)
	{ "xflags",	IMM,		FLAGS,		PUTVAL|xOPTIONAL},
	{ "xproto",	IMM,		ALPHAS,		PUTVAL|xOPTIONAL},
	{ "xhostport",	":",		HOSTPORT,	PUTVAL},
	{ "xgtype",	"=",		DIGITS,		PUTVAL|xOPTIONAL},
END

/*
ISRULE(ROUTE);
ISRULE(HOSTLIST);

SEQ(ROUTE)
	{ "proto",	IMM,		ALPHAS,		PUTVAL},
	{ "host",	"://"		HOST,		PURVAL},
	{ "port",	":"		PORT,		PURVAL},
	{ "dstlist",	":"		HOSTLIST,	PURVAL},
	{ "dstlist",	":"		HOSTLIST,	PURVAL|xOPTIONAL},
END

SEQ(HOSTLIST)
	{ "host",	IMM,		HOST,
END
*/
