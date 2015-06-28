/*////////////////////////////////////////////////////////////////////////
Copyright (c) National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	htfilter.c (HTML filter)
Author:		Yutaka Sato <y.sato@aist.go.jp>
Description:
History:
	941009	extracted from http.c
	140928	extracted from httpd.c
//////////////////////////////////////////////////////////////////////#*/
#include <ctype.h>
#include "delegate.h"
#include "http.h"

void setPartfilter(Connection *Conn,PCStr(query))
{
	if( query ){
		FStrncpy(Conn->dg_putpart,query);
		sv1log("#### PART Filter [%s]\n",Conn->dg_putpart);
	}else	Conn->dg_putpart[0] = 0;
}
void clearPartfilter(Partf *Pf)
{
	Pf->p_Nput = 0;
	Pf->p_NumParts = 0;
	Pf->p_Isin = 0;
	Pf->p_IsinTag = 0;
	Pf->p_Incomment = 0;
	Pf->p_Type[0] = 0;
	Pf->p_Asis = 0;
	Pf->p_Indexing = 0;
	Pf->p_BaseSet = 0;
	Pf->p_Base[0] = 0;
	Pf->p_Title[0] = 0;
	Pf->p_Meta[0] = 0;
}
static void getTitle(PCStr(lp),PVStr(title),int size)
{	const char *tp;
	CStr(tbuff,256);

	setVStrEnd(title,0);
	wordscanY(lp,AVStr(tbuff),sizeof(tbuff),"^>");
	if( tp = strcasestr(tbuff,"TITLE=") ){
		valuescanX(tp+6,AVStr(title),size);
	}
}

/* v9.9.11 new-140724h */
/* v9.9.11 new-140724i, in <!-- comment --> */
const char *findTag(PCStr(html),PCStr(tag),int *inComment){
	const char *hp = html;
	const char *ep;
	const char *found = 0;
	int tlen = strlen(tag);

	if( *inComment ){
		if( ep = strstr(hp,"-->") ){
			Verbose("--incomment findTag[%s] found EOC\n",tag);
			*inComment = 0;
			hp = ep + 3;
		}else{
			Verbose("--incomment findTag[%s] not found EOC\n",tag);
			return 0;
		}
	}
	for( ; *hp; hp++ ){
		if( *hp == '<' ){
			if( strneq(hp,"<!--",4) ){
				if( strncaseeq(hp+4,"<nostrip/>",10) ){
					Verbose("--incoment findTag[%s] <nostrip/>\n",tag);
				}else
				if( ep = strstr(hp+4,"-->") ){
					hp = ep + 3;
					Verbose("--incoment findTag[%s] found paired EOC\n",tag);
				}else{
					*inComment = 1;
					Verbose("--incoment findTag[%s] found dangling comment\n%s\n",tag,hp);
					break;
				}
			}else
			if( strncaseeq(hp,tag,tlen) ){
				if( strtailchr(tag) == '='
				 || strchr("> \r\n",hp[tlen]) != 0
				){
					found = hp;
					break;
				}
			}
		}
	}
	return found;
}

/* v9.9.12 new-140927b, hyper-link generation */
static int isPreNAME(int pch,PCStr(str)){
	IStr(line,1024);

	lineScan(str,line);

	if( pch == -1
	 || isspace(pch)
	 || pch == '>'
	 || pch == '('
	 || pch == ','
	){
		return 1;
	}else{
		return 0;
	}
}
static int isPostNAME(int nch,PCStr(str)){
	IStr(line,1024);

	lineScan(str,line);

	if( nch == -1
	 || isspace(nch)
	 || nch == '<' && str[1] == '/' && (str[2] == 'K' || str[2] == 'I')
	 || nch == '=' /* canbe an attribute in a tag */
	 || nch == ','
	 || nch == '.'
	 || nch == ')'
	){
		return 1;
	}else{
		return 0;
	}
}
static int tobeLinked(Partf *Pf,PCStr(str),int pch,int minleng,PVStr(target)){
	int ch;
	const char *sp = str;
	refQStr(tp,target);

	for( sp = str; ch = *sp; sp++ ){
		if( 16 <= sp - str ){
			break;
		}
		if( ch == '_' || isupper(ch) ){
			setVStrPtrInc(tp,ch);
		}else{
			break;
		}
	}
	setVStrEnd(tp,0);
	if( isinList(Pf->p_NoHrefGen,target) ){
		return 0;
	}

	if( minleng <= (tp - target) ){
		if( isPostNAME(ch,sp) ){
			return (tp - target);
		}
	}
	return 0;
}
static void addNoHrefGen(Partf *Pf,PCStr(html)){
	const char *lp;
	const char *np;
	IStr(line,1024);
	IStr(nohgenlist,1024);
	refQStr(gp,nohgenlist);

	for( lp = html; *lp; lp = np ){
		lineScan(lp,line);
		if( strncaseeq(line,"</no",4) ){
			break;
		}
		if( strncaseeq(line,"<no",3) ){
			goto NEXT;
		}
		if( nohgenlist < gp ){
			setVStrPtrInc(gp,',');
		}
		strcpy(gp,line);
		gp += strlen(gp);

NEXT:
		if( np = strpbrk(lp,"\r\n") ){
			while( *np == '\r' || *np == '\n' )
				np++;
		}else{
			break;
		}
	}
	if( Pf->p_NoHrefGen[0] != 0 )
		strcat(Pf->p_NoHrefGen,",");
	strcat(Pf->p_NoHrefGen,nohgenlist);
}

int Partfilter(Connection *Conn,Partf *Pf,PVStr(line),int size)
{	refQStr(lp,line); /**/
	const char *dp;
	const char *tag;
	refQStr(attr,line); /**/
	CStr(name,32);
	CStr(buff,0x10000);
	refQStr(tail,buff); /**/
	CStr(type,256);
	CStr(title,256);
	CStr(indent,32);
	const char *mark;
	int aname = 0;			/* <A NAME=name> part is found */
	const char *stylebegin = 0;	/* <STYLE ...> is found */
	const char *styleend = 0;	/* </STILE> is found */
	IStr(styleb,0x10000); /* saved STYLE when <A NAME> is found too */
	IStr(header,0x10000); /* saved header for .skeleton and .index */
	IStr(dgsign,1024);		/* <!-- generated ... -> */
	int cm0 = Pf->p_Incomment;
	int cm1 = Pf->p_Incomment;
	int cm2 = Pf->p_Incomment;
	int notempty = 0;	/* there was someting not comment */
	int pch = -1;
	IStr(target,32);

	if( strncmp(ProxyControls,"partname=",9) == 0 )
		mark = "?_?partname=";
	else	mark = "?";

	if( dp = strcasestr(line,"<TITLE>") ){
		wordscanY(dp+7,AVStr(Pf->p_Title),128,"^<");
	}
	title[0] = 0;

	if( dp = strcasestr(line,"<nohrefgen>") ){
		addNoHrefGen(Pf,dp);
	}

	if( Pf->p_Isin == 0 ){
		if( streq(Conn->dg_putpart,".whole") ){ /* v9.9.11 new-140728j */
			Pf->p_NumParts++;
			Pf->p_Isin = 20;
		}
	}
	if( Pf->p_Isin == 0 ){
		cpyQStr(lp,line);

		if( Pf->p_BaseSet == 0 ){ /* v9.9.11 new-140730d */
			const char *mp = line;
			IStr(metab,1024);
			while( tag = findTag(mp,"<META",&cm0) ){
				if( mp = strchr(tag,'>') ){
					QStrncpy(metab,tag,mp-tag+2);
					if( sizeof(Pf->p_Meta)-2 <
						strlen(Pf->p_Meta)+strlen(metab) ){
						break;
					}
					Xsprintf(TVStr(Pf->p_Meta),"%s\r\n",metab);
					mp++;
				}else{
					break;
				}
			}
		}
		/* v9.9.11 new-140724h */
		if( stylebegin = findTag(lp,"<STYLE",&cm1) ){
		  Pf->p_IsinTag = 1;
		  if( styleend = findTag(stylebegin,"</STYLE",&cm1) ){
		    if( styleend = strchr(styleend,'>') ){
			styleend++;
			if( *styleend == '\r' ) styleend++;
			if( *styleend == '\n' ) styleend++;
			  QStrncpy(styleb,stylebegin,styleend-stylebegin+1);
			  Pf->p_IsinTag = 0;
		    }
		  }
		}

		if( streq(Conn->dg_putpart,".parts") ){
			Pf->p_NumParts++;
			Pf->p_Isin = 100;
			/* convert .html#name to .html?name */
		}else
		if( streq(Conn->dg_putpart,".skeleton")
		 || streq(Conn->dg_putpart,".index") ){
			Pf->p_NumParts++;
			Pf->p_Isin = 10;
			Pf->p_Indexing = 1;
		}else
	    {
		while( tag = findTag(lp,"<A NAME=",&cm2) ){
			/*
		while( tag = strcasestr(lp,"<A NAME=") ){
			}
			getTitle(tag,AVStr(title),sizeof(title));
			*/
			attr = (char*)tag + strlen("<A NAME=");
			valuescanX(attr,AVStr(name),sizeof(name));

			if( streq(name,Conn->dg_putpart) ){
				Pf->p_NumParts++;
				aname = 1;
				getTitle(tag,AVStr(title),sizeof(title));
				wordscanY(tag,AVStr(type),sizeof(type),"^>");
				if( strcasestr(type,"TYPE=HIDDEN") ){
					Pf->p_Asis = 1;
				}

				if( lp = strchr(tag,'>') )
					ovstrcpy((char*)line,lp+1);
				else	ovstrcpy((char*)line,tag);
				Pf->p_Isin = 1;
				break;
			}
			lp = attr;
		}

		if( aname != 0 && stylebegin != 0 ){
			sv1log("--PF found both style and aname\n");
		}else
		if( aname != 0 && stylebegin == 0 ){
			sv1log("--PF found aname only\n");
		}else
		if( aname == 0 && stylebegin != 0 ){
			sv1log("--PF found style only\n");
			styleb[0] = 0;
			ovstrcpy((char*)line,stylebegin);
			Pf->p_Isin = 1;
		}
	    }
		if( Pf->p_Incomment != cm2 ){
			sv1log("--PF (%d) incomment = %d -> %d\n",Pf->p_Isin,
				Pf->p_Incomment,cm2);
			Pf->p_Incomment = cm2;
		}
	}

	if( Pf->p_Isin == 0 )
		return 0;

	if( aname != 0 || 10 <= Pf->p_Isin )
	if( Pf->p_BaseSet == 0 ){
	    IStr(all,1024);
	    Pf->p_BaseSet = 1;
	    if( Conn->rq_vbase.u_proto ){ /* v9.9.11 new-140809g vbase=URL in SSI include */
		sprintf(Pf->p_Base,"/%s",Conn->rq_vbase.u_path);
	    }else{
		wordScan(REQ_URL,Pf->p_Base);
		if( dp = strchr(Pf->p_Base,'?') )
			truncVStr(dp);
		if( dp = strrchr(Pf->p_Base,'/') )
			ovstrcpy(Pf->p_Base,dp+1);
	    }

	    if( streq(Conn->dg_putpart,".whole") ){
		sv1log("--PF .whole, don't add header\n");
	    }else{
		sv1log("#### Base: %s\n",Pf->p_Base);
		if( Pf->p_Isin < 100 ){
		    sprintf(all,"<Title>%s / %s</Title>\r\n",Pf->p_Title,
			title[0]?title:Conn->dg_putpart);
		    if( !Pf->p_Asis ){
		      Xsprintf(TVStr(all),"<Div id=HtmlBody>\r\n");
		      if( Pf->p_Isin < 10 ){
			Xsprintf(TVStr(all),"<Noindex>\r\n");
			Xsprintf(TVStr(all),"<A Href=\"%s#%s\">[CTX]</A>\r\n",
				Pf->p_Base,Conn->dg_putpart);
			Xsprintf(TVStr(all),"<A Href=\"%s%s%s#%s\">[ALL]</A>\r\n",
				Pf->p_Base,mark,".whole",Conn->dg_putpart);
			Xsprintf(TVStr(all),"</Noindex>\r\n");
			Xsprintf(TVStr(all),"%s\r\n",title[0]?title:"");
			Xsprintf(TVStr(all),"<Hr>\r\n");
		      }
		     Verbose("####\n%s\n",all);
		   }
		   Strins(AVStr(line),all);
		   Strins(AVStr(line),Pf->p_Meta);
		   strcpy(header,all);
		   Strins(AVStr(header),Pf->p_Meta);
		}
	    }
	}

	if( Pf->p_Nput == 0 ){
		sprintf(dgsign,"<!-- generated by HTML Partfilter of DeleGate/%s -->\r\n",
			DELEGATE_ver());
	}
	Pf->p_Nput++;

	tail = buff;
	buff[0] = 0;
	pch = -1;
	for( cpyQStr(lp,line); *lp; lp++ ){
		if( strneq(lp,"<!--",4) ){
			Pf->p_Incomment = 1;
			continue;
		}
		if( strneq(lp,"-->",3) ){
			Verbose("--PF incomment found EOC in scanning\n");
			Pf->p_Incomment = 0;
			continue;
		}
		if( Pf->p_Incomment ){
			continue;
		}
		notempty = 1;
		if( strncaseeq(lp,"<A ",3) ){
		    Pf->p_Isin++;

		    if( strncaseeq(lp,"<A NAME=",8) ){
			getTitle(lp,AVStr(title),sizeof(title));
			attr = (char*)lp + strlen("<A NAME=");
			valuescanX(attr,AVStr(name),sizeof(name));

			if( Pf->p_Indexing ){
			    Pf->p_NumParts++;
			    wordscanY(lp,AVStr(type),sizeof(type),"^>");
			    if( strcasestr(type,"TYPE=HIDDEN") ){
			    }else{
				if( 12 < Pf->p_Isin )
					sprintf(indent," ...... ");
				else
				if( 11 < Pf->p_Isin )
					sprintf(indent," ... ");
				else	indent[0] = 0;
				sprintf(tail,
"<Li>%s<A Href=\"%s%s%s\">%s</A>\r\n",
indent,Pf->p_Base,mark,name,title[0]?title:name);
				tail += strlen(tail);
			    }
			}else
			if( 100 <= Pf->p_Isin ){
				sprintf(tail,
"<Br><Div Style=\"background-color:#e0e0e0;\">\
&nbsp;<A Href=\"%s%s%s\">%s</A></Div>\r\n",
Pf->p_Base,mark,name,title[0]?title:name);
				Strins(AVStr(lp),tail);
				//lp += strlen(tail) + 1;
				lp += strlen(tail);
				truncVStr(tail);
				//continue; /* the A NAME tag is skipped bellow */
			}
		    }
                    else
		    if( strncaseeq(lp,"<A HREF=",8) ){
				tag = lp;
				attr = (char*)tag + strlen("<A HREF=");
				if( *attr == '"' )
					attr++;
				if( *attr == '#' ){
					setVStrElem(attr,0,'?');
					Strins(AVStr(attr),Pf->p_Base);
				}
				Pf->p_IsinTag++;
		    }
		}else
		if( strncaseeq(lp,"</A>",4) ){
			Pf->p_Isin--;
			if( 0 < Pf->p_IsinTag ){
				Pf->p_IsinTag--;
			}
			if( Pf->p_Isin <= 0  ){
				Pf->p_Isin = 0;
				if( Pf->p_Asis )
					strcpy(lp,"\r\n");
				else	strcpy(lp,"\r\n<Hr>\r\n");
				Xsprintf(TVStr(lp),"</Div>\r\n");
				break;
			}
		}
		else
		if( strncaseeq(lp,"</STYLE",7) ){ /* v9.9.11 new-140724h */
			if( strchr("> \t\r\n",lp[7]) == 0 )
				continue;

			if( 0 < Pf->p_IsinTag ){
				Pf->p_IsinTag--;
			}
			Pf->p_Isin--;
			if( 0 < Pf->p_Isin ){
				continue;
			}
			if( lp = strchr(lp,'>') )
				lp++;
			else	lp += strlen(lp);
			if( *lp == '\r' ) lp++;
			if( *lp == '\n' ) lp++;

			if( tag = findTag(lp,"<STYLE",&Pf->p_Incomment) ){
				ovstrcpy((char*)lp,tag);
				Pf->p_Isin++;
				Pf->p_IsinTag++;
			}else
			if( Pf->p_Incomment ){
				break;
			}else{
				strcpy(lp,"\r\n");
				Pf->p_Isin = 0;
				break;
			}
		}
		else
		if( Pf->p_IsinTag <= 0
		/* && is not in .whole */
		 && isupper(*lp)
		 && isPreNAME(pch,lp)
		 && tobeLinked(Pf,lp,pch,3,AVStr(target))
		)/* v9.9.12 new-140927b, generating hyper-link  */
		{
			IStr(anc,128);
			sprintf(anc,"<A Href=%s?%s id=hgen>",Pf->p_Base,target);
			Strins(AVStr(lp),anc);
			lp += strlen(anc);
			lp += strlen(target);
			Strins(AVStr(lp),"</A>");
			lp += 4;
			pch = '>';
			continue;
		}

		/* v9.9.12 new-140927b, suppress hyper-link generation in tag attributes */
		if( *lp == '<' ){
			for( ; *lp !=0; lp++){
				if( *lp == '>' ){
					break;
				}
			}
		}
		pch = *lp;
	}

	if( notempty == 0 && styleb[0] == 0 ){
		return 0;
	}
	if( Pf->p_Indexing )
	{
		strcpy(line,buff);
		if( header[0] )
			Strins(AVStr(line),header);
	}
	if( styleb[0] )
		Strins(AVStr(line),styleb);
	if( Pf->p_Meta[0] ){
		Strins(AVStr(line),Pf->p_Meta);
		setVStrEnd(Pf->p_Meta,0);
	}
	if( dgsign[0] )
		Strins(AVStr(line),dgsign);

	return 1;
}
