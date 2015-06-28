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
Program:	urlesc.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950421	extracted from url.c
//////////////////////////////////////////////////////////////////////#*/
#include <ctype.h>
#include <stdio.h>
#include "ystring.h"

#define ishex(ch)	(ch && strchr("0123456789abcdefABCDEF",ch))

void unescape_specials(PCStr(str),PCStr(set),PCStr(succ))
{	const char *ep;
	CStr(sx,3);
	int len,x;

	len = strlen(succ);
	if( ep = strchr(str,'%') ){
	    if( ishex(ep[1]) && ishex(ep[2]) && strncmp(&ep[3],succ,len)==0 ){
		sx[0] = ep[1];
		sx[1] = ep[2];
		sx[2] = 0;
		sscanf(sx,"%x",&x);
		if( strchr(set,x) ){
			((char*)ep)[0] = x; /**/
			ovstrcpy((char*)&ep[1],&ep[3]);
		}
	    }
	}
}
#define tonum(hc) (\
	('0' <= hc && hc <= '9')?(hc - '0') : \
	('a' <= hc && hc <= 'f')?(hc - 'a') + 10 : \
	('A' <= hc && hc <= 'F')?(hc - 'A') + 10 : -1)

int url_unescape(PVStr(url),PVStr(dst),int siz,PCStr(set))
{	const char *sp;
	refQStr(dp,url); /**/
	const char *xp = dst + siz - 1;
	char ch;
	unsigned char x1,x2;
	int unesc;
	int dch;

	unesc = 0;
	for( sp = url; ch = *sp; sp++ ){
		if( xp <= dp )
			break;
		x1 = sp[1];
		x2 = sp[2];
		if( ch == '%' && ishex(x1) && ishex(x2) ){
			/*
			*dp++ = (tonum(x1) << 4) | tonum(x2);
			*/
			dch = (tonum(x1) << 4) | tonum(x2);
			if( *set && !strchr(set,dch) ){
				if( dp != sp ){
					setVStrPtrInc(dp,'%');
					setVStrPtrInc(dp,x1);
					setVStrPtrInc(dp,x2);
				}else{
					dp += 3;
				}
			}else{
				setVStrPtrInc(dp,dch);
			}
			sp += 2;
			unesc++;
		}else{
			if( dp == sp )
				dp++;
			else	setVStrPtrInc(dp,ch);
		}
	}
	if( dp != sp )
		setVStrEnd(dp,0);
	return unesc;
}
int nonxalpha_unescape(PCStr(src),PVStr(dst),int spacealso)
{	char ch;
	const char *cp;
	CStr(sx,3);
	int num;
	int x;

	if( src != dst )
		strcpy(dst,src);

	num = 0;
	for( cp = dst; ch = *cp; cp++ )
		if( ch == '%' && ishex(cp[1]) && ishex(cp[2]) ){
			sx[0] = cp[1];
			sx[1] = cp[2];
			sx[2] = 0;
			sscanf(sx,"%x",&x);
			if( spacealso || !strchr(" \t\r\n",x) ){
				((char*)cp)[0] = x; /**/
				ovstrcpy((char*)&cp[1],&cp[3]);
				num++;
			}
		}
	return num;
}
int url_escapeY(PCStr(src),PVStr(dst),int siz,PCStr(escs),PCStr(sbrk))
{	const char *sp;
	char ch;
	refQStr(dp,dst); /**/
	int in2byte,nesc;
	int nodflt,escspc,escbin,eschtm,escdel;
	int escqpt; /* %= ... escape with =XX (quoted printable) */
	int escctl;
	int escurl = 0;
	const char *xp;
	CStr(buf,32);
	int len;

	nodflt = 0; /* turn ON when the url is already escaped */
	escctl = 0;
	escbin = 0;
	escspc = 0;
	eschtm = 0;
	escqpt = 0;
	escdel = 0;
	while( *escs == '%' ){
		if( escs[1] == '%' ){ nodflt = !nodflt; escs += 2; }else
		if( escs[1] == 'C' ){ escctl = 1; escs += 2; }else
		if( escs[1] == 'H' ){ escbin = 1; escs += 2; }else
		if( escs[1] == 'S' ){ escspc = 1; escs += 2; }else
		if( escs[1] == 'U' ){ escurl = 1; escs += 2; }else
		if( escs[1] == '&' ){ eschtm = 1; escs += 2; }else
		if( escs[1] == '=' ){ escqpt = 1; escs += 2; }else
		if( escs[1] == '#' ){ escdel = 1; escs += 2; }else
			break;
	}
	in2byte = 0;
	nesc = 0;
	dp = 0;
	xp = dst + (siz-1);

	for( sp = src; ch = *sp; sp++ ){
		if( sbrk && strchr(sbrk,ch) ){
			if( dp ){
				QStrncpy(dp,sp,xp-dp);
				dp += strlen(dp);
			}
			break;
		}
		if( dp != 0 && 0 < siz && siz-1 <= dp-dst ){
			goto OVERFLOW;
		}
		if( ch == 033 ){
			switch( sp[1] ){
				case '$': in2byte = 1; break;
				case '(': in2byte = 0; break;
			}
		}
		if( !nodflt && ((ch & 0x80) || iscntrl(ch) || ch == '%')
		 || escctl && iscntrl(ch)
		 || escbin && (ch & 0x80)
		 || escspc && isspace(ch)
		 || (in2byte == 0||escurl) && strchr(escs,ch) != 0
		/*
		 || in2byte == 0 && strchr(escs,ch) != 0
		*/
		){
			if( dp == 0 ){
				len = sp - src;
				if( siz <= len ){
					QStrncpy(dst,src,siz);
					goto OVERFLOW;
				}
				Bcopy(src,dst,len);
				dp = (char*)dst + len;
			}

			buf[0] = 0;
			if( escdel ){
				/* ignore the character */
			}else
			if( escqpt ){
				sprintf(buf,"=%02X",ch & 0xFF);
			}else
			if( eschtm ){
				if( ch == '"' )
					sprintf(buf,"%%26quot%%3B");
				else	sprintf(buf,"%%26%%23%d%%3B",ch & 0xFF);
			}else{
				sprintf(buf,"%%%02x",ch & 0xFF);
			}
			if( buf[0] ){
				len = strlen(buf);
				if( xp <= dp+len ){
					goto OVERFLOW;
				}
				strcpy(dp,buf);
				dp += len;
			}
			nesc++;
		}else{
			if( dp != 0 )
				setVStrPtrInc(dp,ch);
		}
	}
	if( dp != 0 && *dp != 0 )
		setVStrEnd(dp,0);

	return nesc;

OVERFLOW:
	if( dp && dp <= xp )
		setVStrEnd(dp,0);
	else	setVStrEnd(dst,siz-1);
	syslog_ERROR("## url_escapeX: buffer overrun(%d) %s\n",siz,dst);
	return nesc;
}
int url_escapeX(PCStr(src),PVStr(dst),int siz,PCStr(escs),PCStr(sbrk))
{	int nesc;
	defQStr(xdst); /*alt*/
	CStr(escaped,4*1024);

	if( src == dst ){
		setQStr(xdst,escaped,sizeof(escaped));
		if( sizeof(escaped) < siz )
			siz = sizeof(escaped);
		setVStrEnd(xdst,0);
	}else{
		setQStr(xdst,dst,(UTail(dst)-dst)+1);
	}
	nesc = url_escapeY(src,AVStr(xdst),siz,escs,sbrk);

	if( nesc == 0 && src != dst ){
		QStrncpy(dst,src,siz);
	}else
	if( nesc != 0 && src == dst ){
		strcpy(dst,escaped);
	}
	return nesc;
}

void logurl_escapeX(PCStr(src),PVStr(dst),int siz)
{
	url_escapeX(src,BVStr(dst),siz," \t\r\n%\"<>",(char*)0);
}
void nonxalpha_escapeX(PCStr(src),PVStr(dst),int siz)
{
	url_escapeX(src,BVStr(dst),siz," \t\n%?#",(char*)0);
}
void safe_escapeX(PCStr(src),PVStr(dst),int siz)
{
	url_escapeX(src,BVStr(dst),siz," \t\n\"#%&'/<>?",(char*)0);
}

int h2toi(PCStr(h2))
{	CStr(hb,3);
	int i = -1;

	if( ishex(h2[0]) && ishex(h2[1]) ){
		hb[0] = h2[0]; hb[1] = h2[1]; hb[2] = 0;
		sscanf(hb,"%x",&i);
	}
	return i;
}
int url_strstrX(PCStr(url),PCStr(pat),int nocase)
{	int plen,ulen,pch,uch,xuch,xpch;

	ulen = 0;
	for( plen = 0; pch = pat[plen]; plen++ ){
		uch = url[ulen++];
		if( uch == pch && uch != '%' )
			continue;
		if( uch != '%' && nocase ){
			int nuch,npch;
			nuch = isupper(uch) ? tolower(uch) : uch;
			npch = isupper(pch) ? tolower(pch) : pch;
			if( nuch == npch )
				continue;
		}
		if( uch == '%' ){
			xuch = h2toi(url+ulen);
			if( xuch == pch ){
				ulen += 2;
				continue;
			}
		}
		if( pch == '%' ){
			xpch = h2toi(pat+plen+1);
			if( xpch == uch ){
				plen += 2;
				continue;
			}
		}
		if( uch == '%' && pch == '%' ){
			if( xuch == xpch ){
				ulen += 2;
				plen += 2;
				continue;
			}
		}
		break;
	}
	if( pch == 0 )
		return ulen;
	else	return 0;
}

#define isRESERVED(ch)	(strchr(":/@.?&=+#",ch)!=0)
/*
#define isHEX(c) ('0'<=c&&c<='9'  || 'A'<=c&&c<='Z'|| 'a'<=c&&c<='z')
*/
#define isHEX(c) ('0'<=c&&c<='9'  || 'A'<=c&&c<='F'|| 'a'<=c&&c<='f')
static int dec2X(unsigned PCStr(str)){
	if( isHEX(str[0]) && isHEX(str[1]) ){
		char xbuf[3];
		int ch;
		xbuf[0] = str[0];
		xbuf[1] = str[1];
		xbuf[2] = 0;
		sscanf(xbuf,"%x",&ch);
		return ch;
	}else{
		return -1;
	}
}
static int set2B(PCStr(src),PCStr(sp),int in2byte){
	if( src+3 <= sp ){
		if( sp[-3] == 033 )
		switch( sp[-2] ){
			case '$': in2byte = 1; break;
			case '(': in2byte = 0; break;
		}
	}
	return in2byte;
}
/*
 * if "escrsvd" is ON, then reserved characters are escaped with %XX
 * to be restored in URL_reescape()
 */
int URL_unescape(PCStr(src),PVStr(dst),int isform,int escrsvd){
	int nesc = 0;
	const unsigned char *sp;
	refQStr(dp,dst);
	int ch;
	int in2byte = 0;
	int out2byte = 0;

	for( sp = (const unsigned char*)src; ch = *sp; sp++ ){
		in2byte = set2B(src,(char*)sp,in2byte);
		out2byte = set2B(dst,(char*)dp,out2byte);

/*
  if( 3 <= dp-dst ) fprintf(stderr,
  "--URLunesc %d %d out[%2X %2X %2X] in[%2X %2X %2X][%2X %2X %2X] %2X %c\n",
    in2byte,out2byte,
    0xFF&dp[-3],0xFF&dp[-2],0xFF&dp[-1],
    0xFF&sp[-3],0xFF&sp[-2],0xFF&sp[-1],
    0xFF&sp[ 0],0xFF&sp[ 1],0xFF&sp[ 2],
    ch,ch);
*/

		if( in2byte ){
		}else
		if( ch == '%' && isHEX(sp[1]) && isHEX(sp[2]) ){
			ch = dec2X(sp+1);
			if( escrsvd && ch == '%' ){
				/* 9.8.4 thru original "%25" in ASCII */
				setVStrPtrInc(dp,ch);
				continue;
			}
			nesc++;
			sp += 2;
		}
		else
		if( out2byte ){
			/* ESC seq. might be esacped with %XX in the URL
			 * while reserved character in 2Bytes of JIS is not
			 * escaped. (ex. 0x222E by "%1B%24%42%22.%1B ...")
			 * It must not be escaped with %XX as RESERVED.
			 */
		}else
		if( escrsvd && (ch == '%' || isRESERVED(ch)) ){
			sprintf(dp,"%%%02X",ch);
			dp += 3;
			nesc++;
			continue;
		}else
		if( !escrsvd && ch == '+' && isform ){
			ch = ' ';
			nesc++;
		}
		setVStrPtrInc(dp,ch);
	}
	setVStrEnd(dp,0);
	return nesc;
}
int URL_reescape(PCStr(src),PVStr(dst),int isform,int rstrsvd){
	int nesc = 0;
	const unsigned char *sp;
	refQStr(dp,dst);
	unsigned char ch;
	int in2byte = 0;
	for( sp = (const unsigned char*)src; ch = *sp; sp++ ){
		in2byte = set2B(src,(char*)sp,in2byte);
		if( !in2byte )
		if( rstrsvd && ch == '%' && isHEX(sp[1]) && isHEX(sp[2]) ){
			int xch;
			xch = dec2X(sp+1);
			if( isRESERVED(xch) ){
				setVStrPtrInc(dp,xch);
				sp += 2;
				continue;
			}
			if( rstrsvd && xch == '%' ){
				/* 9.8.4 thru original "%25" in ASCII */
				setVStrPtrInc(dp,ch);
				continue;
			}
		}
		/* even if the ch is reserved, if it was not esaped to
		 * %XX in the original URL like above, maybe it is a part
		 * of multi-byte character generated by code-conversion
		 */
		if( !rstrsvd && !in2byte && isRESERVED(ch) ){
			setVStrPtrInc(dp,ch);
		}else
		if( isalnum(ch) || ch == '_' || ch == '-' ){
			setVStrPtrInc(dp,ch);
		}else
		if( !rstrsvd && !in2byte && ch == ' ' && isform ){
			setVStrPtrInc(dp,'+');
			nesc++;
		}else{
			sprintf(dp,"%%%02X",ch);
			nesc++;
			dp += 3;
		}
	}
	setVStrEnd(dp,0);
	return nesc;
}
int URL_unescape2B(PCStr(src),PVStr(dst)){
	int nesc = 0;
	const unsigned char *sp;
	refQStr(dp,dst);
	int ch;
	int xch;
	int in2byte = 0;
	int out2byte = 0;

	for( sp = (const unsigned char*)src; ch = *sp; sp++ ){
		if( ch == '%' && isHEX(sp[1]) && isHEX(sp[2]) ){
			xch = dec2X(sp+1);
			if( xch & 0x80 ){
				setVStrPtrInc(dp,xch);
				sp += 2;
				continue;
			}
		}
		setVStrPtrInc(dp,ch);
	}
	setVStrEnd(dp,0);
	return nesc;
}
int URL_escape2B(PCStr(src),PVStr(dst)){
	int nesc = 0;
	const unsigned char *sp;
	refQStr(dp,dst);
	unsigned char ch;
	int in2byte = 0;
	for( sp = (const unsigned char*)src; ch = *sp; sp++ ){
		if( ch & 0x80 ){
			sprintf(dp,"%%%02X",ch);
			nesc++;
			dp += 3;
		}else{
			setVStrPtrInc(dp,ch);
		}
	}
	setVStrEnd(dp,0);
	return nesc;
}
int urlescape_main(int ac,const char *av[]){
	CStr(line,1024);
	CStr(xline,1024);
	while( fgets(line,sizeof(line),stdin) != NULL ){
		URL_reescape(line,AVStr(xline),1,0);
		fputs(xline,stdout);
	}
	return 0;
}
int urlunescape_main(int ac,const char *av[]){
	CStr(line,1024);
	CStr(xline,1024);
	while( fgets(line,sizeof(line),stdin) != NULL ){
		URL_unescape(line,AVStr(xline),1,0);
		fputs(xline,stdout);
	}
	return 0;
}
