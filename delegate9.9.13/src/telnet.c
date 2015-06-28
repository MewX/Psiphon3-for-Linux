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
Program:	telnet.c (telnet proxy)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	940304	created
//////////////////////////////////////////////////////////////////////#*/
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include "ystring.h"
#include "vsignal.h"
#include "delegate.h"
#include "fpoll.h"
#include "auth.h"
#include "proc.h"

extern int IO_TIMEOUT;

int connectToSsh(Connection *Conn,const char *host,int port,PCStr(user),PCStr(pass));
int makeXproxy(Connection *Conn,PVStr(pxdisplay),PCStr(display),PVStr(pxhost),PCStr(relhost),PCStr(me),int timeo);
extern int *ccx_global;

static int ccx_telnet(int*ccx,PVStr(buf),int *ip,int cc);
static int rewriteTelnet(int direction,PVStr(buf),int cc);
static void putIAC(FILE *tc,int com,int what);

typedef struct {
	MStr(	te_Xdisplay,MaxHostNameLen);
	MStr(	te_Xproxy,MaxHostNameLen);
	int	te_Xpid;
	int	te_THREAD;
	int	te_THREAD_exiting;
  const char   *te_useTHREAD;
	int	te_env_valid;
	jmp_buf te_tel_env;
	int	te_gotSIGURG;
	int	te_dump_commands;
	int	te_ClientsWill[128];
	int	te_ServersWill[128];
	int	te_ClientsDO[256];
	int	te_docontrol;
	MStr(	te__opt,8);
	int	te_keepalive;
	MStr(	te_ccxbTOCL,64);
	MStr(	te_ccxbTOSV,64);
	CCXP	te_ccxTOCL;
	CCXP	te_ccxTOSV;
} TelnetEnv;
static TelnetEnv *telnetEnv;
#define Xdisplay	telnetEnv->te_Xdisplay
/**/
#define Xproxy		telnetEnv->te_Xproxy
/**/
#define Xpid		telnetEnv->te_Xpid
#define THREAD		telnetEnv->te_THREAD
#define THREAD_exiting	telnetEnv->te_THREAD_exiting
#define useTHREAD	telnetEnv->te_useTHREAD
#define env_valid	telnetEnv->te_env_valid
#define tel_env		telnetEnv->te_tel_env
#define gotSIGURG	telnetEnv->te_gotSIGURG
#define dump_commands	telnetEnv->te_dump_commands
#define ClientsWill	telnetEnv->te_ClientsWill
#define ServersWill	telnetEnv->te_ServersWill
#define ClientsDO	telnetEnv->te_ClientsDO
#define docontrol	telnetEnv->te_docontrol
#define _opt		telnetEnv->te__opt
/**/
#define keepalive	telnetEnv->te_keepalive
#define ccxTOCL		telnetEnv->te_ccxTOCL
#define ccxTOSV		telnetEnv->te_ccxTOSV
#define ccxbTOCL	telnetEnv->te_ccxbTOCL
#define ccxbTOSV	telnetEnv->te_ccxbTOSV

void scan_TELNETCONF(Connection*_,PCStr(conf))
{	CStr(what,32);
	CStr(value,64);
	int ival;

	if( telnetEnv == 0 )
		telnetEnv = NewStruct(TelnetEnv);

	fieldScan(conf,what,value);
	ival = atoi(value);
	if( strcaseeq(what,"keepalive") ){
		if( ival == 0 )
			ival = 30;
		keepalive = ival;
	}
}

static int guessedHalfdup = -1;

static void sigPIPE(int sig){
	signal(SIGPIPE,SIG_IGN);
	if( env_valid ){
		env_valid = 0;
		if( !THREAD ) longjmp(tel_env,SIGPIPE);
	}
}
static void sigTERM(int sig){
	signal(SIGTERM,SIG_IGN);
	if( env_valid ){
		env_valid = 0;
		if( !THREAD ) longjmp(tel_env,SIGTERM);
	}
}

#define CtoS	1	/* client to server */
#define StoC	2	/* server to client */
#define CtoD	3	/* client to delegate */
#define DtoS	4	/* delegate to server */
#define DtoC	5	/* delegate to client */

#define SE	240
#define NOP	241
#define IP	244	/* Interrupt Process */
#define EC	247
#define EL	248
#define SB	250
#define WILL	251
#define WONT	252
#define DO	253
#define DONT	254
#define IAC	255

#define SYNCH	242
			/* DM DataMark */

#define IS	0
#define VAR	0
#define VALUE	1

#define O_ECHO		 1
#define O_SUPAHEAD	 3	/* Suppress Go Ahead */
#define O_STATUS	 5	/* Give Status */
#define O_TM		 6	/* Timing-Mark */
#define O_NAOL		 8	/* Negotiate About Output Line width */
#define O_NAOP		 9	/* Negotiate About Output Page size */
#define O_TERMTYPE	24	/* Teminal Type */
#define O_NAWS		31	/* Negotiate About Window Size */
#define O_TSPEED	32	/* Terminal Speed */
#define O_LFLOW		33	/* Remote Flow Control */
#define O_XDISPLOC	35	/* X Display Location */
#define O_ENVIRON	36	/* Environment Variables */
#define O_AUTH		37	/* Authentication */
#define O_NENVIRON	39	/* New Environment Option RFC1572 */

static char NOPstr[2] = { IAC, NOP };

static void sigurg(int sig)
{	const char *ssig;

	signal(SIGURG,sigurg);
	gotSIGURG += 1;
	if( sig == SIGURG ) ssig = "URG"; else
	if( sig == SIGIO  ) ssig = "IO"; else
			    ssig = "??";
	sv1log("got SIG%s (%d)\n",ssig,gotSIGURG);
}

/*
#include <sys/sockio.h>
setRecvSIGURG(sock)
{	int pgrp;

	signal(SIGURG,sigurg);
	pgrp = getpid();
	ioctl(sock,SIOCSPGRP,&pgrp);
	ioctl(sock,SIOCGPGRP,&pgrp);
	sv1log("set receive SIGURG [%d] %d\n",sock,pgrp);
}
*/

int recvPEEK(int sock,PVStr(buf),int size);
void CCXcounts(CCXP ccx);
int CCXsize();
static int withTM(int sock){
	int rcc;
	CStr(buf,3);

	/* reset error status of CCX on break */
	if( ccxTOSV ){
		bcopy(ccxbTOSV,ccxTOSV,CCXsize());
	}
	if( ccxTOCL ){
		bcopy(ccxbTOCL,ccxTOCL,CCXsize());
	}

	/* 9.4.0 withTM() is since 9.0.3-pre18, but recvPEEK() breaks the
	 * relay of relayOOB()
	rcc = recvPEEK(sock,AVStr(buf),sizeof(buf));
	if( rcc == 3 )
	if( (0xFF&buf[0]) == IAC && (0xFF&buf[1]) == WILL && buf[2] == O_TM ){
		sv1log("relay TimingMark before OOB DataMark...\n");
		return 1;
	}
	*/
	return 0;
}
static int Read(PCStr(what),int sock,int dst,PVStr(buf),int fsbsize,int timeout)
{	int cnt,rcc,ci,cj;
	const char *sdir;
	int start,nready;

	rcc = 0;
	start = time(0);
	if( keepalive ){
		timeout = keepalive;
	}
	for( cnt = 0; cnt < 10; cnt++ ){
		if( timeout == -1 )
			nready = 1;
		else
		if( THREAD )
			nready = thread_PollIn(sock,timeout*1000);
		else	nready = PollIn(sock,timeout*1000);

		if( THREAD_exiting ){
			sv1log("THREAD_exiting: PollIn()=%d\n",nready);
			rcc = -1;
			break;
		}

		if( nready < 0 ){
			sv1log("nready = %d, errno=%d\n",nready,errno);
			rcc = -1;
			break;
		}
		if( nready == 0 ){
			if( keepalive ){
				Verbose("%s generate NOP\n",what);
				rcc = sizeof(NOPstr);
				Bcopy(NOPstr,buf,rcc);
				break;
			}

			if( timeout <= time(0)-start ){
				sv1log("Timedout %d sec. (by TIMEOUT=io:%ds)\n",
					timeout,timeout);
				rcc = -1;
				break;
			}

			if( relayOOB(sock,dst) )
				continue;

			msleep(10);
			continue;
		}
		errno = 0;

		if( gotOOB(sock) )
		if( !withTM(sock) )
		if( 0 < withOOB(sock) ){
			if( relayOOB(sock,dst) ){
				/* should skip inputs until SYNCH */
			}
			continue;
		}

		rcc = read(sock,(char*)buf,QVSSize(buf,fsbsize));
		if( rcc <= 0 ){
			sv1log("sock=%d read=%d, errno=%d\n",sock,rcc,errno);
			break;
		}
		if( THREAD_exiting ){
			sv1log("THREAD_exiting: read()=%d\n",rcc);
			break;
		}

		if( !gotSIGURG ){
			break;
		}

		if( rcc <= 0 ){
			sv1log("%s read failed (%d) waiting SYNCH (%d)\n",
				what,cnt,gotSIGURG);
			if( 0 < cnt ){
				sv1log("#### faield (%d) wait 0.1 second.\n",cnt);
				msleep(100);
			}
			continue;
		}

		for( ci = 0; ci < rcc; ci++ )
		if( (buf[ci] & 0xFF) == SYNCH ){
			sv1log("%s got SYNCH (%d)\n",what,gotSIGURG);
			gotSIGURG = 0;
			ci++;
			break;
		}
		if( ci == rcc )
			continue;

		rcc -= ci;
		for( cj = 0; cj < rcc; cj++ )
			setVStrElem(buf,cj,buf[ci+cj]); /**/
		break;
	}
	for( ci = 0; ci < rcc; ci++ ){
		if( (buf[ci] & 0xFF) == SYNCH )
			Verbose("######## SYNCH in non Sync mode.\n");
	}
	return rcc;
}

#define C_S	1
#define S_C	2

/*
 * The following stuff is to control ECHOing (and editing with DEL or
 * so) of user-input at the proxy-login dialog (with "Host:" prompt)
 *
 * The default status of ECHO option is WONT/DONT ECHO as described
 * in RFC857.  But some clients programs (like MS's one) seem to
 * expect the server to be WILL ECHO by default, making full-duplex
 * (character by character) communication without doing local-echo...
 * (it's the case of WinNT/2K but not the case in Win95/98/Me/XP...)
 * Doing ECHO negotiation between DeleGate and client is a possible
 * solution, like in older version of DeleGate, but it spoiles
 * the transparent relaying between a server and a client.
 *
 * In secondary connections after closing the first session to a
 * server, a client may be in different status from the initial one
 * (probably in explicit DO ECHO and DO SUPGA). It might make "Host:"
 * dialogue (its editing) be different from the first one (may not be
 * harmful), and make inconsistency with the server (can be harmful)...
 */
static int isHalfdup(){
	int doga;

	if( doga = ClientsDO[O_SUPAHEAD] ) 
		return doga == DONT;
	if( 0 < guessedHalfdup )
		return 1;
	return 0; /* it should be 0 based on RFC858... */ 
}
static int willEcho(){
	int doecho;

	/* explicitly ordered by the client */
	if( doecho = ClientsDO[O_ECHO] )
		return doecho == DO;

	/* negotiated something leaving ECHO as default */
	if( ClientsDO[O_SUPAHEAD] )
		return 0;

	/* suppress redundant echo in half-duplex communication */
	if( isHalfdup() )
		return 0;

	/* it should be 0 baesd on RFC857... */
	/* 0 for Win95 series but 1 for WinNT series */
	return 1;
}
static void logEcho()
{	const char *echo;
	const char *supga;

	switch( ClientsDO[O_ECHO] ){
		case DO:  echo = "DoEcho"; break;
		case DONT:echo = "DontEcho"; break;
		default:  echo = "none"; break;
	}
	switch( ClientsDO[O_SUPAHEAD] ){
		case DO:  supga = "DoSupGA"; break;
		case DONT:supga = "DontSupGA"; break;
		default:  supga = "none"; break;
	}
	sv1log("%s-Echo [client-says:%s,%s], Half=%d(%d)\n",
		willEcho()?"WILL":"WONT",echo,supga,
		isHalfdup(),guessedHalfdup);
}

static void clearServersWill()
{	int si;

	for( si = 0; si < 128; si++)
		ServersWill[si] = 0;
}
static int numServersWill()
{	int si,num;

	num = 0;
	for( si = 0; si < 128; si++ )
		if( ServersWill[si] )
			num++;
	return num;
}

static const char *code(int ch)
{	const char *mn;
	int co;

	co = 1;
	switch( ch ){
		case SE:  co = 0; mn = "SE";		break;
		case 241: co = 0; mn = "NOP";		break;
		case 242: co = 0; mn = "DataMark";	break;
		case 243: co = 0; mn = "Break";		break;
		case 244: co = 0; mn = "InterruptProcess";	break;
		case 245: co = 0; mn = "AbortOutput";	break;
		case 246: co = 0; mn = "AreYouThere";	break;
		case 247: co = 0; mn = "Erasecharacter";	break;
		case 248: co = 0; mn = "EraseLine";	break;
		case 249: co = 0; mn = "Goahead";	break;
		case SB:  co = 0; mn = "SB";		break;
		case WILL:co = 1; mn = "WILL";		break;
		case WONT:co = 1; mn = "WONT";		break;
		case DO:  co = 1; mn = "DO";		break;
		case DONT:co = 1; mn = "DONT";		break;
		case IAC: co = 1; mn = "IAC";		break;
		default:  co = 0; mn = NULL;		break;
	}
	return mn;
}
static const char *option(int ch)
{
	switch( ch ){
		case O_ECHO:     return "Echo";
		case O_TM:     return "Timingmark";
		case O_SUPAHEAD: return "SuppressGoAhead";
		case O_STATUS:	 return "GiveStatus";
		case O_TERMTYPE: return "TerminalType";
		case O_NAOP:     return "NegotiateAboutOutputPageSize";
		case O_NAWS:     return "NegotiateAboutWindowSize";
		case O_TSPEED:   return "TerminalSpeed";
		case O_LFLOW:	 return "RemoteFlowControl";
		case O_XDISPLOC: return "XDisplayLocation";
		case O_ENVIRON:  return "EnvironmentValiables";
		case O_NENVIRON: return "NewEnvironment";
	}
	sprintf(_opt,"%d",ch);
	return _opt;
}

static void controlcommand(Connection *Conn,int toC,int fromC)
{	CStr(code,2);
	CStr(msg,128);

	IGNRETP write(toC,"\r\n> ",4);
	IGNRETP read(fromC,code,1);
	code[1] = 0;
	sprintf(msg,"%c\r\n",code[0]);
	IGNRETP write(toC,msg,strlen(msg));
	global_setCCX(Conn,AVStr(code),AVStr(msg));
	IGNRETP write(toC,msg,strlen(msg));
}

static int scanCommands(int direction,PVStr(buf),int cc)
{	int i,cch,ch,cont;
	CStr(vch,2048);
	const char *mn;
	const char *sdir;

	switch( direction ){
		case CtoS: sdir = "CS"; break;
		case DtoS: sdir = "DS"; break;
		case CtoD: sdir = "CD"; break;
		case StoC: sdir = "SC"; break;
		case DtoC: sdir = "DC"; break;
		default:   sdir = "??"; break;
	}

	for(i = 0; i < cc; i++){

	    if( direction == CtoS ){
		cc += rewriteTelnet(direction,QVStr(buf+i,buf),cc-i);
	    }

	    ch = buf[i] & 0xFF;
	    vch[0] = 0;
	    if( ch == IAC ){
	        ch = buf[++i] & 0xFF;
		if( WILL <= ch && ch <= DONT ){
			cch = ch;
			mn = code(cch);
	        	ch = buf[++i] & 0xFF;
			sprintf(vch,"%-4s %s",mn,option(ch));
			if( direction == CtoS || direction == CtoD ){
				if( ch == O_XDISPLOC ){
					if( cch == WONT && Xdisplay[0] ){
						Verbose("WONT->WILL %s\n",option(ch));
						cch = WILL;
						setVStrElem(buf,i-1,cch);
						mn = code(cch);
						sprintf(vch,"%-4s %s",mn,option(ch));
					}
				}
				if( ch == O_TERMTYPE || ch == O_ENVIRON )
				Verbose("%s Client-Says %s\n",sdir,vch);
				if( cch == WILL
				 || cch == WONT && ClientsWill[ch] == 0 )
					ClientsWill[ch] = cch;
				if( cch == DO || cch == DONT )
					ClientsDO[ch] = cch;
			}else
			if( direction == StoC ){
				ServersWill[ch] = cch;
			}
		}else
		if( ch == NOP ){
			sprintf(vch,"NOP");
		}else
		if( ch == SB ){
			strcpy(vch,"SB,");
			ch = buf[++i];
			strcat(vch,option(ch));

			for(i++; i < cc; i++ ){
				ch = buf[i] & 0xFF;
				if( ' ' < ch && ch < 0x7F ){
					if( buf[i-1]<=' ' || 0x7F<=buf[i-1] )
						strcat(vch,",");
					Xsprintf(TVStr(vch),"%c",ch);
				}else
				if( mn = code(ch) ){
					strcat(vch,",");
					strcat(vch,mn);
				}else{
					strcat(vch,",");
					Xsprintf(TVStr(vch),"%d",ch);
				}
				if( ch == SE )
					break;
			}
		}
	        Verbose("%s[%3d] %02x:%3d %s\n",sdir,i,ch,ch,vch);
	    }else{
		if( dump_commands & (direction<<8) )
			sv1log("%s[%3d] %02x:%3d %c\n",
			sdir,i,ch,ch,(' '<ch&&ch<0x7F)?ch:' ');
		if( direction == StoC ){
			/* code conversion */
			if( ccxTOCL ){
				cc = ccx_telnet((int*)ccxTOCL,AVStr(buf),&i,cc);
				if( (0xFF & buf[i]) == IAC ) i--;
			}else
			if( ccx_global ) cc = ccx_telnet(ccx_global,AVStr(buf),&i,cc);
		}else
		if( direction == CtoS ){
			if( ccxTOSV ){
				cc = ccx_telnet((int*)ccxTOSV,AVStr(buf),&i,cc);
				if( (0xFF & buf[i]) == IAC ) i--;
			}
			if( ccx_global ){
				/* conversion switch command ... */
				/*
			static numCC;
				if( ch == ('C'-0x40) ){
					numCC++;
					if( 2 < numCC ){
						sv1log("## ctrl-C*%d\n",numCC);
						numCC = 0;
						if( i+1 == cc ){
							docontrol = 1;
							cc--;
						}
					}
				}else	numCC = 0;
				*/
			}
		}
	    }
	}
	return cc;
}
static int ccx_telnet(int*ccx,PVStr(buf),int *ip,int cc)
{	CStr(out,0x8000);
	CStr(tmp,0x8000);
	int i,j,k,l,tc,oc;
	int fc;

	i = *ip;
	if( (0xFF & buf[i]) == SYNCH ){
		return cc;
	}
	for( j = i; j < cc; j++ )
		if( (buf[j] & 0xFF) == IAC )
			break;

	if( j == i ){
		return cc;
	}

/*
 fprintf(stderr,
"-- %3d/%3d [%2X [%3d][%3d] %2X] %2X/%3d %2X/%3d %2X %2X %2X %2X %2X %2X ",
j-i,cc,
0<j?0xFF&buf[j-1]:0,i,j,j<cc?0xFF&buf[j]:0,
0xFF&buf[i+0],0xFF&buf[i+0],
0xFF&buf[i+1],0xFF&buf[i+1],
0xFF&buf[i+2],0xFF&buf[i+3],
0xFF&buf[i+4],0xFF&buf[i+5],
0xFF&buf[i+6],0xFF&buf[i+7]
 ); CCXcounts((CCXP)ccx);
*/

	oc = CCXexec((CCXP)ccx,buf+i,j-i,AVStr(out),sizeof(out));
	/*
	fc = CCXexec((CCXP)ccx,"",0,DVStr(out,oc),sizeof(out)-oc);
	oc += fc;
	*/

	tc = 0;
	for( k = j; k < cc; k++ ){
		if( elnumof(tmp) <= tc ){
			break;
		}
		setVStrElemInc(tmp,tc,buf[k]); /**/
	}
	for( k = 0; k < oc; k++ ){
		assertVStr(buf,buf+i+1);
		setVStrElemInc(buf,i,out[k]); /**/
	}
	l = i;
	for( k = 0; k < tc; k++ ){
		assertVStr(buf,buf+l+1);
		setVStrElemInc(buf,l,tmp[k]); /**/
	}
	cc = l;

	*ip = i;
	return cc;
}

static int getCommand(FILE *fp,UTag *Tcbuf,int off)
{	int ci,ch,ach;
	refQStr(cbuf,Tcbuf->ut_addr); /**/
	int cx;

	cbuf = (char*)Tcbuf->ut_addr + off;
	cx = Tcbuf->ut_size - off - 1;

	ci = 0;
	ch = getc(fp);
	setVStrElemInc(cbuf,ci,ch);

	if( WILL <= ch && ch <= DONT ){
		ach = getc(fp);
		setVStrElemInc(cbuf,ci,ach);
	}else
	if( ch == SB ){
		do {
			if( cx <= ci ){
				notify_overflow("Telnet Command",Tcbuf->ut_addr,off+ci);
				discardBuffered(fp);
				break;
			}
			ch = getc(fp);
			if( ch == EOF )
				break;
			setVStrElemInc(cbuf,ci,ch);
		} while(ch != SE);
	}
	return ci;
}
/**/
static int xgetline(void *visible,FILE *fc,FILE *tc,UTag *Tline,UTag *Tcbuf)
{	int ready;
	int ch,ci;
	int endCR;
	int lx;
	int ii;
	const char *cb;
	int timeout;
	CStr(cbufbuf,1024);
	refQStr(line,Tline->ut_addr); /**/
	defQStr(cbuf); /*indirect*//**/
	int lsiz,csiz;
	UTag Tcbufb;

	line = (char*)Tline->ut_addr;
	lsiz = Tline->ut_size;
	if( Tcbuf == NULL ){
		Tcbuf = &Tcbufb;
		setQStr(Tcbuf->ut_addr,cbufbuf,sizeof(cbufbuf));
		Tcbuf->ut_size = sizeof(cbufbuf);
	}
	setQStr(cbuf,Tcbuf->ut_addr,Tcbuf->ut_size);
	csiz = Tcbuf->ut_size;
	endCR = 0;
	ci = 0;
	lx = 0;

	if( Xproxy[0] )
		timeout = LOGIN_TIMEOUT * 1000 * 4;
	else	timeout = LOGIN_TIMEOUT * 1000;

	/*
	 * "Password:" for proxy-authorization should be hidden.
	 * To do so, DeleGate must notify that I WILL DO FULL DUPLEX ECHO
	 * to the client. (This had been the default before 6.1.3)
	 */
	if( !visible ){
		if( ClientsDO[O_ECHO] != DO && ClientsWill[O_ECHO] != WONT )
			putIAC(tc,WILL,O_ECHO);
		if( ClientsDO[O_SUPAHEAD] != DO )
			putIAC(tc,WILL,O_SUPAHEAD);
	}

	for(;;){
		if( lsiz-1 <= lx ){
			notify_overflow("Telnet Input",line,lx);
			discardBuffered(fc);
			break;
		}
		if( csiz-1 <= ci ){
			notify_overflow("Telnet Command",cbuf,ci);
			discardBuffered(fc);
			break;
		}
		if( fflush(tc) == EOF )
			break;

		ready = fPollIn(fc,timeout);
		if( ready <= 0 ){
			if( ready == 0 ){
 fprintf(tc,"\r\n---------- PROXY-TELNET login: TIMEOUT(%d).\r\n",
					timeout);
				fflush(tc);
				return EOF;
			}
			break;
		}
		ch = fgetc(fc);

		if( ch != IAC && ch != 0 ){
			if( guessedHalfdup < 0 ){
				if( ready_cc(fc) <= 0 )
					guessedHalfdup = 0;
				else	guessedHalfdup = 1;
			}
			if( lx == 0 )
				logEcho();
		}

		if( visible ){
			if( willEcho() )
			if( isprint(ch) ){
				putc(ch,tc);
				fflush(tc);
			}

			if( ch == '?' ){
				if( fPollIn(fc,300) == 0 ){
					setVStrElemInc(line,lx,ch);
					goto EOL;
				}
			}
		}else{
			if( isprint(ch) || ch == '\t' ){
				putc('*',tc);
				fflush(tc);
			}
		}

		if( ch != IAC )
			Verbose("CD %x\n",ch);

		switch( ch ){
			case IAC:
				setVStrElem(cbuf,ci,ch);
				ii = 1 + getCommand(fc,Tcbuf,ci+1);
				ci += scanCommands(CtoS,
					QVStr(cbuf+ci,Tcbuf->ut_addr),ii);
				break;

			case 0: break;
			case '\001': break; /* ? */

			case 'D'-0x40:
				fprintf(tc,"\r\n");
				fflush(tc);
			case EOF:
				Verbose("--EOF from client--\n");
				return EOF;
			case 0x7F:
			case 'H'-0x40:
				if( 0 < lx ){
					if( willEcho() )
					fwrite("\b \b",1,3,tc);
					lx--;
				}
				break;

			case 'U'-0x40:
			{	for( ii = 0; ii < lx; ii++ ) fputc('\b',tc);
				for( ii = 0; ii < lx; ii++ ) fputc(' ',tc);
				for( ii = 0; ii < lx; ii++ ) fputc('\b',tc);
				lx = 0;
				break;
			}

			case '\r':
				endCR = 1; /* X-( */
				if( 0 < ready_cc(fc) ){
					int nch;
					nch = getc(fc);
					if( nch == '\n' ){
						ch = nch;
						endCR = 0;
					}else	ungetc(nch,fc);
				}
			case '\n':
				Verbose("EOL char = %x\n",ch);
				goto EOL;
			default:
				setVStrElemInc(line,lx,ch);
				break;
		}
	} EOL:
	setVStrEnd(line,lx);

	if( willEcho() )
	fputs("\r\n",tc);

	Tcbuf->ut_leng = ci;
	return ci;
}

#define addIbuf(v) setVStrElemInc(ibuf,ii,v)
static void putIAC(FILE *tc,int com,int what)
{	JStr(ibuf,32);
	char ii;

	ii = 0;
	addIbuf(IAC); addIbuf(com); addIbuf(what);
	ii = scanCommands(DtoC,AVStr(ibuf),ii);
	fwrite(ibuf,1,ii,tc);
}
static void sayWelcome(Connection *Conn,FILE *tc)
{	const char *aurl;
	CStr(rurl,256);
	CStr(msg,2048);

	aurl = "/-/builtin/mssgs/telnet/telnet-banner.dhtml";
	getBuiltinData(Conn,"TELNET-banner",aurl,AVStr(msg),sizeof(msg),AVStr(rurl));
	put_eval_dhtml(Conn,rurl,tc,msg);
}
static void putHELP(Connection *Conn,FILE *tc)
{	const char *aurl;
	CStr(rurl,256);
	CStr(msg,2048);

	aurl = "/-/builtin/mssgs/telnet/telnet-help.dhtml";
	getBuiltinData(Conn,"TELNET-help",aurl,AVStr(msg),sizeof(msg),AVStr(rurl));
	put_eval_dhtml(Conn,rurl,tc,msg);
}
static void cantConnMessage(Connection *Conn,PCStr(serv),FILE *tc)
{	const char *aurl;
	CStr(rurl,256);
	CStr(msg,2048);

	aurl = "/-/builtin/mssgs/telnet/telnet-cantconn.dhtml";
	getBuiltinData(Conn,"TELNET-cantconn",aurl,AVStr(msg),sizeof(msg),AVStr(rurl));
	put_eval_dhtml(Conn,rurl,tc,msg);
}
static void ConnectedMessage(Connection *Conn,PCStr(serv),FILE *tc,PCStr(comline))
{
	fprintf(tc,"-- Connected to %s.\r\n",serv);
	if( toProxy ){
		fprintf(tc,"Connected to another telnet-proxy.\r\n");
		fprintf(tc,"Your input[%s] is forwarded to it.\r\n",comline);
	}
	fflush(tc);
}

static int get_hostname(Connection *Conn,FILE *fc,FILE *tc,UTag *Tline,UTag *Tcbuf,int ncom)
{	int ci;
	CStr(clhost,MaxHostNameLen);

/*
	putIAC(tc,WILL,O_ECHO);
	putIAC(tc,WILL,O_SUPAHEAD);
*/

	if( ncom == 0 )
		sayWelcome(Conn,tc);

	if( ncom == 0 )
	if( !source_permittedX(Conn) ){
		getpeerNAME(FromC,AVStr(clhost));
		fprintf(tc,
		"!!!!!!!! HOST <%s> not permitted by DeleGate\r\n",clhost);
		fflush(tc);
		service_permitted(Conn,"telnet"); /* delay */
		return EOF;
	}

	fprintf(tc,">> Host name: ");
	if( fflush(tc) == EOF )
		return EOF;
	ci = xgetline((void*)1,fc,tc,Tline,Tcbuf);
	if( ci == EOF )
		return EOF;

	fflush(tc);
	return 0;
}
static void relayClientsWill(FILE *ts,int op)
{	int co;

	if( co = ClientsWill[op] ){
		Verbose("DS Client-Said %s %s.\n",code(co),option(op));
		putc(IAC,ts);
		putc(co,ts);
		putc(op,ts);
	}
}
static void relayClientsWills(FILE *ts)
{	int op;
	for( op = 0; op < 128; op++ )
		relayClientsWill(ts,op);
}

static int telnetCS(Connection *Conn,int fcbsize,int omask)
{	CStr(buf,0x4000);
	int gotsig;
	int rcc;
	int count,total;

	if( FromC < 0 ){
		sv1log("CS-REALY: NO INPUT\n");
		Finish(0);
	}

	total = count = 0;
	if( fcbsize == 0 )
		fcbsize = 1;
	if( sizeof(buf) < fcbsize )
		fcbsize = sizeof(buf);

	if( (gotsig = setjmp(tel_env)) == 0 ){
		env_valid = 1;
		sigsetmask(omask);
		for(;;){
			rcc = Read("CS",FromC,ToS,AVStr(buf),fcbsize,IO_TIMEOUT);
			if( rcc <= 0 )
				break;

			if( dump_commands && C_S ){
				rcc = scanCommands(CtoS,AVStr(buf),rcc);
			}

			count += 1;
			total += rcc;

			if( docontrol ){
				docontrol = 0;
				controlcommand(Conn,ToC,FromC);
				if( rcc == 0 )
					continue;
			}

			if( ToS < 0 )
				continue;

			if( write(ToS,buf,rcc) <= 0 )
				break;
		}
		if( rcc <= 0 ) sv1log("CS-EOF\n");
	}
	env_valid = 0;
	sv1log("CS-RELAY[%d>%d]: %dBytes %dI/O buf=%d\n",
		FromC,ToS,total,count,fcbsize);

	if( gotsig == SIGPIPE ){
		/* the server has done but the response data
		 * to the client may remain (for safety...)
		 */
		sv1log("CS-SIGPIPE\n");
		sleep(1);
	}
	return total;
}
static int telnetSC(Connection *Conn,int fsbsize,int omask)
{	CStr(buf,0x4000);
	int gotsig;
	int rcc,wcc;
	int count,total;

	total = count = 0;
	if( fsbsize == 0 )
		fsbsize = 1;
	if( sizeof(buf) < fsbsize )
		fsbsize = sizeof(buf);

	if( setjmp(tel_env) == 0 ){
		env_valid = 1;
		sigsetmask(omask);
		for(;;){
			rcc = Read("SC",FromS,ToC,AVStr(buf),fsbsize,IO_TIMEOUT);
			if( rcc <= 0 )
				break;

			count += 1;
			total += rcc;
			if( (dump_commands & S_C) || CCX0 ){
				rcc = scanCommands(StoC,AVStr(buf),rcc);
				if( rcc == 0 ){
					/* ESC seq. pending in CCX0 */
					continue;
				}
			}

			if( (wcc = write(ToC,buf,rcc)) <= 0 )
				break;
		}
		if( rcc <= 0 ) sv1log("SC-EOF\n");
	}
	env_valid = 0;
	sv1log("SC-RELAY[%d<%d]: %dBytes %dI/O buf=%d\n",
		ToC,FromS,total,count,fsbsize);
	return total;
}

static void THREADexit(Connection *Conn)
{	int efd;

	if( THREAD && THREAD_exiting == 0 ){
		THREAD_exiting = 1;
		if( !IsAlive(FromC) ) efd = FromC; else
		if( !IsAlive(FromS) ) efd = FromS; else
		{
			sv1log("THREAD_exit: both side are alive ? %d,%d\n",
				FromC,FromS);
			Finish(-1);
		}
		sv1log("THREAD_exit: dup closed socket %d to %d/%d,%d/%d\n",
			efd,FromC,ToC,FromS,ToS);
		if( efd != FromC ) dup2(efd,FromC);
		if( efd != ToC   ) dup2(efd,ToC);
		if( efd != FromS ) dup2(efd,FromS);
		if( efd != ToS   ) dup2(efd,ToS);

		/*
		 * wait the child thread to exit on closed socket {From,To}{C,S}
		 * no return if this is the child thread.
		 */
		msleep(10);
		if( THREAD_exiting != 2 )
			sv1log("THREAD_exit: failed, exiting=%d\n",THREAD_exiting);
	}
	else
	if( THREAD ){
		THREAD_exiting++;
	}
}
static int SC1(Connection *Conn,int fsbsize,int omask)
{	int cc;

	dumpTimer();
	/*
	setRecvSIGURG(FromS);
	*/
	cc = telnetSC(Conn,fsbsize,omask);
	THREADexit(Conn);
	return cc;
}
static int CS1(Connection *Conn,int fcbsize,int omask)
{	int cc;

	dumpTimer();
	/*
	setRecvSIGURG(FromC);
	*/
	cc = telnetCS(Conn,fcbsize,omask);
	THREADexit(Conn);
	return cc;
}

static int relayCS0(Connection *Conn,int bsize){
	CStr(buf,0x4000);
	int rcc;
	int icc;

	rcc = Read("CS",FromC,ToS,AVStr(buf),bsize,-1);
	icc = rcc;
	if( rcc <= 0 )
		return -1;
	/*
	if( dump_commands && C_S ){
	*/
	if( (dump_commands && C_S) || ccxTOSV ){
		rcc = scanCommands(CtoS,AVStr(buf),rcc);
	}
	if( docontrol ){
		docontrol = 0;
		controlcommand(Conn,ToC,FromC);
		if( rcc == 0 )
			return 0;
	}
	if( ToS < 0 )
		return 0;
	if( write(ToS,buf,rcc) <= 0 )
		return -1;
	return rcc;
}
static int relaySC0(Connection *Conn,int bsize){
	CStr(buf,0x4000);
	int rcc;
	int icc;

	rcc = Read("SC",FromS,ToC,AVStr(buf),bsize,-1);
	icc = rcc;
	if( rcc <= 0 )
		return -1;
/*
	if( dump_commands && S_C ){
*/
	/*
	if( dump_commands & S_C ){
	*/
	if( (dump_commands & S_C) || ccxTOCL ){
		rcc = scanCommands(StoC,AVStr(buf),rcc);
	}
	if( docontrol ){
		docontrol = 0;
		controlcommand(Conn,ToS,FromS);
		if( rcc == 0 )
			return 0;
	}
	if( ToC < 0 )
		return 0;
	if( write(ToC,buf,rcc) <= 0 )
		return -1;
	return rcc;
}
static int bidirectional_relay2(Connection *Conn,int fcbsize,int fsbsize)
{	register int ppid,cpid;
	int omask;
	int total;
	void (*opipe)(int);
	void (*oterm)(int);
	void (*ointr)(int);

	CStr(snoop,64);
	int sf;
	if( 0 <= find_CMAP(Conn,"DUMP",AVStr(snoop)) ){
		sf = 0;
		if( strcasestr(snoop,"tosv") ) sf |= C_S|(CtoS<<8);
		if( strcasestr(snoop,"tocl") ) sf |= S_C|(StoC<<8);
		dump_commands |= sf;
	}

	Verbose("buffer: CS=%d[%d>%d] SC=%d[%d>%d] (%s)\n",
		fcbsize,FromC,ToS,fsbsize,FromS,ToC,
		"Polling");

	omask = sigblock(sigmask(SIGPIPE)|sigmask(SIGTERM));
	opipe = Vsignal(SIGPIPE,sigPIPE);
	oterm = Vsignal(SIGTERM,sigTERM);
	ointr = Vsignal(SIGINT, sigTERM);

	if( FromC < 0 ){
		total = telnetSC(Conn,fsbsize,omask);
	}else
	if( FromS < 0 ){
		total = telnetCS(Conn,fcbsize,omask);
	}else{
		int fds[2];
		int rds[2];
		int fi;
		int nready;
		int rcc;
		int count[2];
		int total[2];

		fds[0] = FromC;
		fds[1] = FromS;
		count[0] = 0; count[1] = 0;
		total[0] = 0; total[1] = 0;

		if( CCXactive(CCX_TOCL) ){
			Bcopy(CCX_TOCL,ccxbTOCL,sizeof(ccxbTOCL));
			ccxTOCL = CCX_TOCL;
		}else	ccxTOCL = 0;
		if( CCXactive(CCX_TOSV) ){
			Bcopy(CCX_TOSV,ccxbTOSV,sizeof(ccxbTOSV));
			ccxTOSV = CCX_TOSV;
		}else	ccxTOSV = 0;

		for(;;){
			nready = PollIns(IO_TIMEOUT*1000,2,fds,rds); 
			if( nready <= 0 )
				break;

			if( nready == 0 && errno == 0 || gotOOB(-1) ){
				int fi,sync;
				sync = 0;
				for( fi = 0; fi < 2; fi++ ){
					if( withOOB(fds[fi]) )
					if( !withTM(fds[fi]) )
					sync += relayOOB(fds[fi],fds[(fi+1)%2]);
				}
				if( 0 < sync )
					continue;
			}
			if( 0 < rds[0] ){
				rcc = relayCS0(Conn,fcbsize);
				if( rcc < 0 ){
					sv1log("CS-EOF\n");
					break;
				}
				count[0] += 1;
				total[0] += rcc;
			}
			if( 0 < rds[1] ){
				rcc = relaySC0(Conn,fcbsize);
				if( rcc < 0 ){
					sv1log("SC-EOF\n");
					break;
				}
				count[1] += 1;
				total[1] += rcc;
			}

		}
		sv1log("CS-RELAY[%d>%d]: %dBytes %dI/O buf=%d\n",
			FromC,ToS,total[0],count[0],fcbsize);
		sv1log("SC-RELAY[%d<%d]: %dBytes %dI/O buf=%d\n",
			ToC,FromS,total[1],count[1],fsbsize);
	}

	signal(SIGPIPE,opipe);
	signal(SIGTERM,oterm);
	signal(SIGTERM,ointr);
	sigsetmask(omask);
	return total;
}
static int bidirectional_relay(Connection *Conn,int fcbsize,int fsbsize)
{	register int ppid,cpid;
	int omask;
	int total;
	void (*opipe)(int);
	void (*oterm)(int);
	void (*ointr)(int);

	CStr(snoop,64);
	int sf;
	if( 0 <= find_CMAP(Conn,"DUMP",AVStr(snoop)) ){
		sf = 0;
		if( strcasestr(snoop,"tosv") ) sf |= C_S|(CtoS<<8);
		if( strcasestr(snoop,"tocl") ) sf |= S_C|(StoC<<8);
		dump_commands |= sf;
	}

	useTHREAD = INHERENT_thread();

	Verbose("buffer: CS=%d[%d>%d] SC=%d[%d>%d] (%s)\n",
		fcbsize,FromC,ToS,fsbsize,FromS,ToC,
		useTHREAD?useTHREAD:"FORK");

	omask = sigblock(sigmask(SIGPIPE)|sigmask(SIGTERM));
	opipe = Vsignal(SIGPIPE,sigPIPE);
	oterm = Vsignal(SIGTERM,sigTERM);
	ointr = Vsignal(SIGINT, sigTERM);

	if( FromC < 0 ){
		total = telnetSC(Conn,fsbsize,omask);
	}else
	if( FromS < 0 ){
		total = telnetCS(Conn,fcbsize,omask);
	}else
	if( useTHREAD ){
		THREAD = 1;
		THREAD_exiting = 0;
		thread_fork(0,STX_tid,"CS1",(IFUNCP)CS1,Conn,fsbsize,omask);
		SC1(Conn,fcbsize,omask /*,ppid*/);
		THREAD = 0;
	}else{
		ppid = getpid();
		if( (cpid = Fork("bidirectiona_relay")) == 0 ){
			total = SC1(Conn,fsbsize,omask);
			signal(SIGTERM,SIG_IGN);
			signal(SIGPIPE,SIG_IGN);
			Kill(ppid,SIGTERM);
			Finish(0);
		}else{
			total = CS1(Conn,fcbsize,omask);
			signal(SIGTERM,SIG_IGN);
			signal(SIGPIPE,SIG_IGN);
			Kill(cpid,SIGTERM);
			wait(0);
		}
	}

	signal(SIGPIPE,opipe);
	signal(SIGTERM,oterm);
	signal(SIGTERM,ointr);
	sigsetmask(omask);
	return total;
}

static void getServersWill(int fromS,FILE *tc)
{	int rcc;
	CStr(scbuf,4096);

	if( PollIn(fromS,1000) ){
		rcc = readTIMEOUT(fromS,AVStr(scbuf),sizeof(scbuf));
		sv1log("######## %d bytes from the server\n",rcc);
		rcc = scanCommands(StoC,AVStr(scbuf),rcc);
		fwrite(scbuf,1,rcc,tc);
		fflush(tc);
	}
}

static int putXdisplay(FILE *ts,PCStr(display))
{	JStr(ibuf,128);
	char ch;
	int ii,ij;
	int opt;

	if( ServersWill[O_XDISPLOC] != DO && ServersWill[O_ENVIRON] != DO )
		return 0;

	if( ServersWill[O_XDISPLOC] == DO )
		opt = O_XDISPLOC;
	else	opt = O_ENVIRON;

if( opt == O_ENVIRON )
	return 0;

	ii = 0;
	addIbuf(IAC); addIbuf(WILL); addIbuf(opt);
	addIbuf(IAC); addIbuf(SB);   addIbuf(opt);
	addIbuf(IS);
	if( opt == O_ENVIRON ){
		addIbuf(VAR);
		for( ij = 0; ch = "DISPLAY"[ij]; ij++ ){
			addIbuf(ch);
		}
		addIbuf(VALUE);
	}
	for( ij = 0; ch = display[ij]; ij++ ){
		if( elnumof(ibuf) <= ii+3 )
			break;
		addIbuf(ch);
	}
	addIbuf(IAC); addIbuf(SE);
	ii = scanCommands(DtoC,AVStr(ibuf),ii);
	fwrite(ibuf,1,ii,ts);
	return 1;
}

static int makeXproxy1(Connection *Conn,PVStr(myname),PCStr(peername),int peerport)
{	CStr(me,MaxHostNameLen);
	CStr(myhp,MaxHostNameLen);
	int xpid;

/*
Socks can accept only one X connection ...

	if( Conn->sv_viaSocks ){
		CStr(rhost,64);
		int rport,rsock;

		rsock = bindViaSocks(Conn,DST_HOST,DST_PORT,rhost,&rport);
		sv1log("#### sock=%d host=%s port=%d\n",rsock,rhost,rport);
		close(sock);
	}
*/

	ClientIF_HP(Conn,AVStr(myhp));
	sprintf(me,"%s://%s/",DFLT_PROTO,myhp);
	xpid = makeXproxy(Conn,AVStr(Xproxy),Xdisplay,AVStr(myname),peername,me,0);

	/* if SRCIF="proxyDisplay:*:X" is given */{
		CStr(xdisp,MaxHostNameLen);
		const char *dp;
		int xport;

		if( SRCIFfor(Conn,"X",peername,peerport,AVStr(xdisp),&xport) ){
			if( dp = strchr(Xproxy,':') ){
				sv1log("#### Xproxy = %s (%s)\n",xdisp,Xproxy);
				Strrplc(AVStr(Xproxy),dp-Xproxy,xdisp);
			}
		}
	}

	sv1log("#### Xproxy[%d]: %s <- %s <- %s\n",
		xpid,Xdisplay,Xproxy,peername);
	return xpid;
}

static void proxy_telnet(Connection *Conn)
{	FILE *tc,*fc,*ts;
	CStr(comline,256);
	CStr(cbuf,256);
	CStr(command,256);
	CStr(hostport,MaxHostNameLen);
	CStr(serv,MaxHostNameLen);
	CStr(clnt,MaxHostNameLen);
	const char *addr;
	CStr(auth,256);
	CStr(auser,256);
	CStr(ahost,MaxHostNameLen);
	const char *iuser;
	int port;
	int csize;
	int ns,ncom;
	const char *mount_opts;
	UTag Tcomline,Tcbuf;

	tc = fdopen(ToC,"w");
	fc = fdopen(ToC,"r");

	Xpid = 0;
	Xdisplay[0] = 0;
	dump_commands |= C_S; /* to check WILL/WONT TERMTYPE ... */

	setQStr(Tcomline.ut_addr,comline,sizeof(comline));
	Tcomline.ut_size = sizeof(comline);
	setQStr(Tcbuf.ut_addr,cbuf,sizeof(cbuf));
	Tcbuf.ut_size = sizeof(cbuf);

	ncom = 0;
	for(ns = 0;;ns++){
		if( get_hostname(Conn,fc,tc,&Tcomline,&Tcbuf,ncom) == EOF ){
			sv1log("EOF from the client\n");
			break;
		}
		csize = Tcbuf.ut_leng;
		ncom++;

		if( comline[0] == 0 ){
			sv1log("EMPTY line for QUIT\n");
			break;
		}

		if( mount_opts = CTX_mount_url_to(Conn,NULL,"GET",AVStr(comline)) ){
			if( strncasecmp(comline,"telnet://",9) == 0 ){
				const char *dp;
				wordscanY(comline+9,AVStr(comline),sizeof(comline),"^/? \t\r\n");
				if( dp = strchr(comline,':') )
					*(char*)dp = ' '; /**/
			}
		}

		command[0] = hostport[0] = 0;
		Xsscanf(comline,"%s %[^\r\n]",AVStr(command),AVStr(hostport));
		if( streq(command,"q") || streq(command,"quit") || streq(command,"exit") ){
			sv1log("[%s] command from the client\n",command);
			break;
		}else
		if( streq(command,"help") || streq(command,"?") ){
			putHELP(Conn,tc);
			fflush(tc);
			continue;
		}else
		if( streq(command,"x") || streq(command,"x-gw") ){
			CStr(host,128);
			int port;

			sv1log("TIS compati. proxy-telnet with X-proxy\n");
			host[0] = 0;
			if( Xsscanf(hostport,"%[^:]:%d",AVStr(host),&port) != 2 ){
				if( host[0] == 0 )
					getpeerNAME(FromC,AVStr(hostport));
				strcat(hostport,":0");
				fprintf(tc,"####[regarded as] x-gw %s\r\n",hostport);
				fflush(tc);
			}
			strcpy(Xdisplay,hostport);
			continue;
		}else
		if( streq(command,"a") || streq(command,"accept") ){
			CStr(myname,MaxHostNameLen);

			if( hostport[0] == 0 ){
				fprintf(tc,"???? Usage: accept hostname\r\n");
				fflush(tc);
				continue;
			}
			hostIFfor(hostport,AVStr(myname));
			sv1log("myname = %s\n",myname);
			if( myname[0] == 0 ){
				fprintf(tc,"???? cannot find a route to %s\r\n",hostport);
				fflush(tc);
				continue;
			}

			if( 0 < Xpid )
				Kill(Xpid,SIGTERM);

			Xpid = makeXproxy1(Conn,AVStr(myname),hostport,0);
			fprintf(tc,"####[X-Proxy] accept host '%s'\r\n",hostport);
			fprintf(tc,"####[started] use DISPLAY '%s'\r\n",Xproxy);
			fflush(tc);
			continue;
		}else
		if( streq(command,"j") ){
			CStr(stat,256);
			CCXcreate("*",hostport,CCX_TOCL);
			if( CCXactive(CCX_TOCL) ){
				Bcopy(CCX_TOCL,ccxbTOCL,sizeof(ccxbTOCL));
				ccxTOCL = CCX_TOCL;
			}else	ccxTOCL = 0;

			global_setCCX(Conn,AVStr(hostport),AVStr(stat));
			fprintf(tc,"-- charcode conversion [%s]%s\r\n",
				hostport,stat);
			fflush(tc);
			continue;
		}else
		if( streq(command,"t") || streq(command,"telnet")
		 || streq(command,"c") || streq(command,"connect") ){
			sv1log("TIS compati. proxy-telnet\n");
		}else{
			strcpy(hostport,comline);
		}
		serv[0] = 0;
		port = DFLT_PORT;
		if( strneq(hostport,"-ssh.",5) ){
			strcpy(REAL_PROTO,"ssh");
			ovstrcpy(hostport,hostport+5);
			REAL_PORT = 22;
			port = 22;
		}
		if( strstr(hostport,"@-ssh.") ){
			IStr(auth,128);
			const char *dp;
			dp = wordScanY(hostport,auth,"^@");
			if( strneq(dp,"@-ssh.",6) ){
				strcpy(REAL_PROTO,"ssh");
				sprintf(hostport,"%s@%s",auth,dp+6);
				REAL_PORT = 22;
				port = 22;
			}
		}
		Xsscanf(hostport,"%s %d",AVStr(serv),&port);

		if( serv[0] == 0 ){
			sv1log("empty command for QUIT form the client\n");
			break;
		}

		auser[0] = ahost[0] = 0;
		if( doAUTH0(Conn,fc,tc,"telnet",serv,port,AVStr(auser),AVStr(ahost),(iFUNCP)xgetline,NULL) == EOF )
			break;
		/* DFLT_HOST and DFLT_PORT is set as side effect in doAUTH0() */

		if( Xdisplay[0] ){
			/* suppress direct connection by MASTER */
			strcpy(D_SERVER,"telnet://-/");
		}

		if( iuser = getClientHostPortUser(Conn,AVStr(clnt),NULL) )
			Xsprintf(TVStr(clnt),"(%s)",iuser);
		auth[0] = 0;
		if( auser[0] )
			sprintf(auth,"<%s@%s>",auser,ahost);

		sv1log("TELNET LOGIN FROM %s%s TO %s\n",clnt,auth,serv);
fputLog(Conn,"Login","TELNET; from=%s%s; to=%s\n",clnt,auth,serv);

		if( (addr = gethostaddr(serv)) == NULL )
			addr = "unknown host";

		if( mount_opts == NULL )
		fprintf(tc,"-- Trying %s [%s:%d] ...\r\n",
			serv,addr,DST_PORT);
		fflush(tc);

		ConnError = 0;

		if( streq(DST_PROTO,"ssh") || DST_PORT == 22 ){
			int tos;
			IStr(user,128);
			if( strchr(serv,'@') ){
				wordScanY(serv,user,"^@");
			}
			tos = connectToSsh(Conn,DST_HOST,DST_PORT,user,"");
			sv1log("SSHGW[%d] %s:%d\n",tos,DST_HOST,DST_PORT);
			if( tos != -1 ){
				ToS = FromS = tos;
				bidirectional_relay2(Conn,0x2000,0x2000);
			}else{
				cantConnMessage(Conn,serv,tc);
				fflush(tc);
			}
		}else
		if( connect_to_serv(Conn,FromC,ToC,0) < 0 ){
			cantConnMessage(Conn,serv,tc);
			fflush(tc);
		}else{
			ConnectedMessage(Conn,serv,tc,comline);
			clearServersWill();
			getServersWill(FromS,tc);

			ts = fdopen(dup(ToS),"w");
			if( csize ){
				Verbose("C-S %d bytes\n",csize);
				fwrite(cbuf,1,csize,ts);
				fflush(ts);
			}
			if( Xdisplay[0] ){
				CStr(myname,MaxHostNameLen);
				CStr(peername,MaxHostNameLen);
				int port;

				gethostNAME(ToS,AVStr(myname));
				/*
				getpeerNAME(ToS,peername);
				Xpid = makeXproxy1(Conn,myname,peername);
				*/
				port = getpeerNAME(ToS,AVStr(peername));
				Xpid = makeXproxy1(Conn,AVStr(myname),peername,port);
			}
/*
			if( toProxy ){
*/
			if( toProxy || toMaster && Xdisplay[0] ){
				putIAC(ts,DO,O_ECHO); /* enable server ECHO */

				sv1log("#### connected to Proxy telnet\n");
				/* fprintf(ts,"telnet %s\r\n",serv); */
				if( Xdisplay[0] ){
					fprintf(ts,"x-gw %s\r\n",Xproxy);
					fflush(ts);
				}
				fprintf(ts,"%s",comline);
				if( toMaster )
					fprintf(ts,"\r\n");
			}else{
				if( Xdisplay[0] ){
					int set;

					set = putXdisplay(ts,Xproxy);
					fprintf(tc,"####[set %s] setenv DISPLAY %s\r\n\r\n",
						set?"automatically":"manually",Xproxy);
					fflush(tc);
				}
			}

			/* Some telnet client (at least SunOS's one)
			 * does not repeat WILL/WONT twice.
			 */
			if( numServersWill() != 0 ){ /* is Telnet server */
			relayClientsWills(ts);
			}else{
			/* how the client can be reset to initial state ? */
				/*
				sv1log("#### force kludge line mode ...\n");
				putIAC(tc,WONT,O_ECHO);
				putIAC(tc,WILL,O_SUPAHEAD);
				putIAC(tc,DO,O_TIMING);
				... skip until TIMING-MARK ...
				*/
			}

			fclose(ts);
			/*
			bidirectional_relay(Conn,1024,1024);
			*/
			bidirectional_relay2(Conn,1024,1024);
			fprintf(tc,"\r\n");

			if( 0 < Xpid ){
				Kill(Xpid,SIGTERM);
				Xpid = 0;
			}
			ncom = 0;
			if( ImMaster ){
				break;
			}
		}
	}
	if( 0 < Xpid ){
		Kill(Xpid,SIGTERM);
		Xpid = 0;
	}
}

static void AsServer(Connection *Conn)
{	FILE *fc,*tc,*fp;
	CStr(uname,128);
	CStr(myhost,128);
	CStr(user,128);
	CStr(pass,128);
	JStr(ibuf,128);
	int ii;
	CStr(line,1024);
	const char *dp;
	CStr(com,128);
	const char *arg;
	CStr(pwd,1024);

	ClientIF_name(Conn,FromC,AVStr(myhost));
	Uname(AVStr(uname));

	fc = fdopen(FromC,"r");
	tc = fdopen(ToC,"w");
	fputs("\r\n",tc);
	fprintf(tc,"%s (%s) Telnet-%s\r\n",uname,myhost,DELEGATE_version());
	fputs("\r\n",tc);

	ii = 0;
	addIbuf(IAC); addIbuf(WONT); addIbuf(O_ECHO);
	addIbuf(IAC); addIbuf(DO);   addIbuf(O_ECHO);
	fwrite(ibuf,1,ii,tc);
	fflush(tc);
	scanCommands(DtoC,AVStr(ibuf),ii);
	ii = read(fileno(fc),line,sizeof(line));
	scanCommands(CtoD,AVStr(ibuf),ii);

	fputs("UserName: ",tc);
	fflush(tc);
	if( fgets(line,sizeof(line),fc) == NULL )
		goto EXIT;
	lineScan(line,user);
	sv1log("USER: %s\n",user);

	ii = 0;
	addIbuf(IAC); addIbuf(WILL); addIbuf(O_ECHO);
	addIbuf(IAC); addIbuf(DONT); addIbuf(O_ECHO);
	fwrite(ibuf,1,ii,tc);
	fflush(tc);
	scanCommands(DtoC,AVStr(ibuf),ii);
	ii = read(fileno(fc),line,sizeof(line));
	scanCommands(CtoD,AVStr(ibuf),ii);

	fputs("PassWord: ",tc);
	fflush(tc);
	if( fgets(line,sizeof(line),fc) == NULL )
		goto EXIT;
	fputs("\r\n",tc);
	lineScan(line,pass);
	if( Authenticate(Conn,"localhost",user,pass,"/") < 0 )
		goto EXIT;

	ii = 0;
	addIbuf(IAC); addIbuf(WONT); addIbuf(O_ECHO);
	addIbuf(IAC); addIbuf(DO);   addIbuf(O_ECHO);
	fwrite(ibuf,1,ii,tc);
	fflush(tc);
	scanCommands(DtoC,AVStr(ibuf),ii);
	ii = read(fileno(fc),line,sizeof(line));
	scanCommands(CtoD,AVStr(ibuf),ii);

	for(;;){
		IGNRETS getcwd(pwd,sizeof(pwd));
		fprintf(tc,"%s> ",pwd);
		fflush(tc);

		if( fgets(line,sizeof(line),fc) == NULL )
			break;
		sv1log("%s> %s",pwd,line);
		if( dp = strpbrk(line,"\r\n") )
			truncVStr(dp);
		arg = wordScan(line,com);
		while( *arg == ' ' || *arg == '\t' )
			arg++;
		if( strcmp(com,"cd") == 0 || strcmp(com,"chdir") == 0 ){
			IGNRETZ chdir(arg);
			continue;
		}
		if( strcmp(com,"exit") == 0 || strcmp(com,"quit") == 0 )
			break;

		fp = popen(line,"r");
		while( fgets(line,sizeof(line),fp) != NULL ){
			if( dp = strpbrk(line,"\r\n") )
				truncVStr(dp);
			fputs(line,tc);
			fputs("\r\n",tc);
		}

		fflush(tc);
		pclose(fp);
	}
EXIT:
	fclose(tc);
	fclose(fc);
}

/*
 * relaying to non-Telnet arbitrary port is enabled with REMITTABLE="telnet"
 */
static int telnetonly(Connection *Conn)
{	int relayany;
	Port sv;

	sv = Conn->sv;
	strcpy(REAL_HOST,"-");
	strcpy(REAL_PROTO,"telnet");
	REAL_PORT = 99999;
	relayany = service_permitted2(Conn,"telnet",1);
	Conn->sv = sv;
	return !relayany;
}

static struct { 
	char *ne_USER;
} clenv;
static char doNewEnviron[] = {IAC,SB,O_NENVIRON,1,IAC,SE};
static int getUSERenv(FILE *fc,FILE *tc,AuthInfo *au){
	int rcc,nrcc;
	int timeout = 15*1000;
	IStr(buf,1024+1);
	IStr(nbuf,1024+1);
	const unsigned char *up = (const unsigned char*)buf;
	const unsigned char *vp = (const unsigned char*)nbuf;
	IStr(userb,MaxHostNameLen);

	putIAC(tc,DO,O_NENVIRON); fflush(tc); /* ask USER */
	IGNRETP write(fileno(tc),doNewEnviron,sizeof(doNewEnviron));

	for(;;){
		if( PollIn(fileno(fc),timeout) == 0 ){
			break;
		}
		rcc = read(fileno(fc),buf,sizeof(buf)-1);
		if( 0 < rcc ){
			Bcopy(buf,nbuf,rcc);
			nrcc = scanCommands(CtoS,AVStr(nbuf),rcc);
		}
		if( 3 <= rcc && up[0] == 0xFF ){
			if( up[1] == WILL && up[2] == O_AUTH ){
				putIAC(tc,DONT,O_AUTH);
				fflush(tc);
			}
			if( up[1] == WILL || up[1] == SB )
			if( up[2] == O_NENVIRON ){
			    if( clenv.ne_USER ){
				strcpy(userb,clenv.ne_USER);
				if( strpbrk(userb,":@") ){
					bzero(au,sizeof(AuthInfo));
					decomp_siteX("sftp",userb,au);
 sv1log("--USER[%s]:%d @ HOST[%s]:%d\n",
 au->i_user,istrlen(au->i_pass),au->i_Host,au->i_Port);
				}else{
					bzero(au,sizeof(AuthInfo));
					strcpy(au->i_user,clenv.ne_USER);
				}
				return 1;
			    }else{
				timeout = 300;
			    }
			}
		}
	}
	return 0;
}
int service_telnet1(Connection *Conn);
int service_telnet(Connection *Conn)
{
	int rcode;
	rcode = service_telnet1(Conn);
	return rcode;
}
int service_telnet1(Connection *Conn)
{
	if( telnetEnv == 0 )
		telnetEnv = NewStruct(TelnetEnv);

	if( LOG_VERBOSE )
		dump_commands = C_S | S_C;

	if( strncaseeq(DFLT_HOST,"-ssh",4)
	 && (DFLT_HOST[4] == '.' || DFLT_HOST[4] == 0) ){
		ovstrcpy(DFLT_PROTO,"ssh");
		if( DFLT_HOST[4] == 0 )
			strcpy(DFLT_HOST,"-");
		else	ovstrcpy(DFLT_HOST,DFLT_HOST+5);
		DFLT_PORT = 22;
		sv1log(">>>> ssh://%s:%d\n",DFLT_HOST,DFLT_PORT);
	}

	if( BORN_SPECIALIST )
	if( strcmp(iSERVER_PROTO,"telnet") == 0 )
	if( strcmp(DFLT_HOST,"-.-") == 0 ){
		AsServer(Conn);
		return 0;
	}

	/* -l user[@host] */
	if( strcaseeq(DFLT_PROTO,"ssh") )
	if( DFLT_AUTH == 0 ){
		FILE *tc = fdopen(dup(ToC),"w");
		FILE *fc = fdopen(dup(FromC),"r");
		AuthInfo au;
		if( getUSERenv(fc,tc,&au) ){
			if( au.i_Host[0] ){
				strcpy(DFLT_HOST,au.i_Host);
			}
			if( DFLT_AUTH == 0 )
				DFLT_AUTH = (AuthInfo*)malloc(sizeof(AuthInfo));
			*DFLT_AUTH = au;
		}
		fclose(tc);
		fclose(fc);
	}

	if( isMYSELF(DFLT_HOST) ){
		ImProxy = 1;
		if( PollIn(FromC,10) == 0 ){
			/* disable local echo in telnet client on Win95 series,
			 * but don't disable local echo necessary for
			 * non-Telnet protocols.
			 */
			if( telnetonly(Conn) ){
				IGNRETP write(ToC,NOPstr,2);
				scanCommands(DtoC,CVStr(NOPstr),2);
			}
		}
		proxy_telnet(Conn);
		return 0;
	}

	if( CTX_auth(Conn,NULL,NULL) ) /* with AUTHORIZER */
	{
		FILE *fc = fdopen(FromC,"r");
		FILE *tc = fdopen(ToC,"w");
		CStr(auser,256);
		CStr(ahost,MaxHostNameLen);
		int dport = DFLT_PORT;

		IGNRETP write(ToC,NOPstr,2);
		scanCommands(DtoC,CVStr(NOPstr),2);

		auser[0] = ahost[0] = 0;
		DFLT_PORT = 0; /* to escape "already authorized" */
		if( doAUTH0(Conn,fc,tc,"telnet",DST_HOST,dport,AVStr(auser),AVStr(ahost),(iFUNCP)xgetline,NULL) == EOF ){
			return -1;
		}
		DFLT_PORT = dport;
		fcloseFILE(fc);
		fcloseFILE(tc);
	}
	if( streq(DST_PROTO,"ssh") || DST_PORT == 22 ){
		int tos;
		IStr(user,128);
		IStr(pass,128);
		strcpy(user,DFLT_USER);
		strcpy(pass,DFLT_PASS);
		/* see MYAUTH? */

		tos = connectToSsh(Conn,DST_HOST,DST_PORT,user,pass);
		sv1log("SSHGW[%d] %s:%d\n",tos,DST_HOST,DST_PORT);
		if( tos != -1 ){
			ToS = FromS = tos;
		}
	}
	if( ToC < 0 || ToS < 0 )
		connect_to_serv(Conn,FromC,ToC,0);

	if( ToC < 0 || ToS < 0 )
		return -1;

	/* Telnet clients may not start any negotiation when the
	 * target port is not the standard telnet port, because the server
	 * could be a non telnet server.  Telnet relay server is normally
	 * bound to non standard telnet port, thus initiating Telnet
	 * negotiation in the relay will be helpful for clients to notice
	 * that he is connected with telnet server.
	 */
	if( PollIn(FromS,10) == 0 ){
		IGNRETP write(ToC,NOPstr,2);
		scanCommands(DtoC,CVStr(NOPstr),2);
	}
	/*
	{	CStr(buf,3);
		buf[0] = IAC; buf[1] = WILL; buf[2] = O_SUPAHEAD;
		write(ToC,buf,3);
		scanCommands(DtoC,AVStr(buf),3);
	}
	*/
	/*
	bidirectional_relay(Conn,0x2000,0x2000);
	*/
	bidirectional_relay2(Conn,0x2000,0x2000);
	return 0;
}


/*
 *	parse and rewrite telnet protocol
 */

#define EOA		0x100
#define START		0x101
#define LOOP		0x102
#define STR		0x103
#define RW_TERM		0x104
#define RW_XDISPLOC	0x105
#define RW_ENVIRON	0x106
#define RW_NENVIRON	0x107

static short Trans[][32] = {
 { IAC, SB, O_ENVIRON,  IS, START, VALUE, STR, VAR, STR, RW_ENVIRON, LOOP },
 { IAC, SB, O_NENVIRON, IS, START, VAR, STR, VALUE, STR, RW_NENVIRON, LOOP },
 { IAC, SB, O_TERMTYPE, IS, START, STR, RW_TERM,    EOA },
 { IAC, SB, O_XDISPLOC, IS, START, STR, RW_XDISPLOC, EOA },
 0
};

/*
static int getString(PCStr(buf),int cc,int c0,PVStr(str))
*/
static int getString(PCStr(buf),int cc,int c0,int cx,PVStr(str))
{	int ci,si;
	unsigned char ch;

	si = 0;
	for(ci = c0; ci < cc; ci++ ){
		assertVStr(str,str+si+1);
		ch = buf[ci];
		if( ch == cx ){
			/* the next literal char. in Trans[] */
			if( ch == VAR || ch == VALUE )
				break;
		}
		setVStrElemInc(str,si,ch); /**/
		if( ch < ' ' || 0x7F < ch )
			break;
	}
	setVStrEnd(str,si);
	return ci;
}
static int removeString(PVStr(buf),int cc,int from,int to)
{	int len,ci;

	len = to - from;
	for( ci = from; ci < cc; ci++ )
		setVStrElem(buf,ci,buf[ci+len]); /**/
	return -len;
}
static int replaceString(PVStr(buf),int cc,int from,int to,PCStr(xnew))
{	int len,nlen,inc;
	int ci;

	len = to - from;
	nlen = strlen(xnew);
	inc = nlen - len;

	if( 0 < inc ){
		for( ci = cc-1; to <= ci; ci-- ){
			assertVStr(buf,buf+ci+inc);
			setVStrElem(buf,ci+inc,buf[ci]); /**/
		}
	}else{
		for( ci = to;   ci <  cc; ci++ ){
			assertVStr(buf,buf+ci+inc);
			setVStrElem(buf,ci+inc,buf[ci]); /**/
		}
	}
	for( ci = 0; ci < nlen; ci++ ){
		assertVStr(buf,buf+from+ci);
		setVStrElem(buf,from+ci,xnew[ci]); /**/
	}
	return inc;
}

static int rewriteTelnet(int direction,PVStr(buf),int cc)
{	int si,sji,sjp;
	int chp;
	unsigned char chi;
	short *sb1;
	int inc = 0,inc1;
	ACStr(str,4,2048);
	int strx;
	int start_sjp;
	int start_sji;
	int str_sji = 0;

	for( si = 0; ; si++ ){
	    sb1 = Trans[si];
	    if( sb1[0] == 0 )
		break;

	    sji = 0;
	    strx = 0;
	    for( sjp = 0;; sjp++ ){
	        chp = sb1[sjp];
		chi = buf[sji];

		switch( chp ){
		  case EOA:
			goto NEXTALT;

		  case START:
			strx = 0;
			start_sji = sji;
			start_sjp = sjp;
			break;

		  case LOOP:
			sjp = start_sjp -1;
			break;

		  case STR:
			str_sji = sji; /* the beginning of STR */
			sji = getString(buf,cc,sji,sb1[sjp+1],EVStr(str[strx]));
			/*
			sji = getString(buf,cc,sji,EVStr(str[strx]));
			*/
			strx++;
			break;

		  case RW_XDISPLOC:
			if( direction == CtoS )
			if( Xproxy[0] && !streq(Xproxy,str[0]) ){
				sv1log("DISPLAY [%s] -> [%s]\n",str[0],Xproxy);
				inc1 = replaceString(AVStr(buf),cc,start_sji,sji,
					Xproxy);
				inc += inc1;
				sji += inc1;
			}
			break;

		  case RW_ENVIRON:
			sv1log("ENVIRON [%s=%s]\n",str[0],str[1]);

			if( streq(str[0],"DISPLAY") )
			if( direction == CtoS )
			if( Xproxy[0] && !streq(Xproxy,str[1]) ){
				inc1 = replaceString(AVStr(buf),cc,start_sji,sji,
					Xproxy);
				inc += inc1;
				sji += inc1;
			}
			break;

		  case RW_NENVIRON: /* rewriting VALUE STR for DISPLAY */
			sv1log("NEW-ENVIRON [%s=%s]\n",str[0],str[1]);
			if( streq(str[0],"USER") )
			if( direction == CtoS || direction == CtoD )
			{
				clenv.ne_USER = stralloc(str[1]);
				clenv.ne_USER[strlen(str[1])-1] = 0;/*bug*/
			}
			if( streq(str[0],"DISPLAY") )
			if( direction == CtoS )
			if( Xproxy[0] && !streq(Xproxy,str[1]) ){
				sv1log("DISPLAY [%s] -> [%s]\n",str[1],Xproxy);
				inc1 = replaceString(AVStr(buf),cc,str_sji,sji,
					Xproxy);
				inc += inc1;
				sji += inc1;
			}
			break;

		  default:
			if( chp != chi )
				goto NEXTALT;
			sji++;
		}
	    } NEXTALT:;
	}
	return inc;
}

/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2007 National Institute of Advanced Industrial Science and Technology (AIST)
AIST-Product-ID: 2000-ETL-198715-01, H14PRO-049, H15PRO-165, H18PRO-443

Permission to use this material for noncommercial and/or evaluation
purpose, copy this material for your own use,
without fee, is hereby granted
provided that the above copyright notice and this permission notice
appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
//////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	telnetgw.c
Author:		Yutaka Sato <y.sato@delegate.org>
Description:
History:
	071126	created
//////////////////////////////////////////////////////////////////////#*/
#if defined(__KURO_BOX__)
#include <pty.h>
#define Forkpty(pty,name) forkpty(pty,name,NULL,NULL)
#else
int Forkpty(int *pty,char *name);
#endif
int Stty(int fd,const char *mode);
int Gtty(int fd,const char *mode);

char *fgetsTO(PVStr(b),int z,FILE *f,int t1,int t2);
FILE *fopenTO(PCStr(path),PCStr(mode),int timeout);
static const char *ssh_com = "ssh -p %d %s@%s";
static int sshPty = -1;
static int sshPid = 0;
static int sshThread = 0;
static int badPass = 0;

static void relay_resp(FILE *fs,FILE *tc,int timeout,PVStr(resp),PCStr(com)){
	CStr(res,1024);
	refQStr(rp,resp);
	refQStr(dp,res);
	int tout0;
	int tout;

	if( 0 < timeout )
		tout0 = tout = timeout;
	else	tout0 = tout = 3*1000;

	if( resp )
		setVStrEnd(resp,0);
	if( fPollIn(fs,tout) <= 0 ){
		sv1log("--SSH >> response timeout [%s]%d\n",com,tout);
		return;
	}

	for(;;){
		if( 0 < fgetsBuffered(AVStr(res),sizeof(res),fs) ){
		}else
		if( fgetsTO(AVStr(res),sizeof(res),fs,tout,1) == NULL ){
			break;
		}
		if( strchr(res,'\n') )
			sv1log("--SSH >>(%s) %s",com,res);
		else	sv1log("--SSH >>(%s/NO-NL)[%s]\n",com,res);
		if( dp = strpbrk(res,"\r\n") )
			strcpy(dp,"\r\n");
		if( streq(res,"\r\n") || streq(res,"\n") ){
			/* ignore empty lines */
		}else
		if( rp ){
			strcpy(rp,res);
			rp += strlen(rp);
		}
		tout = 1;
	}
}
static void closeAll(){
	int fi;
	int rcode;
	int lfd = curLogFd();
	for( fi = 3; fi < 64; fi++ ){
		if( fi == lfd )
			continue;
		rcode = close(fi);
	}
}
static int badpass(PCStr(resp)){
	if( badPass ){
		if( resp[0] == '\r'
		 || resp[0] == '\n'
		){
			sv1log("--SSH: SKIP in BAD PASS [%s]\n",resp);
			return badPass;
		}
	}
	if( strtailstr(resp,"Password:")
	 || strtailstr(resp,"Password: ")
	 || strtailstr(resp,"password: ")
	 || strstr(resp,"Enter passphrase for key")
	){
		sv1log("--SSH: BAD PASS [%s]\n",resp);
		badPass = 1;
	}else{
		sv1log("--SSH: PASS OK [%s]\n",resp);
		badPass = 0;
	}
	return badPass;
}

int dupLogFd();
void execsystem(PCStr(what),PCStr(pathcom));
static int forkSsh(PCStr(host),int port,PCStr(user),PCStr(pass),int tf[2],FILE *fc,FILE *tc){
	int pid;
	int pty;
	IStr(name,128);
	int slog = LOG_type1;
	LOG_type1 &= ~L_CONSOLE; /* 9.9.8 suppress logging to pty by child */

	if( curLogFd() == fileno(stderr) ){
		dupLogFd(); /* 9.8.2 not to send log-output to pty */
	}
	pid = Forkpty(&pty,(char*)name);
	if( 0 < pid ){
		CStr(resp,0x10000);
		FILE *fs;

		PollIn(pty,3*1000); /* wait response from ssh */
		LOG_type1 = slog; /* LOG_type1 is on memory shared with child */
		sshPid = pid;
		sshPty = pty;
		sv1log("--SSH: pid=%d pty master %d %s\n",sshPid,pty,name);
		tf[0] = pty;
		tf[1] = pty;

		msleep(100);
		fs = fdopen(pty,"r");
		relay_resp(fs,tc,15*1000,AVStr(resp),"FORK-1");
		if( badpass(resp) && *pass ){
			IStr(req,128);
			sprintf(req,"%s\r\n",pass);
			IGNRETP write(pty,req,strlen(req));
			relay_resp(fs,tc,15*1000,AVStr(resp),"FORK-2");
			badpass(resp);
		}
		fprintf(tc,"%s",resp);
		fflush(tc);
		return 0;
	}else{
		CStr(com,1024);
		int rcode;
		sprintf(com,"");
		Xsprintf(TVStr(com),ssh_com,port,user,host);
		sv1log("--SSH: %s\n",com);

		closeAll();
		rcode = Stty(0,"-echo,-echonl");
		execsystem("ssh",com);
		printf("ssh exec(%s) failed\n",com);
		_exit(0);
		return 0;
	}
}
static void setpty(int pty,FILE *tc){
	IStr(com,128);
	sv1log("----STTY I%X O%X L%X C%X\n",
		Gtty(pty,"iflags"),Gtty(pty,"oflags"),
		Gtty(pty,"lflags"),Gtty(pty,"cflags"));

	Stty(pty,"-echo"); // BSD

	sprintf(com,"stty echo\n");
	IGNRETP write(pty,com,strlen(com)); // for FedoraCore and SSH/Cygwin
	/* shoul skip the response */

	Stty(pty,"icrnl");
	putIAC(tc,WILL,O_SUPAHEAD); fflush(tc);
	putIAC(tc,DONT,O_ECHO); fflush(tc);
	putIAC(tc,WILL,O_ECHO); fflush(tc);
	putIAC(tc,DO,O_NAWS); /* initiate negotiation for WindowSize */
}
int getwinsize(int fd,int *row,int *col);
int setwinsize(int fd,int row,int col);
static void syncpty(int pty,FILE *tc){
	/*
	int row,col;
	row = col = 0;
	getwinsize(pty,&row,&col);
	fprintf(stderr,"----STTY I%X O%X L%X C%X WinSize=%d,%d\n",
		Gtty(pty,"iflags"),Gtty(pty,"oflags"),
		Gtty(pty,"lflags"),Gtty(pty,"cflags"),
		row,col);
	*/
}
static int setWinSize(int pty,FILE *tc,unsigned PCStr(ub),int rcc){
	int i,ocol,orow,col,row,nrow,ncol;
	if( ub[1] == WILL || ub[1] == SB )
	if( ub[2] == O_NAWS ){
		if( ub[1] == SB ){
			col = ub[4];
			row = ub[6];
		}else{
			col = ub[7];
			row = ub[9];
		}
		getwinsize(pty,&orow,&ocol);
		setwinsize(pty,row,col);
		//setwinsize(pty,row-1,col-1); // for SSH/Cygwin??
		nrow = ncol = 0;
		getwinsize(pty,&nrow,&ncol);
		/*
		for(i = 0; i < rcc; i++)
			fprintf(stderr,"[%2d] %02X/%3d\n",i,ub[i],ub[i]);
		*/
		sv1log("----WinSize [%d,%d][%d,%d][%d,%d]\n",
			ocol,orow,col,row,ncol,nrow);
		return 1;
	}
	return 0;
}
static int relay1(FILE *tc,int fs,int ts,int cl){
	int fdv[2];
	int rdv[2];
	int rdy,rcc,wcc;
	CStr(buf,1024+1);
	const unsigned char *ub = (const unsigned char*)buf;
	int xpid;
	int rcode;

	fdv[0] = cl;
	fdv[1] = fs;

	if( badPass ){
		Stty(sshPty,"-echo");
		putIAC(tc,WILL,O_ECHO);
		putIAC(tc,DONT,O_ECHO);
		fflush(tc);
	}else{
		setpty(sshPty,tc);
	}
	for(;;){
		rdy = PollIns(IO_TIMEOUT*1000,2,fdv,rdv);
		syncpty(sshPty,tc);

		if( rdy <= 0 ){
			break;
		}
		if( rdv[0] ){ /* from client */
			rcc = read(fdv[0],buf,sizeof(buf)-1);
			if( rcc <= 0 ) break;
			if( 2 <= rcc && ub[rcc-2] == '\r' && ub[rcc-1] == 0 ){
				sv1log("C-S CR %d [%X][%d]\n",rcc,ub[0],ub[1]);
				rcc--;
			}
			if( ub[0] == 0xFF ){
				if( setWinSize(sshPty,tc,ub,rcc) ){
				}else
				if( ub[1] == DO && ub[2] == O_SUPAHEAD ){
					sv1log("C-S %d DO SUPGA\n",rcc);
					putIAC(tc,WILL,O_SUPAHEAD);
				}else
				if( ub[1] == DO && ub[2] == O_ECHO ){
					sv1log("C-S %d DO ECHO\n",rcc);
					/*
					Stty(sshPty,"echo,echonl");
					*/
					putIAC(tc,WILL,O_ECHO);
				}else{
					fprintf(stderr,"C-S %d [%X][%d][%d]\n",
						rcc,ub[0],ub[1],ub[2]);
				}
				fflush(tc);
				continue;
			}
			/* ... scan Telnet command and erase ... */
			wcc = write(ts,buf,rcc);
			if( wcc <= 0 ) break;
		}
		if( rdv[1] ){ /* from ssh */
			rcc = read(fdv[1],buf,sizeof(buf)-1);
			if( rcc <= 0 ) break;
			wcc = write(cl,buf,rcc);
			if( wcc <= 0 ) break;
			if( 1 <= rcc && ub[rcc-1] == '\n' )
			if( rcc == 1 || ub[rcc-2] != '\r' )
			{
				sv1log("S-C NL to LF-CR %d\n",rcc);
				IGNRETP write(cl,"\r",1);
			}
			if( 1 <= rcc && ub[rcc-1] == '\r' ){
				sv1log("S-C CR to NL %d\n",rcc);
				IGNRETP write(cl,"\n",1);
			}
			if( badPass ){
				setVStrEnd(buf,rcc);
				if( !badpass(buf) ){
					setpty(sshPty,tc);
				}
			}
		}
	}
	close(fs);
	if( fs != ts ) close(ts);
	close(cl);
	xpid = NoHangWait();
	return 0;
}
static int relay0(PCStr(host),int port,PCStr(user),PCStr(pass),int cl){
	int sshv[2]; /* to the pty of ssh */
	FILE *fc;
	FILE *tc;
	AuthInfo au;

	fc = fdopen(cl,"r");
	tc = fdopen(cl,"w");
	if( user[0] == 0 || host[0] == 0 || streq(host,"-") ){
		if( getUSERenv(fc,tc,&au) ){
			if( au.i_user[0] ) user = au.i_user;
			if( au.i_pass[0] ) pass = au.i_pass;
			if( au.i_Host[0] ) host = au.i_Host;
			if( au.i_Port    ) port = au.i_Port;
		}else{
 sv1log("--USER not given\n");
 fprintf(tc,"*** Send the user name as:\r\n");
 fprintf(tc,"*** %% telnet -l UsrName delegate-host\r\n");
			fclose(tc);
			fclose(fc);
			return 0;
		}
	}
	forkSsh(host,port,user,pass,sshv,fc,tc);
	relay1(tc,sshv[0],sshv[1],cl);
	return 0;
}
int connectToSsh(Connection *Conn,PCStr(host),int port,PCStr(user),PCStr(pass)){
	int sockv[2];
	int nready;
	int err;

	if( sshThread ){
		err = thread_wait(sshThread,1000);
		Verbose("--PrevThread %X err=%d\n",sshThread,err);
		sshThread = 0;
	} 
	if( sshPty != -1 ){
		err = close(sshPty);
		Verbose("--PrevPty %d err=%d\n",sshPty,err);
		sshPty = -1;
	}
	if( sshPid ){
		int xpid;
		xpid = NoHangWait();
		Verbose("--PrevPid %d %d\n",sshPid,xpid);
		sshPid = 0;
	}
	badPass = 0;
	Socketpair(sockv);
	sshThread = thread_fork(0x40000,STX_tid,"relay0",(IFUNCP)relay0,host,port,user,pass,sockv[0]);
	nready = PollIn(sockv[1],15*1000);
	return sockv[1];
}
