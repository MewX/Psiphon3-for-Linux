/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2006 National Institute of Advanced Industrial Science and Technology (AIST)

Permission to use this material for noncommercial and/or evaluation
purpose, copy this material for your own use, and distribute the copies
via publicly accessible on-line media, without fee, is hereby granted
provided that the above copyright notice and this permission notice
appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:   program/C; charset=US-ASCII
Program:        dgsign.c
Author:         Yutaka Sato <ysato@delegate.org>
Description:

History:
        060924	extracted from dgauth.c
//////////////////////////////////////////////////////////////////////#*/
#include <ctype.h>
#include <errno.h>
#include "delegate.h"
#include "file.h"
#include "credhy.h"
#include "auth.h"
#include "param.h"

int AuthFunc(DGCTX,void*faddr,PCStr(FIle),int Line);
#define iAuthFunc(f) if(AuthFunc(Conn,(void*)f,__FILE__,__LINE__)<0)return -1

char *getUsername(int uid,PVStr(name));
char *getGroupname(int gid,PVStr(name));

int enCreysX(PCStr(opts),PCStr(pass),PCStr(str),int len,PVStr(estr),int esiz);
int enCreys(PCStr(opts),PCStr(pass),PCStr(str),PVStr(estr),int esiz);
int deCreys(PCStr(opts),PCStr(pass),PCStr(str),PVStr(dstr),int dsiz);
const char *funcName(void *func);
const void *funcFunc(PCStr(func));
const char *getEXEC_PATH();
char *fgetsE(PVStr(str),int siz,FILE *fp);
int fputsE(PCStr(str),FILE *fp);
int offE(PCStr(str),PCStr(ptr));

#ifndef ADMIN
#define ADMIN	"none@nowhere"
#endif

extern const char *DELEGATE_pubkey;
int DGverify(PCStr(sign)){
	return 0;
}

int md5_main(int ac,char *av[]);
int addMD5fp(MD5 *md5,FILE *fp){
	CStr(buf,8*1024);
	int rcc;
	int siz = 0;

	while( 0 < (rcc = fread(buf,1,sizeof(buf),fp)) ){
		siz += rcc;
		addMD5(md5,buf,rcc);
	}
	return siz;
}
int addMD5fptxt(MD5 *md5,FILE *fp){
	CStr(buf,8*1024);
	int rcc;
	int siz = 0;
	int off = 0;

	while( fgets(buf,sizeof(buf),fp) != NULL ){
		rcc = strlen(buf);
		if( strstr(buf,"\"DIGEST-OFF\"") ){
			off = 1;
			break;
		}
		addMD5(md5,buf,rcc);
		siz += rcc;
	}
	return siz;
}
int addMD5file(MD5 *md5,PCStr(fname)){
	FILE *fin;
	CStr(fnameb,1024);

	if( strpbrk(fname,"\r\n") ){
		Xsscanf(fname,"%[^\r\n]",AVStr(fnameb));
		fname = fnameb;
	}
	if( fin = fopen(fname,"r") ){
/*
static int i; fprintf(stderr,"--- %d %s\n",++i,fname);
*/
		if( strtailstrX(fname,".c",1) || strtailstrX(fname,".h",1) )
			addMD5fptxt(md5,fin);
		else	addMD5fp(md5,fin);
		fclose(fin);
		return 0;
	}else{
		return -1;
	}
}
static int Opt_v;
int MD5_mainX(int ac,const char *av[],FILE *afls,PVStr(out),FILE *log){
	int ai;
	int fi;
	int fc = 0;
	FILE *fls;
	CStr(fnam,256);
	MD5 *md5;
	CStr(digest,64);

	for( ai = 1; ai < ac; ai++ ){
		if( streq(av[ai],"-c") ){
			fc = 1;
		}else
		if( streq(av[ai],"-f") ){
			if( ai+1 < ac ){
				ai++;
				fc = 1;
			}
		}else
		if( av[ai][0] != '-' ){
		}
	}
	if( afls == 0 && fc == 0 ){
		return md5_main(ac,(char**)av);
	}

	md5 = newMD5();
	if( afls ){
		int an = 0;
		const char *dp;
		ai = 0;
		while( fgets(fnam,sizeof(fnam),afls) ){
			if( Opt_v ){
				fprintf(stderr,"[%3d/%3d] %X %s",an,ai++,
					0xFF&*(char*)md5,fnam);
			}
			if( dp = strrpbrk(fnam,"/\\") ){
				dp++;
			}else{
				dp = fnam;
			}
			if( *dp == '.' ){
				continue;
			}
			an++;
			addMD5file(md5,fnam);
		}
	}
	for( ai = 1; ai < ac; ai++ ){
		if( streq(av[ai],"-f") ){
			if( ai+1 < ac ){
				ai++;
				if( streq(av[ai],"-") )
					fls = stdin;
				else	fls = fopen(av[ai],"r");
				if( fls ){
					while( fgets(fnam,sizeof(fnam),fls) ){
						addMD5file(md5,fnam);
					}
					if( fls != stdin )
						fclose(fls);
				}else{
				}
			}
		}else{
			addMD5file(md5,av[ai]);
		}
	}
	endMD5(md5,digest);
	MD5toa(digest,(char*)out);
	return 0;
}
int MD5_main(int ac,const char *av[]){
	int code;
	CStr(md5,64);

	truncVStr(md5);
	code = MD5_mainX(ac,av,NULL,AVStr(md5),stderr);
	if( md5[0] ){
		printf("%s\n",md5);
	}
	return code;
}
int cafe_mainX(int ac,const char *av[],FILE *out,FILE *log);
void sort_file(FILE *src,FILE *dst,int rev);
const char *DELEGATE_srcsign();
int srcmd5_main(int ac,const char *av[]){
	int ai;
	const char *nav[1024];
	int nac;
	FILE *tmp;
	FILE *tmp2;
	CStr(md5,128);
	int csrc = 0;
	int simple = 0;
	const char *ofile = 0;
	FILE *ofp = stdout;
	int overb = 0;

	nac = 0;
	nav[nac++] = "-Ffind";
	for( ai = 1; ai < ac && ai < elnumof(nav)-2; ai++ ){
		if( strncmp(av[ai],"-csrc",5) == 0 ){
			csrc = 1;
			continue;
		}
		if( streq(av[ai],"-v") ){
			Opt_v = 1;
			overb = 1;
			continue;
		}
		if( streq(av[ai],"-f") ){
			if( ai+1 < ac ){
				FILE *fp;
				CStr(line,128);
				refQStr(lp,line);
				ai++;
				if( fp = fopen(av[ai],"r") ){
					while( fgets(line,sizeof(line),fp) ){
						if( elnumof(nav)-2 <= nac )
							break;
						if( lp = strpbrk(line,"\r\n") )
							setVStrEnd(lp,0);
						if( *line )
						nav[nac++] = stralloc(line);
					}
					fclose(fp);
				}
			}
			continue;
		}
		if( streq(av[ai],"-s") ){
			simple = 1;
			continue;
		}
		if( streq(av[ai],"-o") ){
			if( ai+1 < ac ){
				ofile = av[++ai];
			}
			continue;
		}
		nav[nac++] = av[ai];
	}
	nav[nac++] = "-print";
	nav[nac] = 0;
	if( overb ){
		for( ai = 0; ai < nac; ai++ ){
			fprintf(stderr,"[%d] %s\n",ai,nav[ai]);
		}
	}

	tmp = TMPFILE("srcmd5");
	cafe_mainX(nac,nav,tmp,stderr);
	fflush(tmp);
	fseek(tmp,0,0);
	tmp2 = TMPFILE("srcmd5");
	sort_file(tmp,tmp2,0);
	fclose(tmp);

	fflush(tmp2);
	fseek(tmp2,0,0);
	truncVStr(md5);
	MD5_mainX(0,NULL,tmp2,AVStr(md5),stderr);
	fclose(tmp2);

	if( simple ){
		fprintf(ofp,"%s\n",md5);
	}else
	if( csrc ){
		CStr(sdate,128);
		CStr(sign,512);
		const char *ver = DELEGATE_ver();
		const char *fname = "BUILT_SRCSIGN";
		if( ofile ){
			FILE *fp;
			if( fp = fopen(ofile,"w") )
				ofp = fp;
		}
		StrftimeLocal(AVStr(sdate),sizeof(sdate),"%Y%m%d%H%M%S%z",
			time(0),0);
		fprintf(stderr,"source MD5 = %s\n",md5);
		setVStrEnd(md5,16);
		/*
		sprintf(sign,"{%s=%s:%s:%s:%s:-}","BLDSIGN",ver,sdate,md5,
		*/
		sprintf(sign,"{%s\\075%s:%s:%s:%s:-}","BLDSIGN",ver,sdate,md5,
			ADMIN);
		fprintf(ofp,"#define %s \"\\n\\\n%s\\n\"+%d\n",fname,sign,10);
	}else{
		CStr(smd5,128);
		printf("source MD5 = %s\n",md5);
		Xsscanf(DELEGATE_srcsign(),"%*[^:]:%*[^:]:%[^:]",AVStr(smd5));
		if( strstr(md5,smd5) ){
printf("*** OK, this is the original source from DeleGate.ORG\n");
		}else{
printf("*** BAD, spoofed or forged, not original code by DeleGate.ORG\n");
		}
	}
	return 0;
}
int binmd5_main(int ac,const char *av[]){
	CStr(path,1024);
	CStr(rbuf,1024);
	int rcc;
	FILE *fp;
	MD5 *md5;
	CStr(digest,64);
	CStr(bmd5,64);

	strcpy(path,EXEC_PATH);
	FullpathOfExe(AVStr(path));
	if( fp = fopen(path,"r") ){
		md5 = newMD5();
		while( 0 < (rcc = fread(rbuf,1,sizeof(rbuf),fp)) ){
			addMD5(md5,rbuf,rcc);
		}
		endMD5(md5,digest);
		MD5toa(digest,(char*)bmd5);
		printf("%s\n",bmd5);
		fclose(fp);
	}
	return 0;
}
int file_md5(FILE *fp,PVStr(bmd5)){
	MD5 *md5;
	int rcc;
	CStr(rbuf,1024);
	CStr(digest,64);

	md5 = newMD5();
	while( 0 < (rcc = fread(rbuf,1,sizeof(rbuf),fp)) ){
		addMD5(md5,rbuf,rcc);
	}
	endMD5(md5,digest);
	MD5toa(digest,(char*)bmd5);
	return 0;
}


/*
 * built-in parameters
 * Compiled-By:
 * Approved-By:
 * Signed-By:
 * ADMIN=
 * OWNER= 
 * RELIABLE=
 * DGROOT=
 */

int rsasign_main(int ac,const char *av[]){
	int ok;
	const char *pass;

	return 0;
}

int pubDecyptRSA(PCStr(pubkey),int len,PCStr(enc),PVStr(dec));
static int rsadecode(PCStr(pubkey),PCStr(sig),PVStr(ysig)){
	CStr(xsig,1024);
	int xlen;
	int ylen;

	setVStrEnd(ysig,0);
	xlen = str_from64(sig,strlen(sig),AVStr(xsig),sizeof(xsig));
	ylen = pubDecyptRSA(pubkey,xlen,xsig,AVStr(ysig));
	if( 0 <= ylen ){
		setVStrEnd(ysig,ylen);
	}else{
		setVStrEnd(ysig,0);
	}
	return ylen;
}
int dgpubDecryptRSA(PCStr(pubkey),PCStr(ssign),PVStr(osign)){
	int len;
	if( pubkey == 0 )
		pubkey = DELEGATE_pubkey;
	len = rsadecode(pubkey,ssign,BVStr(osign));
	return len;
}

static void rsavrfy1(PCStr(pubkey),PCStr(xsig),int xlen){
	CStr(sig,1024);
	CStr(ysig,1024);
	int slen;
	int dlen;

	slen = str_from64(xsig,xlen,AVStr(sig),sizeof(sig));
	dlen = pubDecyptRSA(pubkey,slen,sig,AVStr(ysig));
	if( 0 <= dlen ){
		setVStrEnd(ysig,dlen);
		printf("%s\n",ysig);
	}
}
int rsavrfy_main(int ac,const char *av[]){
	int ai;
	CStr(xsig,1024);
	int xlen;
	const char *pubkey = DELEGATE_pubkey;
	const char *a1;
	FILE *fp;
	int nput = 0;

	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		nput++;
		fp = fopen(a1,"r");
		if( fp == NULL ){
			fprintf(stderr,"Cannot open: %s\n",a1);
			break;
		}
		xlen = fread(xsig,1,sizeof(xsig),fp);
		fclose(fp);
		rsavrfy1(pubkey,xsig,xlen);
	}
	if( nput == 0 ){
		xlen = fread(xsig,1,sizeof(xsig),stdin);
		rsavrfy1(pubkey,xsig,xlen);
	}
	return 0;
}

typedef struct {
	int s_flags;
	int s_off;	/* offset in the file of the appearence */
	int s_from;
	int s_to;
	MStr(s_name,64);
	MStr(s_ver,64);
	MStr(s_date,64);
	MStr(s_md5,64);
	MStr(s_signer,64);
	MStr(s_sign,256);
	MStr(s_signb,1024);
	MStr(s_signx,256);
} FileSign;

#define FS_GOT		1
#define FS_NOCHECK	2

static const char *sprintSign(PVStr(sign),FileSign *sig){
	sprintf(sign,"{%s=%s:%s:%s:%s:%s}",
		sig->s_name,sig->s_ver,sig->s_date,sig->s_md5,
		sig->s_signer,sig->s_sign
	);
	return sign+strlen(sign);
}

static int scanFileSign(PCStr(sign),FileSign *fsig){
	int ne;
	refQStr(sp,fsig->s_signer);

	if( *sign == '{' ){
		ne = Xsscanf(sign,"{%[^=]",AVStr(fsig->s_name));
		sign += 1 + strlen(fsig->s_name) + 1;
	}
	ne += scan_Lists5(sign,':',
		fsig->s_ver,
		fsig->s_date,
		fsig->s_md5,
		fsig->s_signer,
		fsig->s_sign);

	if( 4 <= ne ){
		strsubst(AVStr(fsig->s_sign),"`M",""); /* "\r" by fgetsE() */
		fsig->s_flags |= FS_GOT;
		return ne;
	}
	fsig->s_flags &= ~FS_GOT;
	return -1;
}
static void printSign(FILE *out,FileSign *sig,PCStr(head)){
	FileSign psig;
	psig = *sig;
	setVStrEnd(psig.s_date,10);
	setVStrEnd(psig.s_md5,16);
	fprintf(out,"%s%s %s %s (%s)\n",head,
		psig.s_ver,
		psig.s_date,
		psig.s_md5,
		psig.s_signer);
}

/*
 * "{NOSIGN: ... }"
 * "{NOSIGN: ...
 * ...
 * }"
 */
#define MAXIMPSIZE	32*1024
static int findNOSIGN(FILE *ifp,FILE *ofp,PCStr(name),int *fromp,int *top,int change,int fsilent,int fverb){
	CStr(buf,MAXIMPSIZE);
	refQStr(dp,buf);
	refQStr(ep,buf);
	int off;
	int from = -1;
	int to = 0;
	int off1;
	int nlen = strlen(name);

	while( 1 ){
		off = ftell(ifp);
		if( fgetsE(AVStr(buf),sizeof(buf),ifp) == NULL ){
			break;
		}
		if( ofp ){
			fputsE(buf,ofp);
		}
		if( (dp = strstr(buf,"\"{NOSIGN")) && dp[8] == ':'
		 && strneq(dp+8+1,name,nlen) ){
 if( !fsilent )
 fprintf(stderr,"   ---- %sIMPLANTED CONFIGURATION ----\n",change?"OLD ":"");
			from = off + offE(buf,dp+8+1+nlen);
			if( ep = strstr(dp,"}\"") ){
				off1 = offE(buf,ep);
				if( 0 < off1 ){
					to = off + off1;
				}
			}else{
				truncVStr(dp);
				to = ftell(ifp);
				for(;;){
					if( fgetsE(AVStr(buf),sizeof(buf),ifp) == NULL )
						break;
					if( ofp ){
						fputsE(buf,ofp);
					}
					if( dp = strstr(buf,"}\"") ){
						if( buf < dp ){
							off1 = offE(buf,dp);
							if( 0 < off1 ){
								to += off1;
							}
						}
						break;
					}
					to = ftell(ifp);
				}
			}
 if( !fsilent && fverb )
 fprintf(stderr,"#### read [%X - %X](%d)\n",from,to,to-from);
			*fromp = from;
			*top = to;
		}
	}
	if( 0 <= from && 0 < to ){
		int bcc,rcc;
		CStr(buf,MAXIMPSIZE);
		bcc = to - from;
		fseek(ifp,from,0);
		rcc = fread(buf,1,QVSSize(buf,bcc),ifp);
		setVStrEnd(buf,rcc);
		return to - from;
	}
	return 0;
}

#define SIG_EXE		1
#define SIG_FILE	2
#define SIG_ALL		3
int sslway_dl();

static void getsigns(PCStr(iexe),int fovw,int fverb,FILE *ifp,FILE *ofp,FileSign *ssig,FileSign *bsig,FileSign *fsig,MD5 *md5,PVStr(xd),int fsilent,int whsig){
	int off;
	int nlen;
	IStr(buf,1024);
	refQStr(dp,buf);
	refQStr(ep,buf);
	CStr(digest,32);
	IStr(sigs,128);

	/*
	if( iexe ){
		int size;
		int date;
		IStr(stim,128);
		size = File_size(iexe);
		date = File_mtime(iexe);
		StrftimeLocal(AVStr(stim),sizeof(stim),"%Y/%m/%d",date,0);
		fprintf(stderr,"## %s: %d %s\n",iexe,size,stim);
	}
	*/
	while( 1 ){
		off = ftell(ifp);
		if( fgetsE(AVStr(buf),sizeof(buf),ifp) == NULL ){
			break;
		}
		if( (dp = strstr(buf,"\"{NOSIGN")) && dp[8] == ':' ){
			if( ofp ){
				fputsE(buf,ofp);
			}
			if( ep = strstr(dp,"}\"") ){
				strcpy(dp,ep+2);
			}else{
				truncVStr(dp);
				if( md5 ){ addMD5(md5,buf,strlen(buf)); }
				while( fgetsE(AVStr(buf),sizeof(buf),ifp) ){
					if( ofp ){
						fputsE(buf,ofp);
					}
					if( dp = strstr(buf,"}\"") ){
				if( md5 ){ addMD5(md5,dp+2,strlen(dp+2)); }
						break;
					}
				}
				continue;
			}
		}else
		if( (dp = strstr(buf,"{SRCSIGN")) && dp[8] == '=' ){
			if( ofp ){
				fputsE(buf,ofp);
			}
			if( strchr(buf,'}') == 0 ){
				refQStr(bp,buf);
				int ch;
				bp = buf + strlen(buf);
				while( (ch = getc(ifp)) != EOF ){
					if( ofp ){
						putc(ch,ofp);
					}
					setVStrPtrInc(bp,ch);
					if( ch == '}' ){
						setVStrPtrInc(bp,0);
						break;
					}
				}
			}
			strsubst(AVStr(dp),"\r","");
			strsubst(AVStr(dp),"\n","");
			scanFileSign(dp,ssig);
		}else
		if( (dp = strstr(buf,"{BLDSIGN")) && dp[8] == '=' ){
			if( ofp ){
				fputsE(buf,ofp);
			}
			scanFileSign(dp,bsig);
		}else
		if( (dp = strstr(buf,"{EXESIGN" )) && dp[nlen=8] == '='
		 || (dp = strstr(buf,"{FILESIGN")) && dp[nlen=9] == '='
		    && (fsig->s_flags & FS_GOT) == 0
		){
			fsig->s_from = off + offE(buf,dp+nlen+1);
			fsig->s_to = off + offE(buf,strchr(buf,'}'));
			scanFileSign(dp,fsig);

			strcpy(fsig->s_signb,buf);
			if( ep = strchr(fsig->s_signb,'}') ){
				((char*)ep)[1] = 0;
			}
			if( ofp != 0 ){
				fsig->s_off = ftell(ofp);
				if( fverb )
					fprintf(stderr,"%s\n",fsig->s_signb);
			}else{
				if( fverb )
					printf("%s\n",fsig->s_signb);
				if( md5 == 0 )
					break;
			}
			if( ofp ){
				fputsE(buf,ofp);
			}
			if( ep = strchr(dp,'}') ){
				strcpy(dp,ep+1);
			}
		}else{
			if( ofp ){
				fputsE(buf,ofp);
			}
		}
		if( md5 ){ addMD5(md5,buf,strlen(buf)); }
	}

	if( ssig->s_flags & FS_GOT )
	if( (ssig->s_flags & FS_NOCHECK) == 0 ){
		CStr(ssign,512);
		CStr(osign,512);

		truncVStr(ssign);
		Xsscanf(ssig->s_sign,"%[0-9A-Za-z+/=]",AVStr(ssign));
		rsadecode(DELEGATE_pubkey,ssign,AVStr(osign));
		strcpy(ssig->s_signx,osign);
		if( fsilent == 2 ){
		}else
		if( osign[0] ){
			FileSign osig;
			bzero(&osig,sizeof(FileSign));
			scanFileSign(osign,&osig);
			printSign(stderr,&osig,"-- src Sign> ");
		}else{
			fprintf(stderr,"-- src Sign? %s:%s:%s:%s\n",
				ssig->s_ver,ssig->s_date,ssig->s_md5,
				ssig->s_signer);
		}
	}

	if( bsig->s_name[0] )
	if( fsilent == 2 ){
		Xsprintf(TVStr(sigs),"%s",bsig->s_md5);
		setVStrEnd(sigs,4);
	}else
	if( (bsig->s_flags & FS_NOCHECK) == 0 ){
		printSign(stderr,bsig,"-- bld Sign> ");
		if( strstr(ssig->s_signx,bsig->s_md5) == NULL )
 fprintf(stderr,"** NG, this executable is not built from the original code: %s\n",(iexe && *iexe)?iexe:"-");
	}

	if( md5 ){
		endMD5(md5,digest);
		MD5toa(digest,(char*)xd);

		if( fsig->s_flags & FS_GOT )
		if( fsilent == 2 ){
		}else
		if( (fsig->s_flags & FS_NOCHECK) == 0 ){
			CStr(ssign,512);
			CStr(osign,512);
			const char *ftype;

			if( streq(fsig->s_name,"EXESIGN") )
				ftype = "executable";
			else	ftype = "file";

			truncVStr(ssign);
			Xsscanf(fsig->s_sign,"%[0-9A-Za-z+/=]",AVStr(ssign));
			rsadecode(DELEGATE_pubkey,ssign,AVStr(osign));
			if( !fsilent ){
				if( osign[0] ){
					FileSign osig;
					bzero(&osig,sizeof(FileSign));
					scanFileSign(osign,&osig);
					printSign(stderr,&osig,"-- exe Sign> ");
				}else{
					printSign(stderr,fsig,"-- exe Sign? ");
				}
			}
			if( strstr(osign,xd) ){
 fprintf(stderr,"** OK, this %s is as released from %s",ftype,fsig->s_signer);
			}else{
				if( ofp == 0 )
					printf("-- File MD5: %s\n",xd);
				else	fprintf(stderr,"-- File MD5: %s\n",xd);

	if( !fovw )
	if( osign[0] == 0 )
	    if( sslway_dl() <= 0 )
 fprintf(stderr,"** NG, cannot verify this %s (RSA lib. unavailable)",ftype);
	    else
 fprintf(stderr,"** NG, this %s is not signed",ftype);
	else
 fprintf(stderr,"** BAD, possibly spoofed or forged %s [%s]",ftype,osign);

			}
			if( strstr(osign,xd) || !fovw ){
				if( *iexe )
					fprintf(stderr,": %s\n",iexe);
				else	fprintf(stderr,"\n");
			}
		}else{
			printf("-- File MD5: %s\n",xd);
		}
	}
	if( fsilent == 2 ){
		if( sigs[0] )
			printf("%s\n",sigs);
		else	printf("(none)\n");
	}
}

/*
 * EXECAUTH/EXECPASS can be AUTHORIZER=as:sudo/MYAUTH=u:p:sudo
 * SUDOAUTH/SUDOPASS can be AUTHORIZER=as:exec/MYAUTH=u:p:exec
 */

char funcFimp[] = "-Fimp";
int ttyuid(int fd);

#ifdef _MSC_VER
int getcuser(PVStr(name),int size,PVStr(domain),int dsiz);
int getowner(PCStr(path),PVStr(owner),int osiz,PVStr(group),int gsiz);
char *myName(PVStr(name),int osiz){
	IStr(group,128);
	strcpy(name,"?");

	getcuser(BVStr(name),osiz,AVStr(group),sizeof(group));
	return (char*)name;
}
#else
char *myName(PVStr(name),int size){
	const char *user;
	int uid,tuid;

	if( (uid = getuid()) == 0 ){
		if( 0 < (tuid = ttyuid(0)) ){
			getUsername(tuid,BVStr(name));
			return (char*)name;
		}
		if( (user = getenv("USER")) && !streq(user,"root") )
			return strcpy(name,user);
		if( (user = getenv("LOGNAME")) && !streq(user,"root") )
			return strcpy(name,user);
	}
	getUsername(getuid(),BVStr(name));
	return (char*)name;
}
int getowner(PCStr(path),PVStr(owner),int osiz,PVStr(group),int gsiz){
	int uid;
	int gid;
	int got = 0;

	if( owner ){
		strcpy(owner,"?");
		uid = File_uid(path);
		if( uid != -1 ){
			getUsername(uid,BVStr(owner));
			got |= 1;
		}
	}
	if( group ){
		strcpy(group,"?");
		gid = File_gid(path);
		if( gid != -1 ){
			getGroupname(gid,BVStr(group));
			got |= 2;
		}
	}
	return got;
}
#endif

static void putEmbedHelp(FILE *out,int ac,const char *av[],int detail){
 CStr(com,256);
 CStr(me,256);
 CStr(greeting,256);
 if( strneq(av[0],"-F",2) )
	sprintf(com,"%s %s",main_argv[0],av[0]);
 else	sprintf(com,"delegated %s",funcFimp);

 fprintf(out,
"---- Implanted Configuration Parameters in the Executable File ----\n");
 fprintf(out,"Usage: %s [xfile] [-w password] [-u users] [-m] [-a args]\n",com);

 if( detail )
 fprintf(out,"\
   xfile  ...  the executable file to be read/written [self]\n\
   -o ofile    write to a new executable file\n\
   -k[key]     encrypt the implanted configuration with a (new) key\n\
   -w pass     password for SU operations (as bind(80),PAM,etc.)\n\
   -u users    list of users to be permitted SU operations [root,owner]\n\
   -c sucaps   list of SU operations to be capable\n\
   -m          chown(root)+chmod(ug+s) to enable \"set-uid-on-exec\"\n\
   -W pass     password to invoke this delegated \n\
   -U users    list of users to be permitted to invoke [*] \n\
   -C caps     list of protocols/functions to be capable [*] \n\
   users  ...  a list of user/group as \"usr1,usr2,/grp1,/grp2\"\n\
   caps   ...  a list of capable protocol (ex. http) or function (ex. Fkill)\n\
   -z          clear all of implanted configurations\n\
   -zX         reset the option -X to the default (ex. -zk -zw -zu -zc -zm)\n\
   -zNAME      clear all of implanted NAME=value \n\
   --X elem    exclude the elem from the list (for -u -c -U -C) \n\
   -e          edit the configuration with an external text editor\n\
   -s file     save the configuration into the file\n\
   -l file     load the configuration from the file\n\
   -a args     a list of arbitrary arguments of DeleGate (as -u -z ...)\n\
   NAME=value  implant the parameter (ADMIN,DGROOT,OWNER,LDPATH,SERVER,...) \n\
   -Pport      implant -Pport\n\
   -h          show help\n");

 if( detail ){
	myName(AVStr(me),sizeof(me));
	sprintf(greeting,"Hi %s",me);
 }else{
	sprintf(greeting,"Use -h to show help");
 }
 fprintf(out,"\
                                   @ @  { %s }\n\
                                  ( - ) %s\n",greeting,DELEGATE_ver());

 if( detail )
 fprintf(out,"\
Example:\n\
   %% %s -w password ADMIN=user@host.domain\n\
   %% sudo %s -m\n\
   \n",com,com);
}

#define _P_IMPORIG	"_IMPORIG" /* original owner and mode */
#define _P_IMPLAST	"_IMPLAST"
int getBconfig1(PCStr(ckey),PCStr(bconf),int mac,const char *av[],PVStr(conf),int csiz,int edit);
int File_mod(PCStr(path));

#ifndef ETXTBSY
#define ETXTBSY -1
#endif

int asFunc(PCStr(arg1));
int paramX(PCStr(param),int nameonly);
int isSucap(PCStr(caps));
void lsFuncs(FILE *out);
void lsProtos(FILE *out);
void lsParams(FILE *out);
void lsSucaps(FILE *out);

static scanListFunc cap1(PCStr(cap)){
	if( *cap == '-' )
		cap++;
	if( *cap == '_' ){
		if( streq(cap,"_all") )
			return 0;
		return isSucap(cap+1);
	}else
	if( *cap == 'F' && islower(cap[1]) ){
		if( streq(cap,"Fall") )
			return 0;
		if( asFunc(cap+1) <= 0 ){
			fprintf(stderr,"Unknown function: %s\n",cap);
			goto PUT_HELP;
		}
	}else
	if( isupper(*cap) ){
		if( streq(cap,"ALL") )
			return 0;
		if( paramX(cap,1) <= 0 ){
			fprintf(stderr,"Unknown parameter: %s\n",cap);
			goto PUT_HELP;
		}
	}else{
		if( streq(cap,"all") )
			return 0;
		if( serviceport(cap) <= 0 ){
			fprintf(stderr,"Unknown protocl: %s\n",cap);
			goto PUT_HELP;
		}
	}
	return 0;
PUT_HELP:
	fprintf(stderr,"Protocols:\n"); lsProtos(stderr);
	fputs("\n",stderr);
	fprintf(stderr,"Functions:\n"); lsFuncs(stderr);
	fputs("\n",stderr);
	fprintf(stderr,"Parameters:\n"); lsParams(stderr);
	fputs("\n",stderr);
	return -1;
}
static int checkCaps(PCStr(caps)){
	return scan_commaListL(caps,0,scanListCall cap1);
}
void toMD5X(PCStr(key),int klen,char digest[]);
void toMD5X64(PCStr(key),int klen,PVStr(md5),int msiz){
	CStr(digest,16);
	refQStr(dp,md5);

	toMD5X(key,klen,digest);
	str_to64(digest,16,BVStr(md5),msiz,0);
	if( dp = strpbrk(md5,"=\r\n") )
		setVStrEnd(dp,0);
}
static void sputMD5(PVStr(dp),PCStr(pass),int len){
	CStr(md5,64);
	CStr(buf,64);
	int xlen;

	xlen = str_from64(pass,len,AVStr(buf),sizeof(buf));
	if( xlen == 16 ){
		strcpy(dp,pass);
	}else{
		toMD5X64(pass,strlen(pass),AVStr(md5),sizeof(md5));
		sprintf(dp,"%s",md5);
		setVStrEnd(dp,len);
	}
}

int excludeL(PVStr(list),int delim,PCStr(elem)){
	CStr(ebuf,MAXIMPSIZE);
	refQStr(lp,list);
	refQStr(op,list);
	int ndel = 0;
	for(;;){
		lp = scan_ListElem1(lp,delim,AVStr(ebuf));
		if( *ebuf == 0 )
			break;
		if( streq(ebuf,elem) ){
		}else{
			if( list < op ) setVStrPtrInc(op,',');
			strcpy(op,ebuf);
			op += strlen(op);
		}
		if( *lp == 0 )
			break;
	}
	setVStrEnd(op,0);
	return ndel;
}
static scanListFunc subst1(PCStr(elem),int dfltop,PCStr(olist),int delim,PVStr(list),char **lp){
	refQStr(xp,list);
	int del = 0;
	CStr(delem,128);

	xp = *lp;
	if( elem[0] == '^' ){
		elem++;
		del = 1;
	}else
	if( !streq(elem,"+") && dfltop == '-' ){
		del = 2;
	}
	sprintf(delem,"-%s",elem);
	if( del ){
		if( isinList(list,elem) ){
			excludeL(AVStr(list),delim,elem);
			xp = list + strlen(list);
			return 0;
		}else{
			fprintf(stderr,"ERROR: ^'%s' not in '%s'\n",
				elem,olist);
			if( !isinList(list,delem) ){
				elem = delem;
				goto ADD1;
			}
			return -1;
		}
	}else{
		if( isinList(list,delem) ){
			excludeL(AVStr(list),delim,delem);
			xp = list + strlen(list);
			return 0;
		}else
		if( isinList(list,elem) ){
			fprintf(stderr,"WARNING: '%s' is already in '%s'\n",
				elem,list);
		}else{
	ADD1:
			if( streq(list,"*") ){
				xp = list;
			}
			if( list < xp ){
				setVStrPtrInc(xp,',');
			}
			if( streq(elem,"+") )
				strcpy(xp,olist);
			else	strcpy(xp,elem);
			xp += strlen(xp);
		}
	}
	*lp = (char*)xp;
	return 0;
}
const char *substL(PCStr(nlist),int dfltop,PVStr(olist)){
	CStr(olb,MAXIMPSIZE);
	CStr(nlb,MAXIMPSIZE);
	int delim = ',';
	int ok;
	const char *lp = olist;

	if( nlist == NULL )
		nlist = "";
	if( isinList(nlist,"+") == 0 ){
		sprintf(nlb,"+,%s",nlist);
		nlist = nlb;
	}
	strcpy(olb,olist);
	ok = scan_ListL(nlist,delim,0,scanListCall subst1,dfltop,olb,delim,AVStr(olist),&lp);
	return olist;
}

typedef struct {
	MStr(_ckey,128);
	int _cklen;
	const char	*_PARAMs[256];
	const char	*_iav[1024];	/* given as the arg. to -Fimp */
	int		 _iac;
	const char	*_oav[1024];	/* loaded from old imp. area */
	int		 _oac;
	int		 _fclr;
	int		 _optK;	/* 0:asis 1:crypt 2:newkey -1:no-crypt */ 

	MStr(	_owner,128);
	MStr(	_group,128);
	int	_ofmode;
	int	_ofdate;
	int	_ofsize;

	const char	*_supass;
	const char	*_expass;

	MStr(_imporig,256);
	MStr(_spassb,128);
	MStr(_susersb,1024);
	MStr(_scapsb,1024);
	MStr(_xpassb,128);
	MStr(_xusersb,1024);
	MStr(_xcapsb,1024);

	const char *_exusers;
	const char *_excaps;
	const char *_suusers;
	const char *_sucaps;

	int _nth;
	int _suuserop;
	int _sucapsop;
	int _exuserop;
	int _excapsop;

	MStr(_lsfmt,128);
	int _fsilent;
	int _putopts;
} ParamSet;
#define PO_NLONLY	0x0001
#define PO_ENCRYPTED	0x0002
#define PO_ENCWITHKEY	0x0004

#define _ADMIN	_PARAMs[paramX(P_ADMIN,1)]
#define _OWNER	_PARAMs[paramX(P_OWNER,1)]
#define _DGROOT	_PARAMs[paramX(P_DGROOT,1)]
#define _LDPATH	_PARAMs[paramX(P_LDPATH,1)]
#define _SERVER	_PARAMs[paramX(P_SERVER,1)]
#define _FUNC	_PARAMs[paramX(P_FUNC,1)]
#define _DGOPTS	_PARAMs[paramX(P_DGOPTS,1)]

#define IFS(str)	((str) && *(str))
#define IFSB(str,sub)	(((str) && *(str))?str:sub)

static void getParams(ParamSet *PS,const char *oav[],int loaded){
	const char *ov;
	const char *pv;
	int ai;
	int px;

	if( ov = getv(oav,_P_IMPLAST) ){
		if( *ov == '"' ) ov++;
		PS->_nth = atoi(ov);
	}
	if( ov = getv(oav,_P_IMPORIG) ){
		strcpy(PS->_imporig,ov);
	}
/*
	if( ov = getv(oav,P_DGOPTS) ){
		if( strneq(ov,"-P",2) ){
			if( PS->_ports == 0 )
				PS->_ports = ov;
		}
	}
*/
	for( ai = 0; ov = oav[ai]; ai++ ){
		while( isspace(*ov) )
			ov++;
		px = paramX(ov,1);
		if( px <= 0 ){
			if( *ov == 0 ){
			}else
			if( *ov == '#' ){
			}else
			if( *ov == '+' ){
			}else
			if( *ov == '_' ){
			}else
			if( strneq(ov,"-z",2) ){
			}else
			if( strneq(ov,"CASE",4) ){
			}else
			if( strneq(ov,"ESAC",4) ){
			}else{
			fprintf(stderr,"## Unknown Parameter: %s\n",ov);
			}
		}else{
			if( PS->_PARAMs[px] == 0 ){
				if( pv = strchr(ov,'=') )
					PS->_PARAMs[px] = pv + 1;
			}
		}
	}

	if( !loaded ){
		return;
	}

	if( ov = getv(oav,P_SUDOAUTH) ){
		scan_Lists3(ov,':',PS->_spassb,PS->_susersb,PS->_scapsb);
		if( PS->_supass==0 && *PS->_spassb&&!streq(PS->_spassb,"*") )
			 PS->_supass = PS->_spassb;
	}
	PS->_suusers= substL(PS->_suusers,PS->_suuserop,AVStr(PS->_susersb));
	PS->_sucaps = substL(PS->_sucaps,PS->_sucapsop,AVStr(PS->_scapsb));
	if( ov = getv(oav,P_EXECAUTH) ){
		scan_Lists3(ov,':',PS->_xpassb,PS->_xusersb,PS->_xcapsb);
		if( PS->_expass==0 && *PS->_xpassb&&!streq(PS->_xpassb,"*") )
			 PS->_expass = PS->_xpassb;
	}
	PS->_exusers= substL(PS->_exusers,PS->_exuserop,AVStr(PS->_xusersb));
	PS->_excaps = substL(PS->_excaps,PS->_excapsop,AVStr(PS->_xcapsb));
}
static char *putParam1(PVStr(pp),PCStr(name),PCStr(value)){
	if( name && *name && value && *value ){
		sprintf(pp,"%s=%s\n",name,value);
		return (char*)pp + strlen(pp);
	}
	return (char*)pp;
}
const char *paramName(int pi);
int isinv(const char *av[],PCStr(v1)){
	int ai;
	for( ai = 0; av[ai]; ai++ ){
		if( streq(av[ai],v1) )
			return ai+1;
	}
	return 0;
}

extern char PW_imp[];
extern char PW_ext[];
extern char PW_exec[];
extern char PW_sudo[];

int paramMulti(PCStr(param));
static char *putParams(PVStr(buf),ParamSet *PS){
	refQStr(dp,buf);
	int pi;
	const char *p1;
	const char *pB = 0;
	const char *pL = 0;
	const char *eol;

	if( PS->_putopts & PO_NLONLY )
		eol = "\n";
	else	eol = "\r\n";

	if( PS->_supass
	 || IFS(PS->_suusers)
	 || IFS(PS->_sucaps)
	){
		sprintf(dp,"%s=",P_SUDOAUTH);
		dp += strlen(dp);
		if( PS->_supass ){
			sputMD5(AVStr(dp),PS->_supass,32);
			dp += strlen(dp);
		}
		if( !IFS(PS->_suusers)
		 || PS->_suusers && streq(PS->_suusers,"*") )
		if( PS->_supass == 0 || *PS->_supass == 0 ){
			/* should not be allowed to anyone */
			PS->_suusers = "root";
		}
		sprintf(dp,":%s",IFSB(PS->_suusers,"*"));
		dp += strlen(dp);
		sprintf(dp,":%s",IFSB(PS->_sucaps,"*"));

		dp += strlen(dp);
		sprintf(dp,"%s",eol);
		dp += strlen(dp);
	}

	if( PS->_expass
	 || IFS(PS->_exusers)
	 || IFS(PS->_excaps)
	 || PS->_FUNC
	){
		sprintf(dp,"%s=",P_EXECAUTH);
		dp += strlen(dp);
		if( PS->_expass ){
			sputMD5(AVStr(dp),PS->_expass,32);
			dp += strlen(dp);
		}
		sprintf(dp,":%s",IFSB(PS->_exusers,"*"));
		dp += strlen(dp);
		if( PS->_FUNC && *PS->_FUNC ){
			sprintf(dp,":F%s",PS->_FUNC);
		}else	sprintf(dp,":%s",IFSB(PS->_excaps,"*"));
		dp += strlen(dp);
		sprintf(dp,"%s",eol);
		dp += strlen(dp);
	}

/*
	PS->_PARAMs[paramX(P_SUDOAUTH,1)] = 0;
	PS->_PARAMs[paramX(P_EXECAUTH,1)] = 0;
	dp = putParam1(AVStr(dp),P_DGOPTS, PS->_ports);
*/

	for( pi = 0; pi < PS->_iac; pi++ ){
		IStr(pname,128);
		IStr(dom,128);

		p1 = PS->_iav[pi];
		if( isinv((const char**)PS->_oav,p1) ){
			continue;
		}
		if( strneq(p1,"-z",2) ){
			int po;
			const char *op;
			int incase = 0;
			for( po = 0; po < PS->_oac; po++ ){
				op = PS->_oav[po];
				if( strheadstrX(op,"CASE",0) ){
					incase++;
				}else
				if( strheadstrX(op,"ESAC",0) ){
					incase--;
				}else
				if( 0 < incase ){
				}else
				if( strheadstrX(op,p1+2,0) ){
					PS->_oav[po] = "# # # # ";
				}
			}
			continue;
		}

		if( strheadstrX(p1,P_PASSWD,0) ){
			Xsscanf(p1,"%[^=]=%[^:]",AVStr(pname),AVStr(dom));
			if( streq(dom,PW_imp)
			 || streq(dom,PW_sudo)
			 || streq(dom,PW_exec)
			){
				continue;
			}
		}
		sprintf(dp,"%s%s",p1,eol);
		dp += strlen(dp);
	}
/*
	for( pi = 1; pi < elnumof(PS->_PARAMs); pi++ ){
		if( p1 = PS->_PARAMs[pi] ){
			dp = putParam1(AVStr(dp),paramName(pi),p1);
		}
	}
*/
	for( pi = 0; pi < PS->_oac; pi++ ){
		const char *v1;
		CStr(com,1024);
		p1 = PS->_oav[pi];

		if( *p1 == '#' && strneq(p1,"# # # # ",8) )
			continue;

		wordScanY(p1,com,"^= \t\r\n");
		if( *com == 0 ){
		}else
		if( *com == '#' ){
			if( streq(p1,"# < ") )
				continue;
		}else
		if( *com == '-' ){
		}else
		if( *com == '+' ){
		}else
		if( *com == '_' ){
			if( streq(com,_P_IMPORIG) || streq(com,_P_IMPLAST) )
				continue;
		}else{
			if( paramX(com,1) <= 0 ){
				if( streq(com,"CASE") ){
				}else
				if( streq(com,"ESAC") ){
				}else{
					sprintf(dp,"##!UNKNOWN!## %s%s",p1,eol);
					dp += strlen(dp);
					continue;
				}
			}
			if( streq(com,P_SUDOAUTH) || streq(com,P_EXECAUTH) )
				continue;
			if( streq(com,P_DGOPTS) ){
				int found = 0;
				int len;
				int ii;
				const char *p2;
				CStr(head,128);

				len = strlen(com);
				strcpy(head,p1);
				if( strneq(head+len,"=-",2) && head[len+2] ){
					setVStrEnd(head,len+3);
					for( ii = 0; p2 = PS->_iav[ii]; ii++ ){
						if( strneq(p2,head,len+3) ){
							if( !streq(p1,p2) ){
			fprintf(stderr,"## replaced %s with %s\n",p1,p2);
								found = 1;
								break;
							}
						}
					}
					if( found )
					continue;
				}
			}
			if( getv(PS->_iav,com) ){
				if( paramMulti(com) ){
					/* should remove if duplicated */
				}else{
				  if( !isinv((const char**)PS->_iav,p1) ){
					fprintf(stderr,"## replaced %s\n",p1);
					continue;
				  }else{
				  }
				}
			}
		}
		if( pB == 0 ){
			pB = p1;
			if( !streq(pB,"# < ") ){
				/*
				sprintf(dp,"%s%s","# < ",eol);
				dp += strlen(dp);
				*/
			}
		}
		sprintf(dp,"%s%s",p1,eol);
		dp += strlen(dp);
		pL = p1;
	}
	if( pL && !streq(pL,"# > ") ){
		/*
		sprintf(dp,"%s%s","# > ",eol);
		dp += strlen(dp);
		*/
	}
	setVStrEnd(dp,0);
	return (char*)dp;
}
static void resetParams(int ac,const char *av[],ParamSet *PS){
	int ai;
	const char *a1;

	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( strneq(av[ai],"--",2) ){
			switch( av[ai][2] ){
				case 'w': PS->_supass = 0; break;
				case 'W': PS->_expass = 0; break;
				case 'A': PS->_ADMIN = 0; break;
				case 'R': PS->_DGROOT = 0; break;
				case 'L': PS->_LDPATH = 0; break;
				case 'S': PS->_SERVER = 0; break;
				case 'F': PS->_FUNC = 0; break;
				case 'k': PS->_optK = -1; break;
			}
		}
		if( strneq(av[ai],"-z",2) ){
			switch( av[ai][2] ){
				case 'w': PS->_supass = 0; break;
				case 'u': PS->_suusers = 0; break;
				case 'c': PS->_sucaps = 0; break;
				case 'W': PS->_expass = 0; break;
				case 'U': PS->_exusers = 0; break;
				case 'C': PS->_excaps = 0; break;
				case 'A': PS->_ADMIN = 0; break;
				case 'R': PS->_DGROOT = 0; break;
				case 'L': PS->_LDPATH = 0; break;
				case 'S': PS->_SERVER = 0; break;
				case 'F': PS->_FUNC = 0; break;
				case 'k': PS->_optK = -1; break;
			}
		}
	}
}

static int checkImpSign(ParamSet *PS,PCStr(iexe)){
	const char *ov;
	CStr(who,128);
	CStr(you,128);
	CStr(ino,128);

	if( (ov = getv((const char**)PS->_oav,_P_IMPLAST)) == 0 )
		return 0;

	myName(AVStr(you),sizeof(you));
	sprintf(who,"by %s",you);
	sprintf(ino,"%d",File_ino(iexe));
	if( strstr(ov,ino) == 0 ){
		if( strstr(ov,who) == 0 ){
			fprintf(stderr,
			"ERROR: you (%s) are not who implanted it.\n",you);
			return -1;
		}else{
			fprintf(stderr,"Warning: seems copied: %s\n",iexe);
		}
	}
	return 0;
}

void dumpCKeyX(PCStr(opts),PCStr(param),PCStr(dom),PCStr(user),int force);
int restoreCKeyX(PCStr(opts),PCStr(param),PCStr(dom),PCStr(user),PVStr(ekey),int esiz);
void setCKeyP(PCStr(param),PCStr(dom),PCStr(user),PCStr(ekey),int elen);
int getCryptKeyMain(int which,PCStr(param),PCStr(cap),PCStr(user),PVStr(ckey),int ksiz);
int getCryptKeyX(Connection *Conn,int which,PCStr(param),PCStr(dom),PCStr(user),PVStr(key),int siz);
int getCryptKeyTty(PCStr(param),PCStr(dom),PCStr(user),PVStr(ekey),int esiz);
const char *getCKeyMainArg(Connection *Conn,PCStr(param),PCStr(dom),PCStr(user));
int getCryptKeyMainArg(PCStr(param),PCStr(dom),PCStr(user),PVStr(ckey),int csiz);

char *signParams(PVStr(ep),ParamSet *PS,FILE *ifp,PCStr(oexe),PCStr(save)){
	CStr(user,128);
	CStr(date,128);
	CStr(fino,128);
	CStr(imp,256);
	CStr(orig,256);
	CStr(econf,MAXIMPSIZE);
	const char *eol;

	if( PS->_putopts & PO_NLONLY )
		eol = "\n";
	else	eol = "\r\n";

	myName(AVStr(user),sizeof(user));
	StrftimeLocal(AVStr(date),sizeof(date),"%y%m%d%H%M%S%z",time(0),0);
	sprintf(fino,"%d",File_ino(oexe));
	sprintf(imp,"%s=\"%dth at %s into %s by %s\"%s",_P_IMPLAST,PS->_nth+1,
		date,fino,user,eol);
	strcat(ep,imp);
	if( PS->_imporig[0] == 0 ){
		CStr(fdate,128);

		StrftimeLocal(AVStr(fdate),sizeof(fdate),"%y%m%d%H%M%S%z",
			PS->_ofdate,0);
		sprintf(PS->_imporig,"\"owner=%s/%s;mode=0%o;date=%s\"",
			PS->_owner,PS->_group,
			PS->_ofmode,fdate);
	}
	sprintf(orig,"%s=%s%s",_P_IMPORIG,PS->_imporig,eol);
	strcat(ep,orig);

	if( !PS->_fsilent )
		fprintf(stderr,"%s",ep);

	if( save ){
		FILE *sfp;
		if( sfp = fopen(save,"w") ){
			if( PS->_putopts & PO_ENCRYPTED ){
				CStr(xkey,128);
				const char *opts = "b";
				const char *ckey = "";
				if( PS->_putopts & PO_ENCWITHKEY ){
 if( 0 < getCryptKeyX(MainConn(),0xFF,P_PASSWD,PW_ext,"",AVStr(xkey),sizeof(xkey)) )
					ckey = xkey;
				}
				enCreys(opts,ckey,ep,AVStr(econf),sizeof(econf));
				fprintf(sfp,"+=enc:ext::%s:\n",econf);
			}else{
				fputs(ep,sfp);
			}
			fclose(sfp);
			fprintf(stderr,"Save to: %s\n",save);
		}else{
			fprintf(stderr,"Cannot open: %s\n",save);
		}
		ls_unix(stderr,"-Ll",AVStr(PS->_lsfmt),save,NULL);
	}

	enCreys("s",PS->_ckey,ep,AVStr(econf),sizeof(econf));
	sprintf(ep,"+=enc:imp::%s:\n",econf);
	return (char*)ep + strlen(ep);
}
static int editParams(const char *av[],PCStr(iexe),PVStr(buf),int bsiz){
	refQStr(bp,buf);
	const char *bx = &buf[bsiz-1];
	CStr(xtmp,1024);
	CStr(comd,1024);
	IStr(opts,1024);
	CStr(line,1024);
	refQStr(op,opts);
	const char *ed;
	FILE *sfp;
	const char *a1;
	int ai;

	sprintf(xtmp,"%s/dgimp-%X.cnf",getTMPDIR()?getTMPDIR():"/tmp",
		strCRC32(iexe,strlen(iexe)));
	sfp = fopen(xtmp,"w");
	if( sfp == NULL ){
		return 0;
	}
	if( (ed = DELEGATE_getEnv("EDITOR")) == 0
	 && (ed = DELEGATE_getEnv("VISUAL")) == 0 )
		ed = "vi";

	for( ai = 0; a1 = av[ai]; ai++ ){
		if( strneq(a1,"_IMP",4)
		 || strneq(a1,"SUDOAUTH=",9)
		 || strneq(a1,"EXECAUTH=",9)
		){
			continue;
		}
		if( ai == 0 && *a1 == 0 )
			continue;
		if( strneq(a1,"# < ",4) ) continue;
		if( strneq(a1,"# > ",4) ) continue;
		if( strneq(a1,"####",4) )
			continue;
		fprintf(sfp,"%s\n",a1);
	}
	fclose(sfp);
	sprintf(comd,"%s %s",ed,xtmp);

	IGNRETZ system(comd);
	sfp = fopen(xtmp,"r");
	if( sfp == NULL ){
		return 0;
	}

/*
	while( fgets(line,sizeof(line),sfp) != NULL ){
		CStr(com,1024);
		lineScan(line,com);
		if( strneq(com,"DGOPTS=",7) ){
			if( strstr(opts,com+7) == 0 ){
				if( opts < op )
					sprintf(op,";%s",com+7);
				else	strcpy(op,com+7);
				op += strlen(op);
			}
		}else
		if( com[0] == '-' && com[1] != '-' ){
			if( strstr(opts,com) == 0 ){
				if( opts < op )
					sprintf(op,";%s",com);
				else	strcpy(op,com);
				op += strlen(op);
			}
		}else{
		}
	}
*/
	fseek(sfp,0,0);

	bp = buf;
	if( a1=getv(av,P_SUDOAUTH) ){ bp=putParam1(AVStr(bp),P_SUDOAUTH,a1); }
	if( a1=getv(av,P_EXECAUTH) ){ bp=putParam1(AVStr(bp),P_EXECAUTH,a1); }
	if( a1=getv(av,_P_IMPLAST) ){ bp=putParam1(AVStr(bp),_P_IMPLAST,a1); }
	if( a1=getv(av,_P_IMPORIG) ){ bp=putParam1(AVStr(bp),_P_IMPORIG,a1); }
/*
	if( opts[0] ){
		sprintf(bp,"%s=%s\n",P_DGOPTS,opts);
		bp += strlen(bp);
	}
*/
	while( bp < bx && fgets(bp,bx-bp,sfp) != NULL ){
		lineScan(bp,line);
/*
		if( strneq(line,"DGOPTS=",7) ){
		}else
*/
		if( line[0] == '-' && line[1] != '-' ){
			Strins(AVStr(bp),"DGOPTS=");
			bp += strlen(bp);
		}else{
			bp += strlen(bp);
		}
	}

	fclose(sfp);
	unlink(xtmp);
	return bp - buf;
}

int implant_main(int ac,const char *av[],Connection *Conn);

void fimpByClone(Connection *Conn,int ac,const char *av[],PCStr(func),ParamSet *PS,PCStr(oexe)){
	CStr(xtmp,1024);
	FILE *ofp;
	int ai,nac;
	const char *nav[128];
	CStr(com,1024);
	int klen;
	CStr(ikey,128);
	CStr(ekey,128);
	CStr(nkey,128);
	int withnew_k = 0;
	int setoexe = 0;

	if( getenv("IMP_RETRYING") ){
		fprintf(stderr,"FAILED open(%s)\n",oexe);
		Finish(-1);
	}
	putenv("IMP_RETRYING=yes");

	sprintf(xtmp,"%s/dgimp-%X.exe",
		getTMPDIR()?getTMPDIR():"/tmp",
		strCRC32(oexe,strlen(oexe)));
	fprintf(stderr,"#### making a copy to %s\n",xtmp);

	ofp = fopen(xtmp,"w");
	if( ofp == NULL ){
		fprintf(stderr,"FAILED open(%s)\n",xtmp);
	}else{
		fclose(ofp);
		/* create a clone with -Fimp capability only */
		nac = 0;
		nav[nac++] = funcFimp;
		nav[nac++] = "-Vs";
		nav[nac++] = "FUNC=imp";
		nav[nac++] = "-o";
		nav[nac++] = xtmp;
		nav[nac] = 0;
		implant_main(nac,nav,Conn);
		chmod(xtmp,0700);

		nac = 0;
		nav[nac++] = xtmp;
		nav[nac++] = func;
		for( ai = 1; ai < ac && ai < elnumof(nav)-2; ai++ ){
			if( streq(av[ai],"-x") )
				continue;
			if( strneq(av[ai],"-k",2) && av[ai][2] != 0 ){
				withnew_k = 1;
			}
			if( streq(av[ai],"-a") ){
				nav[nac++] = oexe;
				setoexe = 1;
			}
			nav[nac++] = av[ai]; 
		}
		if( setoexe == 0 ){
			nav[nac++] = oexe;
		}
		for( ai = 0; ai < nac; ai++ )
			fprintf(stderr,"[%d] %s\n",ai,nav[ai]);

		klen = getCryptKeyX(Conn,1,P_PASSWD,PW_imp,"",
			AVStr(ikey),sizeof(ikey));
		if( 0 < klen ){
			Strins(AVStr(ikey),"PASSWD=imp::pass:");
			nav[nac++] = ikey;
		}
		klen = getCryptKeyX(Conn,1,P_PASSWD,PW_exec,"",
			AVStr(ekey),sizeof(ekey));
		if( 0 < klen ){
			Strins(AVStr(ekey),"PASSWD=exec::pass:");
			nav[nac++] = ekey;
		}

		if( !withnew_k )
		if( 0 < PS->_optK && getv(av,"_newPASSWD") == 0 ){
			CStr(nk,128);
			int nklen = -1;
			nklen =
			getCryptKeyTty("_newPASSWD",PW_imp,"",AVStr(nk),sizeof(nk));
			if( 0 <= nklen ){
				sprintf(nkey,"%s=imp::pass:%s","_newPASSWD",nk);
				nav[nac++] = nkey;
			}
		}

		nav[nac] = 0;

		execvp(xtmp,(char**)nav);
		fprintf(stderr,"FAILED exec(%s)\n",xtmp);
	}
	Finish(-1);
}
static void addNewArg1(ParamSet *PS,PCStr(a1)){
	if( !strheadstrX(a1,P_PASSWD,0) )
		fprintf(stderr,"imp[%d] %s\n",PS->_iac,a1);
	if( elnumof(PS->_iav)-1 <= PS->_iac ){
		fprintf(stderr,"IGNORED: too many args\n");
	}else{
		PS->_iav[PS->_iac++] = a1;
		PS->_iav[PS->_iac] = 0;
	}
}

/* should introduce the capability for "others" */
static int OwnerUid = -1;
static int impAllowed(PCStr(iexe),FILE *ifp){
	int uid = getuid();
	int fuid;
	int tuid;

	if( uid == 0 )
		return 1;
	tuid = ttyuid(0);

	/* matching with the owner in _IMPORIG */
	if( OwnerUid != -1 ){
		if( OwnerUid == uid || OwnerUid == tuid )
			return 1;
	}
	if( iexe ){
		fuid = File_uid(iexe);
		if( fuid == uid ) return 1;
		if( fuid == tuid ) return 1;
	}
	if( ifp ){
		fuid = file_uid(fileno(ifp));
		if( fuid == uid ) return 1;
		if( fuid == tuid ) return 1;
	}
	/*
	if( iexe && File_gid(iexe) == getgid() )
		return 1;
	if( ifp && file_gid(fileno(ifp)) == getgid() )
		return 1;
	*/
	return 0;
}

int implant_main(int ac,const char *av[],Connection *Conn){
	int ai;
	const char *a1;
	CStr(mypath,1024);
	CStr(tmp,1024);
	int omode;
	const char *oexe = 0;
	const char *iexe = 0;
	const char *save = 0;
	FILE *ifp = stdin;
	FILE *ofp = NULL;
	int chg = 0;
	ParamSet PS;

	int from = -1;
	int to = -1;
	int f_ovw = 0;
	int fmod = 0;
	int fcpmod = 0;
	int byclone = 0;
	int fsilent = 0;
	int fverb = 0;
	int fedit = 0;

	CStr(buf,MAXIMPSIZE);
	refQStr(dp,buf);
	refQStr(ep,buf);
	int rcc;
	int bsize;
	int oai;
	CStr(obuf,sizeof(buf));
	const char *load = 0; /* a file of parameters to be loaded */
	IStr(rimp,MAXIMPSIZE);
	IStr(nckey,128);
	int ncklen = -1;

	iAuthFunc(implant_main);

	if( 1 < ac ){ f_ovw = 1; }
	bzero(&PS,sizeof(ParamSet));
	PS._suuserop = '+';
	PS._sucapsop = '+';
	PS._exuserop = '+';
	PS._excapsop = '+';

	if( isWindows() )
		strcpy(PS._lsfmt,"%T%M%3L %8S %D %N");
	else	strcpy(PS._lsfmt,"%T%M%3L %-7O %-5G %8S %D %N");
	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( streq(a1,"-a") ){
			break;
		}else
		if( strneq(a1,"-e",2) ){
			if( !isatty(0) || !isatty(1) || !isatty(2) ){
				fprintf(stderr,"Not on tty for -e\n");
				return -1;
			}
			if( isWindows() ){
				fprintf(stderr,"Not supported -e on Windows\n");
				return -1;
			}
			fedit = 1;
			chg=1;
		}else
		if( strneq(a1,"-k",2) ){
			PS._optK = 1;
			chg=1;
			if( a1[2] ){
				strcpy(nckey,a1+2);
				ncklen = strlen(nckey);
				PS._optK = 2;
			}
		}else
		if( strneq(a1,"-x",2) ){
			byclone = 1;
		}else
		if( streq(a1,"-Vv") ){
			fverb = 1;
		}else
		if( streq(a1,"-Vs") ){
			fsilent = 1;
		}else
		if( strneq(a1,"-z",2) ){
		    switch( a1[2] ){
			case 'm':
				fmod = 2;
				break;
			case 0:
				PS._fclr = 1;
				PS._ADMIN = 0;
				chg=1;
				break;
			default:
				chg=1;
				if( a1[2] == '-' ){
					sprintf(tmp,"-z%s=%s",P_DGOPTS,a1+2);
				}else
				if( strneq(a1+2,"+=",2) ){
					sprintf(tmp,"-z%s",a1+2);
				}else
				if( isupper(a1[2]) && isupper(a1[3]) ){
					sprintf(tmp,"-z%s",a1+2);
				}else{
					break;
				}
				a1 = stralloc(tmp);
				goto ADDA1;
				break;
		    }
		}else
		if( streq(a1,"-W") ){
		    if( ai+1 < ac ){ chg=1; a1 = av[++ai]; PS._expass = a1; }
		}else
		if( streq(a1,"-U") || streq(a1,"--U") ){
			if( a1[1] == '-' ) PS._exuserop = a1[1];
		    if( ai+1 < ac ){ chg=1; a1 = av[++ai]; PS._exusers = a1; }
		}else
		if( streq(a1,"-C") || streq(a1,"--C") ){
			if( a1[1] == '-' ) PS._excapsop = a1[1];
		    if( ai+1 < ac ){ chg=1; a1 = av[++ai]; PS._excaps = a1; }
		}else
		if( streq(a1,"-m") ){
			fmod = 1;
		}else
		if( streq(a1,"-w") ){
		    if( ai+1 < ac ){ chg=1; a1 = av[++ai]; PS._supass = a1; }
		}else
		if( streq(a1,"-u") || streq(a1,"--u") ){
			if( a1[1] == '-' ) PS._suuserop = a1[1];
		    if( ai+1 < ac ){ chg=1; a1 = av[++ai]; PS._suusers = a1; }
		}else
		if( streq(a1,"-c") || streq(a1,"--c") ){
			if( a1[1] == '-' ) PS._sucapsop = a1[1];
		    if( ai+1 < ac ){ chg=1; a1 = av[++ai]; PS._sucaps = a1; }
		}else
		if( streq(a1,"-l") ){
			FILE *lfp;
			int rcc;
		    if( ai+1 < ac ){ chg=1; a1 = av[++ai]; load = a1;
			if( lfp = fopen(load,"r") ){
				rcc = fread((char*)rimp,1,sizeof(rimp)-1,lfp);
				if( 0 <= rcc ){
					setVStrEnd(rimp,rcc);
				}else{
				fprintf(stderr,"Cannot load: %s %s\n",
					a1,load);
				}
				fclose(lfp);
			}else{
				fprintf(stderr,"Cannot open: %s %s\n",
					a1,load);
				ls_unix(stderr,"-Ll",AVStr(PS._lsfmt),
					load,NULL);
			}
		    }
		}else
		if( strneq(a1,"-s",2) ){
			switch( a1[2] ){
			  case 'n': PS._putopts = PO_NLONLY; break;
			  case 'e': PS._putopts = PO_NLONLY | PO_ENCRYPTED; break;
			  case 'k': PS._putopts = PO_NLONLY
					 | PO_ENCRYPTED | PO_ENCWITHKEY;
				break;
			}
			if( ai+1 < ac ){ chg=1; a1 = av[++ai]; save = a1; }
		}else
		if( streq(a1,"-o") ){
			f_ovw = 0;
			if( ai+1 < ac ){ a1 = av[++ai]; oexe = a1;
				if( !File_is(oexe) )
					fcpmod = 1;
				ofp = fopen(a1,"w");
				if( ofp == NULL ){
					fprintf(stderr,"Cannot write: %s\n",a1);
					return -1;
				}
			}
		}else
		if( streq(a1,"-A") ){
		    if( ai+1 < ac ){ chg=1; a1 = av[++ai];
			sprintf(tmp,"%s=%s",P_ADMIN,a1);
			a1 = stralloc(tmp);
			goto ADDA1;
		    }
		}else
		if( streq(a1,"-O") ){
		    if( ai+1 < ac ){ chg=1; a1 = av[++ai];
			sprintf(tmp,"%s=%s",P_OWNER,a1);
			a1 = stralloc(tmp);
			goto ADDA1;
		    }
		}else
		if( strneq(a1,"-P",2) ){
			chg=1;
			sprintf(tmp,"%s=%s",P_DGOPTS,a1);
			a1 = stralloc(tmp);
			goto ADDA1;
		}else
		if( streq(a1,"-R") ){
		    if( ai+1 < ac ){ chg=1; a1 = av[++ai];
			sprintf(tmp,"%s=%s",P_DGROOT,a1);
			a1 = stralloc(tmp);
			goto ADDA1;
		    }
		}else
		if( streq(a1,"-S") ){
		    if( ai+1 < ac ){ chg=1; a1 = av[++ai];
			sprintf(tmp,"%s=%s",P_SERVER,a1);
			a1 = stralloc(tmp);
			goto ADDA1;
		    }
		}else
		if( isupper(a1[0]) && strchr(a1,'=') && paramX(a1,0)
		 || strstr(a1,"+=")
		){
		ADDA1:
			addNewArg1(&PS,a1);
			chg=1;
		}else
		if( strneq(a1,"--",2) ){
			/* exclude from a list */
			chg=1;
		}else
		if( streq(a1,"-h") ){
			putEmbedHelp(stderr,ac,av,1);
		}else
		if( a1[0] == '-' ){
			switch( a1[1] ){
				case 'd':
				case 'r':
				case 'f':
				case 'v':
					sprintf(tmp,"%s=%s",P_DGOPTS,a1);
					a1 = stralloc(tmp);
					goto ADDA1;
					break;
				default:
				fprintf(stderr,"Unknown Option: %s\n",a1);
				putEmbedHelp(stderr,ac,av,1);
				exit(-1);
			}
		}else
		if( File_is(a1) ){
			iexe = a1;
			ifp = fopen(a1,"r");
			if( ifp == NULL ){
				fprintf(stderr,"Cannot read: %s\n",a1);
				return -1;
			}
		}
	}
	if( ai < ac && streq(av[ai],"-a") ){
		for( ai++; ai < ac; ai++ ){
			a1 = av[ai];
			if( a1[0] == '-' ){
				sprintf(tmp,"%s=%s",P_DGOPTS,a1);
				a1 = stralloc(tmp);
			}
			addNewArg1(&PS,a1);
			chg=1;
		}
	}
	PS._fsilent = fsilent;
	PS._iav[PS._iac] = 0;
	if( PS._excaps && checkCaps(PS._excaps) != 0 ){ return -1; }
	if( PS._sucaps && checkCaps(PS._sucaps) != 0 ){ return -1; }
	getParams(&PS,PS._iav,0);
	if( PS._fclr ){
		if( fmod == 0 ){
			fprintf(stderr,"#### reset set-uid-on-exec with -z\n");
			fmod = 2;
		}
	}

	/*
	if( PS._ADMIN ){
		fprintf(stderr,".... validating ADMIN=%s .... ",PS._ADMIN);
		fflush(stderr);
		if( validateEmailAddr(PS._ADMIN,0) != 0 ){
			fprintf(stderr,"#### INVALID mail-address\n");
			PS._ADMIN = 0;
		}else{
			fprintf(stderr,"OK\n");
		}
	}
	*/

	if( iexe == 0 ){
	    if( isatty(fileno(stdin)) ){
		strcpy(mypath,EXEC_PATH);
		FullpathOfExe(AVStr(mypath));
		iexe = mypath;
		ifp = fopen(iexe,"r");
		if( ifp == NULL ){
			fprintf(stderr,"Cannot open: %s\n",iexe);
			return -1;
		}
	    }else{
		/* imp < ifile > ofile ... should it be supported ? */
	    }
	}
	if( !impAllowed(iexe,ifp) ){
		if( iexe == 0 )
			iexe = "?";
		ls_unix(stderr,"-Ll",AVStr(PS._lsfmt),iexe,NULL);
		fprintf(stderr,
			"-Fimp Forbidden: You are not the owner of %s\n",
				iexe?iexe:"?");
		return -1;
	}

	getowner(iexe,AVStr(PS._owner),sizeof(PS._owner),AVStr(PS._group),sizeof(PS._group));
	PS._ofmode = File_mod(iexe);
	PS._ofsize = File_size(iexe);
	PS._ofdate = File_mtime(iexe);

	if( fmod ){
		int rcode;
		const char *exe;
		if( oexe != 0 )
			exe = oexe;
		else	exe = iexe;
		omode = File_mod(exe);

		fcpmod = 0;
		ls_unix(stderr,"-Ll",AVStr(PS._lsfmt),exe,NULL);
		if( fmod == 1 ){
			if( !File_is(exe) || File_size(exe) == 0 ){
				if( ofp != NULL ){
					fprintf(stderr,"Rewriting: %s\n",exe);
				}else{
					ofp = fopen(exe,"w");
					fprintf(stderr,"Created: %s\n",exe);
				}
				if( ofp ){
					copyfile1(ifp,ofp);
					fseek(ifp,0,0);
					fclose(ofp);
				}
			}
			if( chown(exe,0,(unsigned int)-1) != 0 ){
				fprintf(stderr,"Cannot chown: %s\n",exe);
			}
			omode |= 06110;
			omode &= ~01;
			rcode = chmod(exe,omode);
		}else{
			if( ((omode = File_mod(exe)) & ~07777) == 0 ){
				int ouid;
				rcode = chmod(exe,omode&01777);
				ouid = ttyuid(0);
				if( ouid == -1 )
					ouid = getuid();
				IGNRETZ chown(exe,ouid,(unsigned int)-1);
				/* should use the saved owner in
				 * _IMPORIG=user/group/mode ? */
			}
		}
		ls_unix(stderr,"-Ll",AVStr(PS._lsfmt),exe,NULL);

		if( chg == 0 ){
			if( OwnerUid < 0 ){
				chg = 1;
			}else
			return 0;
		}
	}

	if( 0 < chg && f_ovw && iexe != NULL ){
		oexe = iexe;
	}
	if( oexe )
	if( getuid() != 0 )
	if( File_uid(oexe) != getuid() )
	if( File_gid(oexe) != getgid() )
	{
		CStr(you,128);
		myName(AVStr(you),sizeof(you));
 ls_unix(stderr,"-Ll",AVStr(PS._lsfmt),oexe,NULL);
 fprintf(stderr,"--------------\n");
 fprintf(stderr,"ERROR: You (%s) are not the owner of the executable.\n",you);
/* if the saved owner in _IMPORIG is you */
 {
 fprintf(stderr,"HINT: Be the owner as folloes:\n");
 fprintf(stderr,"  %% %s %s -zm\n",
	main_argv[0]?main_argv[0]:EXEC_PATH,funcFimp);
 }
 fprintf(stderr,"--------------\n");
		return -1;
	}
	if( 0 < chg && f_ovw && oexe != NULL ){
		if( byclone ){
			fclose(ifp);
			fimpByClone(Conn,ac,av,funcFimp,&PS,oexe);
		}

		ofp = fopen(oexe,"r+");
		if( ofp == NULL ){
			if( ((omode = File_mod(oexe)) & ~07777) == 0 ){
				chmod(oexe,omode|400);
				ofp = fopen(oexe,"r+");
				if( ofp != NULL ){
				fprintf(stderr,"Opened with chmod: %s\n",oexe);
				}
				chmod(oexe,omode);
			}
		}
		if( ofp == NULL ){
			if( errno == ETXTBSY
			 || errno == EACCES && isWindows() ){
				fclose(ifp);
				fimpByClone(Conn,ac,av,funcFimp,&PS,oexe);
			}
			fprintf(stderr,"Cannot write: %s\n",iexe);
			ls_unix(stderr,"-Ll",AVStr(PS._lsfmt),iexe,NULL);
			return -1;
		}
	}
	if( ac == 1 ){
		putEmbedHelp(stderr,ac,av,0);
	}
 	if( !fsilent ){
		if( iexe ){
			fprintf(stderr,"xfile: ");
			ls_unix(stderr,"-Ll",AVStr(PS._lsfmt),iexe,NULL);
		}
		if( oexe && *oexe ){
			fprintf(stderr,"ofile: ");
			ls_unix(stderr,"-Ll",AVStr(PS._lsfmt),oexe,NULL);
		}
	}
	if( fcpmod ){
		int rcode;
		omode = File_mod(iexe);
		rcode = chmod(oexe,omode);
		fprintf(stderr,"file mode copied: %o %d\n",omode,rcode);
		fprintf(stderr,"ofile: ");
		ls_unix(stderr,"-Ll",AVStr(PS._lsfmt),oexe,NULL);
	}
 	if( !fsilent ){
		fputs("\n",stderr);
	}

	bsize = findNOSIGN(ifp,ofp,"bconfig:",&from,&to,chg,fsilent,fverb);
	if( ofp ){
		fflush(ofp);
	}
	if( 0 < bsize && 0 <= from && 0 <= to ){
		fseek(ifp,from,0);
		rcc = fread(buf,1,QVSSize(buf,bsize),ifp);
		if( 0 < rcc ){
			setVStrEnd(buf,rcc);
		}
		PS._oav[0] = 0;
		if( 0 < rcc ){
			setVStrEnd(buf,rcc);
			if( rimp[0] ){
				strcpy(buf,rimp);
			}
			if( fedit ){
 PS._oac = getBconfig1(PS._ckey,buf,elnumof(PS._oav),PS._oav,AVStr(obuf),sizeof(obuf),1);
 rcc = editParams((const char**)PS._oav,iexe,AVStr(buf),sizeof(buf));
			}
 PS._oac = getBconfig1(PS._ckey,buf,elnumof(PS._oav),PS._oav,AVStr(obuf),sizeof(obuf),1);
			if( checkImpSign(&PS,iexe) < 0 ){
				if( getuid() != 0 )
					return -1;
			}
			if( !fsilent ){
				for( oai = 0; oai < PS._oac; oai++ ){
					const char *p1 = PS._oav[oai];
					if( *p1 == '#' ) continue;
					if( *p1 == 0 ) continue;
					fprintf(stderr,"   %s\n",p1);
				}
			}

		}
		if( ofp ){
			if( PS._fclr ){
				int i;
				for( i = 0; i < bsize; i++ )
					setVStrElem(buf,i,'#');
			}else{
				getParams(&PS,(const char**)PS._oav,1);
			}
		}
	}

   PS._cklen = getCryptKeyX(Conn,1,P_PASSWD,PW_imp,"",AVStr(PS._ckey),sizeof(PS._ckey));
	if( ofp && 0 <= from && 0 <= to ){
		const char *dx;
		int cx;

		if( OwnerUid < 0 ){
		CStr(you,128);
		myName(AVStr(you),sizeof(you));
		fprintf(stderr,"**** I'll remember you (%s) as my owner.\n",you);
		}

		resetParams(ac,av,&PS);
		if( 0 < rcc ){
			dp = buf;
			ep = dp;
			if( !PS._fclr ){
				dp = putParams(AVStr(dp),&PS);
			}
			if( !fsilent ){
				fprintf(stderr,"\n");
	fprintf(stderr,"---- NEW IMPLANTED CONFIGURATION ----\n");
			}
			if( !(*ep == '#' && strtailchr(ep) == '#') ){

 if( PS._optK == 0 ){
   PS._cklen = getCryptKeyX(Conn,1,P_PASSWD,PW_imp,"",AVStr(PS._ckey),sizeof(PS._ckey));
 }else
 if( PS._optK == 2 ){
	strcpy(PS._ckey,nckey);
	PS._cklen = ncklen;
 }else
 if( 0 < PS._optK ){
   PS._cklen = getCryptKeyMainArg("_newPASSWD",PW_imp,"",AVStr(PS._ckey),sizeof(PS._ckey));
   if( PS._cklen < 0 )
   PS._cklen = getCryptKeyX(Conn,4,P_PASSWD,PW_imp,"",AVStr(PS._ckey),sizeof(PS._ckey));
 }else{
	PS._ckey[0] = 0;
 }
				dp = signParams(AVStr(ep),&PS,ifp,oexe,save);
			}
			if( !fsilent )
				fprintf(stderr,"\n");
		} 
		cx = 0;
		for( dx = buf+bsize-1; dp < dx; ){
			setVStrPtrInc(dp,cx%2==0?'#':' ');
			cx++;
			if( cx % 128 == 0 ){
				if( dp < dx ){
					setVStrPtrInc(dp,'\n');
					cx = 0;
				}
			}
		}
		if( fseek(ofp,from,0) == 0 ){
			int wcc;
			if( !fsilent && fverb )
				fprintf(stderr,"#### written (%X,%d)\n",
					iftell(ofp),bsize);
			wcc = fwrite(buf,1,bsize,ofp);
		}
		fclose(ifp);
		fclose(ofp);
		if( !fsilent )
		ls_unix(stderr,"-Ll",AVStr(PS._lsfmt),oexe,NULL);
	}
	if( !fsilent )
	if( PS._ckey[0] )
printf("_______________________________________________________[CRYPTED]___\n");
	else
printf("___________________________________________________________________\n");

	dumpCKeyX("eptuwM",P_PASSWD,PW_exec,"",1);
	if( PS._optK == 0 ){
		dumpCKeyX("eptuwM",P_PASSWD,PW_imp,"",1);
	}
	return 0;
}
const char *DELEGATE_bconfig();
int CreysWithPass(PCStr(cstr));

static int decryptBconfig1(PCStr(ckey),PCStr(cstr),PVStr(dconf),int dsiz){
	int dch;
	int dlen;

	if( (dlen = deCreys("",ckey,cstr,AVStr(dconf),dsiz)) < 0 ){
		return -1;
	}
	dch = dconf[0];
	if( !isspace(dch) && dch != '#' && dch != '/'
	 && !isalnum(dch) && dch != '+' && dch != '-' && dch != '_' ){
		fprintf(stderr,"---- deCreys ERR %d/%d [%X][%X]\n",
			istrlen(dconf),dlen,dconf[0],dconf[1]);
		return -1;
	}
	return dlen;
}
static int decryptBconfig(PCStr(ckey),PCStr(cstr),PVStr(dconf),int dsiz){
	CStr(xck,128);
	int cklen = 0;
	int dlen;

	if( ckey[0] == 0 && CreysWithPass(cstr) ){
	    cklen = restoreCKeyX("eptuwML",P_PASSWD,PW_imp,"",AVStr(xck),sizeof(xck));
	    if( 0 < cklen ){
		dlen = decryptBconfig1(xck,cstr,BVStr(dconf),dsiz);
		if( 0 < dlen ){
			setCKeyP(P_PASSWD,PW_imp,"",xck,cklen);
			goto EXIT;
		}
	    }
	    cklen = getCryptKeyMain(3,P_PASSWD,PW_imp,"",AVStr(xck),sizeof(xck));
	    if( 0 < cklen ){
		ckey = xck;
		dlen = decryptBconfig1(ckey,cstr,BVStr(dconf),dsiz);
		if( 0 < dlen ){
			goto EXIT;
		}
	    }
	    cklen = getCryptKeyMain(4,P_PASSWD,PW_imp,"",AVStr(xck),sizeof(xck));
	    if( 0 < cklen ){
		ckey = xck;
		dlen = decryptBconfig1(ckey,cstr,BVStr(dconf),dsiz);
		if( 0 < dlen ){
			goto EXIT;
		}
	    }
	}
	dlen = decryptBconfig1(ckey,cstr,BVStr(dconf),dsiz);
	if( dlen < 0 ){
 fprintf(stderr,"--------------\n");
 fprintf(stderr,"ERROR: Can't decrypt the encrypted implanted config.\n");
/*
 fprintf(stderr,"HINT: You can erase the configuration as folloes:\n");
 fprintf(stderr,"  %% %s %s -z\n",
	main_argv[0]?main_argv[0]:EXEC_PATH,funcFimp);
*/
 fprintf(stderr,"--------------\n");
	}

EXIT:
	bzero(xck,sizeof(xck));
	return dlen;
}

int getBconfig1(PCStr(ckey),PCStr(bconf),int mac,const char *av[],PVStr(conf),int csiz,int edit){
	CStr(dconf,2*MAXIMPSIZE);
	refQStr(cp,conf);
	refQStr(dp,conf);
	const char *lp;
	const char *nlp;
	const char *cx;
	IStr(cases,64);
	int ac;

	lp = bconf;
	cp = conf;
	cx = &conf[csiz-1];
	ac = 0;
	for(; ac < mac-1 && *lp; ){
		nlp = linescanX(lp,AVStr(cp),cx-cp);
		if( *nlp == '\r' && nlp[1] == '\n' ){
			lp = nlp + 2;
		}else
		if( *nlp == '\n' ){
			lp = nlp + 1;
		}else{
			const char *ep;
			if( 20 < strlen(lp) )
				ep = lp + strlen(lp) - 20;
			else	ep = lp;
			/*
			fprintf(stderr,"---- without NL: ... [%d]%s\n",
				strlen(lp),ep);
			*/
			lp += strlen(cp);
		}
		if( streq(cp,"}\"") ){
			break;
		}
		if( strneq(cp,"# # # # ",8) ){
			continue;
		}
		if( *cp=='#' && 128<=strlen(cp) && strtailchr(cp)=='#' ){
			continue;
		}
		if( strneq(cp,"+=enc:imp::",11) ){
			int nac;
			if( decryptBconfig(ckey,cp+11,AVStr(dconf),sizeof(dconf)) < 0 ){
				return -1;
			}
			nac = getBconfig1(ckey,dconf,mac-ac,&av[ac],AVStr(cp),
				csiz-(conf-cp),edit);
			if( nac < 0 ){
				return -1;
			}
			ac += nac;
			if( 0 < ac )
				cp = (char*)(av[ac-1] + strlen(av[ac-1]) + 1);
			continue;
		}
		if( edit ){
			if( ac == 0 && *cp == 0 )
				continue;
			av[ac++] = (char*)cp;
			cp += strlen(cp) + 1;
		}else{
			void conf_eval_line(PCStr(line),PVStr(xline));
			if( *cp == 0 || *cp == '#' ){
				continue;
			}
			conf_eval_line(cp,AVStr(cp)); /* strip NAME="xxx" */
			if( strneq(cp,"CASE ",5) ){
				wordScan(cp+5,cases);
				strcat(cases,"_");
			}else
			if( strneq(cp,"ESAC",4) ){
				truncVStr(cases);
			}else{
				if( cases[0] ){
					Strins(AVStr(cp),cases);
				}
				av[ac++] = (char*)cp;
				cp += strlen(cp) + 1;
			}
		}
	}
	av[ac] = 0;
	return ac;
}
static int _getBconfig;
int getBconfig(int mac,const char *av[]){
	CStr(conf,MAXIMPSIZE);
	const char *lp;
	int ac;
	int ai;
	int ax;
	const char *a1;
	const char *vp;

	if( _getBconfig ){
		return 0;
	}
	_getBconfig = 1;
	lp = DELEGATE_bconfig();
	ac = getBconfig1("",lp,mac,av,AVStr(conf),sizeof(conf),0);
	_getBconfig = 0;
	if( ac < 0 ){
 fprintf(stderr,"--------------\n");
 fprintf(stderr,"FATAL: Can't get implanted params.\r\n");
 fprintf(stderr,"--------------\n");
		Finish(-1);
	}

	ax = 0;
	for( ai = 0; ai < ac; ai++ ){
		a1 = av[ai];
		if( LOG_VERBOSE )
		if( !strneq(a1,P_EXECAUTH,9) )
		if( !strneq(a1,P_SUDOAUTH,8) )
			fprintf(stderr,"BUILTIN[%d] %s\n",ax,a1);

		if( vp = strheadstrX(a1,_P_IMPORIG,0) ){
			IStr(owner,32);
			Xsscanf(vp,"=owner=%[^/; ]",AVStr(owner));
			if( owner[0] ){
				OwnerUid = getUserId(owner);
			}
		}

		if( strstr(a1,"+=") ){
			/* ignore ? */
		}

		if( param_lock(PARAM_IMPLANT,a1,&a1) < 0 ){
		}else{
			av[ax] = stralloc(a1);
			ax++;
		}
	}
	av[ax] = 0;
	return ax;
}

scanListFunc matchgu1(PCStr(name),PCStr(user),int uid,int gid,PCStr(file)){
	int cid;
	if( streq(name,".u") ){
		cid = File_uid(file);
		if( cid == uid )
			return 1;
	}else
	if( streq(name,"/.g") ){
		cid = File_gid(file);
		if( cid == gid )
			return 1;
	}else
	if( strneq(name,"/",1) ){
		cid = getGroupId(name+1);
		if( cid == gid )
			return 1;
	}else
	if( streq(name,".owner") ){
		cid = OwnerUid;
		if( cid != -1 )
		if( cid == uid ){
			return 1;
		}
	}else
	if( isWindows() ){
		if( streq(name,user) )
			return 1;
	}else{
		cid = getUserId(name);
		if( cid == uid )
			return 1;
	}
	return 0;
}
static int matchguid(PCStr(users),PCStr(file)){
	int ok;
	int uid = getuid();
	int gid = getgid();
	IStr(user,128);

	myName(AVStr(user),sizeof(user));
	ok = scan_commaListL(users,0,scanListCall matchgu1,user,uid,gid,file);
	return ok;
}

void setupSucaps(PCStr(caps));
void enableServs(PCStr(proto),int enable);
void enableFuncs(PCStr(func),int enable);
void enableParams(PCStr(param),int enable);
static void setupCaps(PCStr(caps)){
	CStr(cap1,128);
	const char *clist;
	const char *c1;
	int op;

	if( *caps != '-' ){
		enableServs("*",-1);
		enableFuncs("*",-1);
	}
	clist = caps;
	while( *clist ){
		clist = scan_ListElem1(clist,',',AVStr(cap1));
		c1 = cap1;
		op = 1;
		if( *c1 == '-' ){
			op = -1;
			c1++;
		}
		if( *c1 == 'F' && islower(c1[1]) ){
			enableFuncs(c1+1,op);
		}else
		if( isupper(*c1) ){
			enableParams(c1,op);
		}else{
			enableServs(c1,op);
		}
	}
}
static int checkAuth(Connection *Conn,PCStr(auth),PCStr(p_auth),PCStr(p_dom)){
	IStr(pass,128);
	IStr(users,256);
	IStr(caps,256);
	const char *p1;

	scan_Listlist3(auth,':',AVStr(pass),AVStr(users),AVStr(caps));
	if( streq(pass,"*") ) truncVStr(pass);
	if( streq(users,"*") ) truncVStr(users);
	if( streq(caps,"*") ) truncVStr(caps);

	if( streq(p_auth,P_SUDOAUTH) && getuid() != 0 )
	if( pass[0] == 0 && users[0] == 0 ){
		/* SUDO should have some authentication */
		fprintf(stderr,"Error: Config %s=%s\n",p_auth,auth);
		return -1;
	}

	if( users[0] ){
		if( !matchguid(users,getEXEC_PATH()) ){
			fprintf(stderr,"Error: Forbidden User\n");
			return -1;
		}
	}
	if( pass[0] ){
		CStr(ip,64);
		CStr(md5,64);
		int klen;

 klen = restoreCKeyX("eptuwML",P_PASSWD,p_dom,"",AVStr(ip),sizeof(ip));
		if( 0 < klen ){
			setCKeyP(P_PASSWD,p_dom,"",ip,klen);
			/* to be retrieved with getCryptKeyX() */
		}
 klen = getCryptKeyX(Conn,3,P_PASSWD,p_dom,"",AVStr(ip),sizeof(ip));
		toMD5X64(ip,strlen(ip),AVStr(md5),sizeof(md5));
		if( strheadstrX(md5,pass,1) == 0 ){
 klen = getCryptKeyX(Conn,4,P_PASSWD,p_dom,"",AVStr(ip),sizeof(ip));
		    if( klen < 0 ){
			fprintf(stderr,"Error: No %s:pass Given\n",p_dom);
			return -1;
		    }
		    toMD5X64(ip,strlen(ip),AVStr(md5),sizeof(md5));
		    if( strheadstrX(md5,pass,1) == 0 ){
			fprintf(stderr,"Error: Bad %s:pass Given\n",p_dom);
			return -1;
		    }
		}
	}
	if( *caps ){
		if( streq(p_auth,P_SUDOAUTH) ){
			setupSucaps(caps);
		}else	setupCaps(caps);
	}
	iLog("--- AUTH. OK %s=%s",p_auth,auth);
	return 0;
}
static int checkSUDOAUTH1(Connection *Conn,int ac,const char *av[]){
	const char *auth;
	if( auth = getEnvBin1st(P_EXECAUTH) ){
		if( checkAuth(Conn,auth,P_EXECAUTH,PW_exec) != 0 ){
			return -1;
		}
	}
	if( !isWindows() )
	if( geteuid() == 0 ){
		if( auth = getEnvBin1st(P_SUDOAUTH) ){
			if( checkAuth(Conn,auth,P_SUDOAUTH,PW_sudo) != 0 ){
				return -2;
			}
		}else
		if( getuid() != 0 ){
			fprintf(stderr,"ERROR: NO built-in %s\n",P_SUDOAUTH);
			return -3;
		}
	}
	return 0;
}
int checkEXECAUTH(Connection *Conn,int ac,const char *av[]){
	const char *auth;
	if( auth = getEnvBin1st(P_EXECAUTH) ){
		if( checkAuth(Conn,auth,P_EXECAUTH,PW_exec) != 0 ){
			return -1;
		}
	}
	return 0;
}
int FimpByOwner(PCStr(func)){
	const char *exec;
	IStr(user,128);
	IStr(owner,128);
	int imowner = 0;

	if( funcFunc(func) != implant_main )
		return 0;

	exec = getEXEC_PATH();
	myName(AVStr(user),sizeof(user));
	getowner(exec,AVStr(owner),sizeof(owner),VStrNULL,0);
	if( isWindows() ){
		imowner = streq(user,owner);
	}else{
		imowner = File_uid(exec) == getuid() || getuid() == 0;
		if( imowner == 0 ){
			imowner = impAllowed(exec,NULL);
			if( imowner ){
		fprintf(stderr,"**** I remember you as my owner...\n");
			}
		}
	}
	if( imowner ){
		fprintf(stderr,
			"**** %s Forbidden but you (%s) are my owner ****\n",
			func,user);
		fputs("\n",stderr);
		return 1;
	}
	return 0;
}
int checkSUDOAUTH(Connection *Conn,int ac,const char *av[]){
	const char *a1;
	int ai;
	int rcode;

	rcode = checkSUDOAUTH1(Conn,ac,av);
	if( rcode != 0 ){
		for( ai = 0; ai < ac; ai++ ){
			a1 = av[ai];
			if( FimpByOwner(a1) ){
				return 0;
			}
		}
		exit(-1);
	}
	return 0;
}

int putFolded(FILE *ofp,PCStr(head),PCStr(obuf),int elen){
	int ei;
	int pfx;
	int wcc = -1;
	int width = 72;

	fprintf(ofp,"%s",head);
	pfx = strlen(head);
	for( ei = 0; ei < elen; ei += wcc ){
		if( ei+width-pfx < elen ){
			wcc = width-pfx;
			fwrite(obuf+ei,1,wcc,ofp);
			fputs("\r\n",ofp);
		}else{
			wcc = elen - ei;
			fwrite(obuf+ei,1,wcc,ofp);
		}
		pfx = 0;
	}
	fprintf(ofp,":\r\n");
	return 0;
}
int getFolded(FILE *ifp,PVStr(enc),PCStr(encx)){
	refQStr(ep,enc);
	int rem;

	if( strchr(enc,':') ){
		return 0;
	}
	ep = enc + strlen(enc);
	for(;;){
		while( enc < ep && (ep[-1] == '\r' || ep[-1] == '\n') )
			ep--;
		if( str_fgets(AVStr(ep),encx-ep,ifp) == NULL )
			break;
		if( strchr(ep,':') )
			break;
		ep += strlen(ep);
	}
	return 1;
}

int encTextFile(FILE *ifp,FILE *ofp,PCStr(opts),PCStr(ckey),PCStr(head)){
	CStr(ibuf,MAXIMPSIZE);
	CStr(obuf,MAXIMPSIZE*2);
	int isbin = 0;
	int ioff = 0;
	int irem = 0;
	int nirem = 0;
	int nioff;
	int ilen;
	int rcc;
	int elen;

	for(;;){
		irem = 0;
		if( nirem ){
			Bcopy(ibuf+nioff,ibuf,nirem);
			irem = nirem;
			nirem = 0;
		}
		ioff = ftell(ifp);
		rcc = fread(ibuf+irem,1,sizeof(ibuf)/2,ifp);
		if( irem == 0 && rcc <= 0 )
			break;
		ilen = irem+rcc;
		nirem = 0;
		if( !isbin ){
			int ix;
			int ich;
			for( ix = 0; ix < rcc; ix++ ){
				ich = ibuf[irem+ix];
				if( ich == 0 ){
					isbin = 1;
					break;
				}
			}
			if( !isbin )
			for( ix = rcc-1; 0 <= ix; ix-- ){
				ich = ibuf[irem+ix];
				if( ich == '\n' ){
					nirem = rcc - (ix + 1);
					nioff = irem + ix + 1;
					ilen -= nirem;
					break;
				}
			}
		}
		elen = enCreysX(opts,ckey,ibuf,ilen,AVStr(obuf),sizeof(obuf));
		if( 0 < elen ){
			putFolded(ofp,head,obuf,elen);
		}else{
			fprintf(stderr,"-- encryption ERROR [%d/%d]\n",
				elen,rcc);
			return -1;
		}
	}
	return 0;
}
int decrypt1(PCStr(opts),PCStr(ckey),PCStr(edata),PVStr(obuf),int osiz){
	IStr(nkey,128);
	int dlen;

	dlen = deCreys(opts,ckey,edata,AVStr(obuf),osiz);
	if( 0 <= dlen )
		return dlen;
	if( ckey[0] != 0 )
		return -1;

	if( getCryptKeyMainArg(P_PASSWD,PW_ext,"",AVStr(nkey),sizeof(nkey)) < 0 )
		getCryptKeyTty(P_PASSWD,PW_ext,"",AVStr(nkey),sizeof(nkey));
	if( nkey[0] == 0 ){
		fprintf(stderr,"-- CAN'T GET THE KEY TO DECRYPT\n");
		return -1;
	}

	dlen = deCreys(opts,nkey,edata,AVStr(obuf),osiz);
	if( dlen < 0 ){
		fprintf(stderr,"-- CAN'T DECRYPT with the key[%s]\n",nkey);
	}
	return dlen;
}
int decFile(FILE *ifp,FILE *ofp,PCStr(opts),PCStr(ckey),PCStr(head)){
	CStr(ibuf,MAXIMPSIZE*2);
	CStr(obuf,MAXIMPSIZE);
	refQStr(enc,ibuf);
	int dlen;
	int hlen = strlen(head);
	CStr(ckeyb,128);

	for(;;){
		if( fgets(ibuf,sizeof(ibuf),ifp) == NULL )
			break;
		if( enc = strstr(ibuf,head) ){
			getFolded(ifp,DVStr(enc,hlen),&ibuf[sizeof(ibuf)-1]);
			dlen = deCreys(opts,ckey,enc+hlen,
				AVStr(obuf),sizeof(obuf));
			if( dlen < 0 ){
				if( 0 < getCryptKeyTty(P_PASSWD,PW_ext,"",
					AVStr(ckeyb),sizeof(ckeyb)) ){
					dlen = deCreys(opts,ckeyb,enc+hlen,
						AVStr(obuf),sizeof(obuf));
					if( 0 <= dlen ){
						ckey = ckeyb;
					}
				}
				if( dlen < 0 ){
					fprintf(stderr,"-- CAN'T DECRYPT\n");
						return -1;
				}
			}
			if( 0 < dlen ){
				fwrite(obuf,1,dlen,ofp);
			}
		}else{
			fputs(ibuf,ofp);
		}
	}
	return 0;
}

static void enc_help(int ac,const char *av[],FILE *out,int enc){
	if( enc )
		fprintf(stderr,
"Usage: %s [-kKey] [infile] [-o outfile] [-a arg1 arg2 ...]\n",av[0]);
	else	fprintf(stderr,
"Usage: %s [-kKey] [infile] [-o outifle] [-a +=enc:xxx:...] \n",av[0]);
}
/*
 * -Fenc [-kKEY] [-o outfile] -a arg1 arg2 ...
 * -Fenc [-kKEY] [-o outfile] [infile]  ... convey the data and mode of infile?
 * -Fdec [-kKEY] [-o outfile] [infile]
 * -Fenc [-kKEY] file
 * -Fdec [-kKEY] file
 */
int encdecarg_main(int ac,const char *av[],int enc){
	int ai;
	int aj;
	const char *a1;
	IStr(opts,128);
	IStr(ckey,128);
	FILE *ifp = stdin;
	FILE *ofp = stdout;
	const char *ifile = 0;
	const char *ofile = 0;
	CStr(opath,1024);
	CStr(ipath,1024);
	int force = 0;
	int fedit = 0;
	refQStr(dp,opath);
	CStr(ibuf,MAXIMPSIZE);
	CStr(obuf,MAXIMPSIZE*2);
	refQStr(ip,ibuf);
	const char *ox = &obuf[sizeof(obuf)-1];
	const char *np;
	int rcc;
	CStr(head,128);
	int hlen;
	int elen;
	int dlen;
	int setif = 0;
	CStr(lsfmt,128);

	if( isWindows() )
		strcpy(lsfmt,"%T%M%3L %8S %D %N");
	else	strcpy(lsfmt,"%T%M%3L %-7O %-5G %8S %D %N");
	strcpy(opts,"bt");
	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( streq(a1,"-a") ){
			break;
		}else
		if( streq(a1,"-h") ){
			enc_help(ac,av,stderr,enc);
			return 0;
		}else
		if( ai == 1 && strneq(a1,"-k",2) ){
			strcpy(ckey,a1+2);
		}else
		if( streq(a1,"-e") ){
			fedit = 1;
		}else
		if( streq(a1,"-es") ){
			strcpy(opts,"ts");
		}else
		if( streq(a1,"-ex") ){
			strcpy(opts,"t");
		}else
		if( streq(a1,"-f") ){
			force = 1;
		}else
		if( streq(a1,"-o") ){
			if( ai+1 < ac ){
				ai++;
				a1 = av[ai];
				if( streq(a1,"-") )
					ofp = stdout;
				else	ofp = fopen(a1,"w");
				if( ofp == NULL ){
					fprintf(stderr,"Cannot open: %s\n",a1);
					return -1;
				}
				ofile = a1;
			}
		}else
		if( strneq(a1,"+=enc:",6) ){
			sprintf(ip,"%s\n",a1);
			ip += strlen(ip);
		}else
		if( *a1 == '-' && !streq(a1,"-") ){
			break;
		}else
		if( setif == 0 ){
			setif++;
			if( streq(a1,"-") )
				ifp = stdin;
			else{
				if( enc ){
					ifp = fopen(a1,"r");
					ifile = a1;
				}else{
					sprintf(ipath,"%s.enc",a1);
					if( ifp = fopen(ipath,"r") ){
						ifile = ipath;
					}else{
						ifp = fopen(a1,"r");
						ifile = a1;
					}
				}
			}
			if( ifp == NULL ){
				fprintf(stderr,"Cannot open: %s\n",a1);
				return -1;
			}
		}else{
			break;
		}
	}
	for( aj = ai; aj < ac; aj++ ){
		a1 = av[aj];
		if( aj == ai && streq(a1,"-a") ){
			continue;
		}
		if( streq(a1,"--") )
			break;
		sprintf(ip,"%s\n",a1);
		ip += strlen(ip);
	}

	sprintf(head,"+=enc:ext::");
	hlen = strlen(head);

	if( !isatty(fileno(ifp)) && enc ){
		if( ifile != 0 && ofile == 0 && isatty(fileno(ofp)) ){
			sprintf(opath,"%s.enc",ifile);
			if( File_is(opath) && !force ){
	fprintf(stderr,"*** The target file exists (use -f to overwrite)\n");
			  ls_unix(stderr,"-Ll",AVStr(lsfmt),opath,NULL);
			  return -1;
			}
			if( (ofp = fopen(opath,"w")) == NULL ){
				fprintf(stderr,"Cannot write: -o %s\n",opath);
				return -1;
			}
			encTextFile(ifp,ofp,opts,ckey,head);
			fclose(ofp);
			ls_unix(stderr,"-Ll",AVStr(lsfmt),ifile,NULL);
			ls_unix(stderr,"-Ll",AVStr(lsfmt),opath,NULL);
		}else{
			encTextFile(ifp,ofp,opts,ckey,head);
		}
		return 0;
	}
	if( !isatty(fileno(ifp)) && enc == 0 ){
		int owas = 0;
		if( ifile != 0 && ofile == 0 && isatty(fileno(ofp)) ){
			strcpy(opath,ifile);
			if( dp = strtailstr(opath,".enc") )
				setVStrEnd(dp,0);
			else	strcat(opath,".dec");

			owas = File_is(opath);
			if( owas && !force && !fedit ){
	fprintf(stderr,"*** The target file exists (use -f to overwrite)\n");
			  ls_unix(stderr,"-Ll",AVStr(lsfmt),opath,NULL);
			  return -1;
			}
			if( (ofp = fopen(opath,"w")) == NULL ){
				fprintf(stderr,"Cannot write: -o %s\n",opath);
				return -1;
			}
			decFile(ifp,ofp,opts,ckey,head);
			fclose(ofp);
			ls_unix(stderr,"-Ll",AVStr(lsfmt),ifile,NULL);
			ls_unix(stderr,"-Ll",AVStr(lsfmt),opath,NULL);

			if( fedit && isatty(0) ){
				CStr(compath,1024);
				CStr(comd,1024);
				const char *vi;
				if( (vi = DELEGATE_getEnv("VISUAL")) == 0 )
				if( (vi = DELEGATE_getEnv("EDITOR")) == 0 )
					vi = "vi";
				if( fullpathCOM(vi,"r",AVStr(compath)) ){
					sprintf(comd,"%s %s",compath,opath);
					IGNRETZ system(comd);
					ifp = fopen(opath,"r");
					ofp = fopen(ifile,"w");
					encTextFile(ifp,ofp,opts,ckey,head);

					if( owas )
				ls_unix(stderr,"-Ll",AVStr(lsfmt),opath,NULL);
					else	unlink(opath);
				ls_unix(stderr,"-Ll",AVStr(lsfmt),ifile,NULL);
				}
			}
		}else{
			decFile(ifp,ofp,opts,ckey,head);
			fflush(ofp);
		}
		return 0;
	}

	if( !isatty(0) || ifp != stdin ){
		int rem = sizeof(ibuf) - 1 - (ip-ibuf);
		rcc = fread((char*)ip,1,QVSSize(ip,rem),ifp);
		if( rcc < 0 ){
			return -1;
		}
		setVStrEnd(ip,rcc);
	}

	if( ibuf[0] == 0 ){
		enc_help(ac,av,stderr,enc);
		return -1;
	}

	sprintf(head,"+=enc:ext::");
	hlen = strlen(head);
	if( enc ){
		elen = enCreys(opts,ckey,ibuf,AVStr(obuf),sizeof(obuf));
		if( 0 < elen ){
			fprintf(ofp,"%s%s:\r\n",head,obuf);
		}
	}else{
	    const char *enc;
	    for( np = ibuf; *np; ){
		CStr(line,MAXIMPSIZE);
		np = wordScanY(np,line,"^\n");
		if( enc = strstr(line,head) ){
			dlen = decrypt1(opts,ckey,enc+hlen,AVStr(obuf),sizeof(obuf));
			if( dlen < 0 )
				break;
			fwrite(obuf,1,dlen,ofp);
		}else{
			fprintf(ofp,"%s\n",line);
		}
		if( *np == '\n' )
			np++;
		else	break;
	    }
	}
	return 0;
}
int argenc_main(int ac,const char *av[]){
	return encdecarg_main(ac,av,1);
}
int argdec_main(int ac,const char *av[]){
	return encdecarg_main(ac,av,0);
}

int getFoldedEnc(FILE *sfp,PVStr(enc),PCStr(encx)){
	refQStr(ep,enc);
	const char *dp;
	CStr(dom,1024);
	CStr(user,1024);
	int comp = 0;

	dp = wordScanY(enc,dom,"^:");
	if( *dp == ':' ){
		dp = wordScanY(dp+1,user,"^:");
		if( *dp == ':' ){
			if( strchr(dp+1,':') ){
				comp = 1;
			}
		}
	}
	if( comp ){
		return 0;
	}else{
		if( (ep = strpbrk(enc,"\r\n")) == 0 )
			ep = enc+strlen(enc);
		getFolded(sfp,AVStr(ep),encx);
		return 1;
	}
}
int encDecrypt(PCStr(estr),PVStr(dconf),int dsize){
	const char *ep;
	IStr(dom,128);
	IStr(user,128);
	IStr(etype,128);
	CStr(key,128);
	int klen = 0;
	int dlen = -1;
	int decrypted = 0;

	ep = wordScanY(estr,dom,"^:");
	if( *ep != ':' ){
		fprintf(stderr,"ERROR: enc:%s\n",estr);
		return -1;
	}
	ep++;
	ep = wordScanY(ep,user,"^:");
	if( *ep != ':' ){
		fprintf(stderr,"ERROR: enc:%s\n",estr);
		return -1;
	}
	ep++;
	wordScanY(ep,etype,"^.");

	if( lCRYPT() )
	fprintf(stderr,"---- Loading Encrypted Data [%s][%s][%s]\n",
		dom,user,etype);
	if( *etype == '0' ){
		dlen = deCreys("","",ep,AVStr(dconf),dsize);
	}else
	if( *etype == '1' ){
		/*
		if( isatty(fileno(stderr)) )
		this is necessary for service/Win or auto. start of daemon
		*/
		klen = getCryptKeyX(MainConn(),0xFF,P_PASSWD,dom,user,
			AVStr(key),sizeof(key));
		if( 0 <= klen ){
			dlen = deCreys("",key,ep,AVStr(dconf),dsize);
			if( dlen < 0 ){
				fprintf(stderr,"---- BAD KEY for %s=%s:%s\n",
					P_PASSWD,dom,user);
				Finish(-1);
			}
			decrypted = 1;
		}
	}else{
	}
	if( decrypted == 0 ){
		if( lSECUREEXT() ){
			fprintf(stderr,"---- Not encrypted: %s\n",estr);
			Finish(-1);
		}
	}
	return dlen;
}

void CTX_eval_script(DGC*Conn,FILE *sfp,PCStr(name),PCStr(base),PCStr(url),PCStr(cases),int encrypted,ArgComp *Acmp);
int CTX_load_encrypted(Connection *Conn,PCStr(name),PCStr(base),PCStr(estr)){
	CStr(dconf,MAXIMPSIZE);
	int dlen = -1;
	FILE *tmp;
	const char *dp;
	const char *np;
	CStr(line,1024);
	CStr(buf,MAXIMPSIZE);
	refQStr(bp,buf);

	dlen = encDecrypt(estr,AVStr(dconf),sizeof(dconf));
	if( dlen < 0 ){
		return -1;
	}
	if( dlen == 0 ){
		return 0;
	}

	for( dp = dconf; *dp; dp = np ){
		np = wordScanY(dp,line,"^\n");
		if( *line == '_' ){
			if( isatty(fileno(stderr)) ){
				if( strheadstrX(line,_P_IMPLAST,0) )
				fprintf(stderr,"%s\n",line);
			}
		}else{
			sprintf(bp,"%s\n",line);
			bp += strlen(bp);
		}
		if( *np == '\n' )
			np++;
		else	break;
	}
	tmp = str_fopen(buf,strlen(buf),"r");
	CTX_eval_script(Conn,tmp,name,base,"enc:","",1,NULL);
	str_fclose(tmp);
	return 0;
}

int fromRsh();
int fromSSH();
int fromCGI();
int exesign_main(int ac,const char *av[]){
	int ai;
	const char *a1;
	const char *iexe = 0;
	const char *oexe = 0;
	int fovw = 0;
	int fverb = 0;
	int fsilent = 0;
	CStr(mypath,1024);
	CStr(buf,1024);
	refQStr(dp,buf);
	FILE *ifp = stdin;
	FILE *ofp = 0;
	MD5 *md5 = 0;
	CStr(xd,64);
	FileSign ssig;
	FileSign bsig;
	FileSign fsig;
	int whsig = SIG_EXE;
	int mtime;
	CStr(lsfmt,128);

	strcpy(lsfmt,"%T%M%3L %-7O %-5G %8S %D %N");
	bzero(&fsig,sizeof(fsig)); fsig.s_off = -1;
	bzero(&bsig,sizeof(fsig)); bsig.s_off = -1;
	bzero(&ssig,sizeof(ssig)); ssig.s_off = -1;
	md5 = newMD5();

	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( streq(a1,"-vv") ){
			fverb = 1;
		}else
		if( streq(a1,"-vs") ){
			fsilent = 2;
		}else
		if( streq(a1,"-s") ){
			fsilent = 1;
		}else
		if( streq(a1,"-w") ){
			fovw = 1;
		}else
		if( streq(a1,"-o") ){
			if( ai+1 < ac ){
				a1 = av[++ai];
				if( streq(a1,"-") ){
					oexe = "";
					ofp = stdout;
				}else{
					oexe = a1;
					ofp = fopen(a1,"r+");
					if( ofp == NULL ){
						ofp = fopen(a1,"w");
					}
					if( ofp == NULL ){
				fprintf(stderr,"Cannot open: %s\n",a1);
						break;
					}
				}
			}
		}else
		if( streq(a1,"-m") ){
		}else{
			if( iexe != 0 && ifp != NULL ){
			getsigns(iexe,fovw,fverb,ifp,ofp,&ssig,&bsig,&fsig,md5,AVStr(xd),fsilent,whsig);
				bzero(&fsig,sizeof(fsig)); fsig.s_off = -1;
				bzero(&ssig,sizeof(ssig)); ssig.s_off = -1;
				md5 = newMD5();
			}

			iexe = a1;
			ifp = fopen(iexe,"r+");
			if( ifp == NULL ){
				ifp = fopen(iexe,"r");
			}
			if( ifp == NULL ){
				fprintf(stderr,"Cannot open: %s\n",iexe);
				return -1;
			}
		}
	}
	/*
	if( iexe == 0 && isatty(fileno(stdin)) ){
	*/
	if( iexe == 0 )
	if( isatty(fileno(stdin))
	 || fromCGI()
	 || fromSSH()
	 || fromRsh()
	){
		strcpy(mypath,EXEC_PATH);
		FullpathOfExe(AVStr(mypath));
		iexe = mypath;
		ifp = fopen(iexe,"r");
		if( ifp == NULL ){
			fprintf(stderr,"Cannot open: %s\n",iexe);
			return -1;
		}
	}
	if( ofp == 0 && fovw ){
		if( iexe ){
			oexe = iexe;
			ofp = fopen(iexe,"r+");
		}
	}
	if( iexe == 0 ){
		iexe = "-stdin";
	}

	mtime = file_mtime(fileno(ifp));
	getsigns(iexe,fovw,fverb,ifp,ofp,&ssig,&bsig,&fsig,md5,AVStr(xd),fsilent,SIG_EXE);

	if( md5 )
	if( ofp )
	if( 0 <= fsig.s_from && 0 <= fsig.s_to )
	if( 0 < (fsig.s_to - fsig.s_from) ){
		int bsize,rcc;
		bsize = fsig.s_to - fsig.s_from;

		/* should check the protection recorded in the original sign
		 * (ex. if the sign can be copied/updated/modified or not,
		 * recorded possiblly with passphrase or RSA sign)
		 * and the ownership (user and group) of the target file...
		 */

		if( 0 <= fsig.s_from )
		if( fseek(ifp,fsig.s_from,0) == 0 )
		if( rcc = fread(buf,1,QVSSize(buf,bsize),ifp) )
		if( rcc == bsize ){
			CStr(ndate,32);
			CStr(nsign,512);
			CStr(id,512);
			CStr(newsig,1024);
			const char *signer = "Author@DeleGate.ORG";
			int len,bi;
			FILE *pfp;
			FileSign nsig;

			setVStrEnd(buf,rcc);
			StrftimeLocal(AVStr(ndate),sizeof(ndate),
				"%Y%m%d%H%M%S%z",time(0),0);
			sprintf(id,"%s:%s:%s:%s",fsig.s_ver,ndate,xd,signer);
			strcpy(nsign,"");
			if( getenv("SIGPASS") ){
				CStr(com,1024);
				sprintf(com,"rsasign %s",id);
				if( pfp = popen(com,"r") ){
					refQStr(np,nsign);
					while( fgets(np,sizeof(nsign),pfp) ){
						np += strlen(np);
					}
					strsubst(AVStr(nsign),"\n","");
					pclose(pfp);
				}
			}
			if( nsign[0] == 0 ){
				strcpy(nsign,"-");
				signer = ADMIN;
			}
			setVStrEnd(xd,16);
			sprintf(id,"%s:%s:%s:%s",fsig.s_ver,ndate,xd,
				signer);
			sprintf(newsig,"%s:%s",id,nsign);
			Bcopy(newsig,buf,strlen(newsig));
			len = strlen(buf) - 2;
			/*
			for( bi = 1+strlen(newsig); bi < len; bi++ ){
			*/
			for( bi = strlen(newsig); bi < len; bi++ ){
				setVStrElem(buf,bi,'\'');
			}

			printSign(stderr,&fsig,"old> ");
			bzero(&nsig,sizeof(FileSign));
			scanFileSign(buf,&nsig);
			printSign(stderr,&nsig,"new> ");
			if( streq(fsig.s_ver,nsig.s_ver)
			 && streq(fsig.s_md5,nsig.s_md5)
			 && streq(fsig.s_signer,nsig.s_signer)
			){
				fprintf(stderr,"** No need to update the sign\n");
			}else{
				if( !fsilent )
					fprintf(stderr,"%s\n",buf);
				if( fseek(ofp,fsig.s_from,0) == 0 ){
					fwrite(buf,1,bsize,ofp);
				}
			}
			fflush(ofp);
			set_futimes(fileno(ofp),mtime,mtime);
			if( *oexe && *oexe != '-' ){
				/* fix-140509f keep the file modification time
				 * after -Fesign -w
				 */
				fclose(ofp);
				set_utimes(oexe,mtime,mtime);
			}
			ls_unix(stderr,"-Ll",AVStr(lsfmt),oexe,NULL);
		}
	}
	return 0;
}

int exeMD5(FILE *fp,MD5 *md5,PVStr(amd5),int silent){
	FileSign ssig;
	FileSign bsig;
	FileSign fsig;

	bzero(&fsig,sizeof(fsig)); fsig.s_off = -1;
	bzero(&bsig,sizeof(bsig)); bsig.s_off = -1;
	bzero(&ssig,sizeof(ssig)); ssig.s_off = -1;
	if( silent ){
		fsig.s_flags = FS_NOCHECK;
		bsig.s_flags = FS_NOCHECK;
		ssig.s_flags = FS_NOCHECK;
	}
	if( md5 == NULL )
		md5 = newMD5();
	setVStrEnd(amd5,0);
	getsigns("",0,0,fp,NULL,&ssig,&bsig,&fsig,md5,BVStr(amd5),silent,SIG_EXE);
	return 0;
}

static int fileStatCRC;
static char *fileSign;
int getFileSIGN(PCStr(file),PVStr(sign)){
	FileSign ssig,bsig,fsig;
	MD5 *md5;
	IStr(amd5,128);
	FILE *fp;
	int silent = 1;
	FileStat st;
	int crc = 0;

	bzero(&st,sizeof(st));
	if( stat(file,&st) == 0 ){
		st.st_atime = 0;
		crc = strCRC32((char*)&st,sizeof(st));
	}
	if( fileSign ){
		if( crc == fileStatCRC ){
			strcpy(sign,fileSign);
			return 0;
		}
	}
	sv1log("getFileSIGN %X %X %s\n",fileStatCRC,crc,file);
	clearVStr(sign);

	md5 = newMD5();
	bzero(&fsig,sizeof(fsig)); fsig.s_off = -1; fsig.s_flags = FS_NOCHECK;
	bzero(&bsig,sizeof(bsig)); bsig.s_off = -1; bsig.s_flags = FS_NOCHECK;
	bzero(&ssig,sizeof(ssig)); ssig.s_off = -1; ssig.s_flags = FS_NOCHECK;

	fp = fopen(file,"r");
	if( fp == NULL ){
		return -1;
	}
	getsigns(file,0,0,fp,NULL,&ssig,&bsig,&fsig,md5,AVStr(amd5),silent,SIG_EXE);
	fclose(fp);

	sprintSign(TVStr(sign),&ssig);
	sprintSign(TVStr(sign),&bsig);
	sprintSign(TVStr(sign),&fsig);

	if( fileSign ){
		free(fileSign);
	}
	fileStatCRC = crc;
	fileSign = stralloc(sign);
	return 0;
}

char *fgetsE(PVStr(str),int siz,FILE *fp){
	int ch;
	int pch = EOF;
	refQStr(sp,str);
	const char *sx;

	/* v9.9.11 fix-140803i, a recovery to make -Fimp work again.
	 * This check is introduced in v9.9.7-pre24 (2010-02-11,
	 * from the time stamp of dgsign.c) without any explanation
	 * in CHANGES.
	 * The comparation "MAXSIZE <= siz" is very strange because
	 * it makes findNOSIGN() fail always because it calls this
	 * function with siz==MAXSIZE, and then -Fimp calling
	 * findNOSIGN() stoppes to work with the error message bellow.
	 * It is possible that this was a trial to avoid the infinite
	 * loop in getting the "NOSIGN" (what does this mean?) from
	 * directory (of the same name with the executable).  The case
	 * was solved in v9.9.7-pre25 (2010-02-13, from CHANGES) by
	 * the code bellow with "FATAL" message and "(errno=EISDIR)"
	 * comment.
	 * Also in -pre25, it seems that it was finally fixed in
	 * file.c:fopen_PATHX() (on the same day, 2010-02-13 from
	 * CHANGES) with warning message including "ign.dir...".
	 * Anyway, this check causes the problem only when it is
	 * called for -Fimp, and by this modification -Fimp is not
	 * broken any more but is fixed, maybe without side effect,
	 * so decided to apply this modification.
	if( siz <= 3 || MAXIMPSIZE <= siz ){
	}
	 */
	if( siz <= 3 || MAXIMPSIZE < siz ){
		IStr(msg,128);
		sprintf(msg,"##{FATAL:fgetsE(%s:%d,siz=%X,%X:%u:%d)}##",
			whStr(str),siz,p2i(fp),iftell(fp),feof(fp));
		fprintf(stderr,"%s\r\n",msg);
		syslog_ERROR("%s\n",msg);
		_exit(-1);
	}
	sx = &str[siz-3];
	errno = 0;
	ch = 0;
	for( sp = str; sp < sx; ){
		ch = getc(fp);

		if( ch == '{' )
		/* v9.9.12 fix-140913c, not to split {FILESIGN=...} on boundary */
		if( pch == 0x00 || (pch & 0x80) ) /* in binary without NL ended */
		{
			int MAXSIGNSIZE = 512; /* 256 or so is enough ? */
			if( siz-(sp-str) < MAXSIGNSIZE ){ 
				ungetc(ch,fp);
				break;
			}
		}
		if( pch == '}' )
		/* v9.9.12 fix-140913d, not to be filled with binary after end */
		{
			if( ch != '\n'
			 && ch != '"' /* for "{NOSIGN:...}" */
			){
				ungetc(ch,fp);
				break;
			}
		}
		pch = ch;

		if( ch == EOF )
			break;
		if( ch=='`' || ch=='~' || ch=='$' || ch=='#' || ch=='?' ){
			setVStrPtrInc(sp,'`'); setVStrPtrInc(sp,ch);
		}else
		if( ch == 0x7F ){
			setVStrPtrInc(sp,'`'); setVStrPtrInc(sp,'d');
		}else
		if( 0x00 <= ch && ch < 0x20 && ch != '\n' && ch != '\t' ){
			setVStrPtrInc(sp,'`'); setVStrPtrInc(sp,ch+'@');
		}else
		if( 0x80 <= ch && ch < 0xA0 ){
			setVStrPtrInc(sp,'~'); setVStrPtrInc(sp,ch-0x80+'@');
		}else
		if( 0xA0 <= ch && ch < 0xC0 ){
			setVStrPtrInc(sp,'$'); setVStrPtrInc(sp,ch-0xA0+'@');
		}else
		if( 0xC0 <= ch && ch < 0xE0 ){
			setVStrPtrInc(sp,'#'); setVStrPtrInc(sp,ch-0xC0+'@');
		}else
		if( 0xE0 <= ch ){
			setVStrPtrInc(sp,'?'); setVStrPtrInc(sp,ch-0xE0+'@');
		}else{
			setVStrPtrInc(sp,ch);
			if( ch == '\n' )
				break;
		}
	}
	setVStrEnd(sp,0);
	if( sp == str && feof(fp) )
		return NULL;
	if( sp == str && ch == EOF ){
		IStr(msg,128);
		sprintf(msg,"##{FATAL:fgetsE(%s:%d,siz=%X,%X:%u:%d)}(%X e%d)##",
			whStr(str),siz,p2i(fp),iftell(fp),feof(fp),ch,errno);
		fprintf(stderr,"%s\r\n",msg);
		syslog_ERROR("%s\n",msg);
		/* might be a directory (errno=EISDIR) */
		_exit(-1);
	}
	return (char*)str;
}
int offE(PCStr(str),PCStr(ptr)){
	const char *sp;
	int ch,nch;
	int off = 0;

	for( sp = str; ch = *sp; sp++ ){
		if( sp == ptr ){
//fprintf(stderr,"---- offE %2d / %2d [%x %x %x][%s]\n",off,sp-str,ptr,sp,str,str);
			return off;
		}
		nch = sp[1];
		if( ch == '`' ){
			if( nch )
			switch( nch ){
				case '`':
				case '~': case '$': case '#': case '?':
				case 'd':
					off++;
					sp++; continue;
				case '\n':
					sp++; continue;
			}
		}
		if( ch=='`'  || ch=='~' || ch=='$' || ch=='#' || ch=='?' ){
			if( nch == 0 ){
				break;
			}
			switch( ch ){
				case '`':
				case '~': case '$': case '#': case '?':
					off++;
					sp++; continue;
			}
		}else{
			off++;
		}
	}
 fprintf(stderr,"---- offE %d / %d ? [%x %x %x][%s]\n",
 off,ll2i(sp-str),p2i(ptr),p2i(sp),p2i(str),str);
	return -1;
}
int fputsEX(PCStr(str),FILE *fp,FILE *in){
	int ch;
	int nch;
	const char *sp;

	for( sp = str; ch = *sp; sp++ ){
		nch = sp[1];
		if( ch=='`' ){
			switch( nch ){
				case '`':
				case '~': case '$': case '#': case '?':
					putc(nch,fp); sp++;
					continue;
				case 'd':
					putc(0x7F,fp); sp++;
					continue;
				case '\n':
					sp++;
					continue;
			}
		}
		if( ch=='`'  || ch=='~' || ch=='$' || ch=='#' || ch=='?' ){
			if( nch == 0 ){
				if( in != NULL ){
					ungetc(ch,in);
				}else{
					fprintf(stderr,"--- fputSX ` %X\n",p2i(in));
				}
				break;
			}
			if( nch < '@' || '_' < nch ){
				fprintf(stderr,"--- fputSX unknown ^%X\n",nch);
			}
			switch( ch ){
				case '`': putc(nch-'@',fp); sp++; break;
				case '~': putc(nch-'@'+0x80,fp); sp++; break;
				case '$': putc(nch-'@'+0xA0,fp); sp++; break;
				case '#': putc(nch-'@'+0xC0,fp); sp++; break;
				case '?': putc(nch-'@'+0xE0,fp); sp++; break;
			}
		}else{
			putc(ch,fp);
		}
	}
	return 0;
}
int fputsE(PCStr(str),FILE *fp){
	return fputsEX(str,fp,NULL);
}
int trx_main(int ac,const char *av[]){
	const char *a1;
	int ai;
	int fdec = 0;
	FILE *in = stdin;
	FILE *out = stdout;
	CStr(buf,8*1024);

	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( streq(a1,"-d") ){
			fdec = 1;
		}
	}
	for(;;){
		if( fdec ){
			if( fgets(buf,sizeof(buf),in) == NULL )
				break;
			fputsEX(buf,out,in);
		}else{
			if( fgetsE(AVStr(buf),sizeof(buf),in) == NULL )
				break;
			fputs(buf,out);
		}
	}
	if( !fdec ){
		fputs("`\n",out);
	}
	return 0;
}
