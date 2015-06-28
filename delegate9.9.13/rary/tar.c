/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	tar.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	000510	created
TODO:
	tar-diff file1.tar file2.tar
	tar-patch
	tar-cat file1.tar file2.tar > file3.tar
	tar-file --> selection --> tar-file
	tar-file --> conversion --> MIME multipart
	(Unix)MBOX to/from TAR conversion

	symbolic-tar ... binary data with BASE64 encoding
	indexed-tar ... a tar file including a index file(s)
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include "ystring.h"
#include "proc.h"
#include "file.h"

char *getUsernameCached(int,PVStr(user));
char *getGroupname(int,PVStr(group));
void MIME_to64X(FILE *in, FILE *out, int leng);
void _to64(FILE *in,FILE *out);

void sedFilter(FILE *in,FILE *out,PCStr(comline),PCStr(args));

const char *INHERENT_thread();

void tar_add(FILE *tfp,FILE *msg,PCStr(dir),const char *files[]);

#define TBLOCK 512
#define NAMSIZ 100
typedef struct header {
	MStr(	x_name,NAMSIZ);
	MStr(	x_mode,8);
	MStr(	x_uid,8);
	MStr(	x_gid,8);
	MStr(	x_size,12);
	MStr(	x_mtime,12);
	MStr(	x_chksum,8);
	char	x_linkflag;
	MStr(	x_linkname,NAMSIZ);
} Header;
/**/

typedef union hblock {
  unsigned char	dummy[TBLOCK];
	Header	dbuf;
} HBlock;
typedef struct {
	MStr(	h_name,NAMSIZ);
	long	h_mode;
	long	h_uid;
	long	h_gid;
	long	h_size;
	long	h_mtime;
	long	h_chksum;
	long	h_linkflag;
	MStr(	h_linkname,NAMSIZ);
} iHeader;

#define OP_CREATE	1	/* c */
#define OP_APPEND	2	/* r */
#define OP_LIST		3	/* t */
#define OP_UPDATE	4	/* u */
#define OP_EXTRACT	5	/* x */
#define OP_EDIT		6	/* e (private extension) */

static void itoo(PVStr(str),int siz,int val)
{
	CStr(fmt,32);
	CStr(buf,32);
	sprintf(fmt,"%%0%do",siz-1);
	sprintf(buf,fmt,val);
	strncpy(str,buf,siz);
}
static int headsum(HBlock *hbp)
{	int sum,i;
	const unsigned char *hp;
	const unsigned char *xp;
	const unsigned char *yp;

	sum = 0;
	hp = hbp->dummy;
	xp = (const unsigned char*)hbp->dbuf.x_chksum;
	yp = xp + 7;
	for( i = 0; i < sizeof(HBlock); i++,hp++ ){
		if( hp < xp || yp < hp )
			sum += *hp;
		else	sum += ' ';
	}
	return sum;
}
static void set_chksum(HBlock *Hp)
{	Header *hp = &Hp->dbuf;

/*
	sprintf(hp->x_chksum,"%*o",sizeof(hp->x_chksum)-2,headsum(Hp));
*/
	itoo(AVStr(hp->x_chksum),sizeof(hp->x_chksum)-1,headsum(Hp));
	hp->x_chksum[7] = ' ';
}
static int dirtar(PCStr(file1),PCStr(dir),FILE *tfp,FILE *msg)
{	const char *files[2]; /**/
	CStr(path,1024);

	if( strcmp(file1,".") == 0 || strcmp(file1,"..") == 0 )
		return 0;
	if( dir[0] ){
		while( *file1 == '/' )
			file1++;
		if( strtailchr(dir) != '/' )
			sprintf(path,"%s/%s",dir,file1);
		else	sprintf(path,"%s%s",dir,file1);
		files[0] = path;
	}else	files[0] = (char*)file1;
	files[1] = 0;
	tar_add(tfp,msg,dir,files);
	return 0;
}
void tar_adding(FILE *tfp,FILE *msg,const char *files[])
{	CStr(buf,512);

	tar_add(tfp,msg,"",files);
	bzero(buf,sizeof(buf));
	fwrite(buf,1,512,tfp);
	fwrite(buf,1,512,tfp);
}
static void iprb(iHeader *iHp,FILE *msg);
static void ntoh(Header *Hp,iHeader *iHp);
void tar_add(FILE *tfp,FILE *msg,PCStr(dir),const char *files[])
{	HBlock head;
	Header *hp;
	iHeader ihead;
	const char *file1;
	int fi;
	FILE *fp;
	int size1,bsize;
	CStr(buf,512);
	int rem,rcc;
	CStr(link1,1024);
	char type1;
	int mode1,uid1,gid1,mtime1;
	CStr(path,1024);

	hp = &head.dbuf;
	bzero(&head,sizeof(head));
	for( fi = 0; file1 = files[fi]; fi++ ){
		fp = NULL;
		if( 0 <= (rcc = readlink(file1,link1,QVZsizeof(link1))) ){
			setVStrEnd(link1,rcc);
			File_stats(file1,1,&mode1,&uid1,&gid1,&size1,&mtime1);
			size1 = 0;
			type1 = '2';
		}else{
			File_stats(file1,0,&mode1,&uid1,&gid1,&size1,&mtime1);
			link1[0] = 0;
			if( fileIsdir(file1) ){
				type1 = '5';
				size1 = 0;
			}else{
				fp = fopen(file1,"r");
				if( fp == NULL ){
					fprintf(msg,"cannot open file: %s\n",file1);
					break;
				}
				type1 = '0';
				size1 = file_size(fileno(fp));
			}
		}

		if( strncmp(file1,"./",2) != 0 ){
			strcpy(path,"./");
			if( *file1 == '/' )
				Xstrcpy(DVStr(path,2),file1+1);
			else	Xstrcpy(DVStr(path,2),file1);
		}else{
			strcpy(path,file1);
		}
		if( type1 == '5' && strtailchr(path) != '/' )
			strcat(path,"/");
		Xstrncpy(AVStr(hp->x_name),path,sizeof(hp->x_name));
		itoo(AVStr(hp->x_mode),sizeof(hp->x_mode),mode1);
		itoo(AVStr(hp->x_uid),sizeof(hp->x_uid),uid1);
		itoo(AVStr(hp->x_gid),sizeof(hp->x_gid),gid1);
		itoo(AVStr(hp->x_size),sizeof(hp->x_size),size1);
		itoo(AVStr(hp->x_mtime),sizeof(hp->x_mtime),mtime1);
		hp->x_linkflag = type1;
		Xstrncpy(AVStr(hp->x_linkname),link1,sizeof(hp->x_linkname));
		set_chksum(&head);
		ntoh(&head.dbuf,&ihead);
		iprb(&ihead,msg);
		fwrite(&head,1,sizeof(head),tfp);

		if( 0 < size1 ){
			bsize = ((size1+511) / 512) * 512;
			for( rem = size1; 0 < rem; rem -= 512 ){
				if( 512 < rem )
					rcc = 512;
				else	rcc = rem;
				IGNRETP fread(buf,1,rcc,fp);
				fwrite(buf,1,rcc,tfp);
			}
			bzero(buf,512);
			fwrite(buf,1,bsize-size1,tfp);
		}
		if( fp )
			fclose(fp);
		if( type1 == '5' )
			Scandir(file1,scanDirCall dirtar,file1,tfp,msg);
	}
}

static int otoi(PCStr(str),int siz)
{	char oc;
	int i,len;

	i = 0;
	for( len = 0; len < siz; len++ ){
		oc = str[len];
		if( '0' <= oc && oc <= '7' )
			i = (i << 3) + (oc - '0');
	}
	return i;
}
static void iprb(iHeader *iHp,FILE *msg)
{	CStr(timeb,64);
	CStr(userb,64);
	CStr(groupb,64);

	switch( iHp->h_linkflag ){
		case 2: fprintf(msg,"l"); break;
		case 5: fprintf(msg,"d"); break;
		default: fprintf(msg,"-"); break;
	}
	fprintf(msg,"%s",FileModes(iHp->h_mode));
	fprintf(msg," %s/%s",getUsernameCached(iHp->h_uid,AVStr(userb)),
		getGroupname(iHp->h_gid,AVStr(groupb)));
	fprintf(msg," %9d",ll2i(iHp->h_size));
	StrftimeLocal(AVStr(timeb),sizeof(timeb),TIMEFORM_TAR,iHp->h_mtime,0);
	fprintf(msg," %s",timeb);
	fprintf(msg," %s",iHp->h_name);
	if( iHp->h_linkflag ){
		switch( iHp->h_linkflag ){
			case 2: fprintf(msg," -> %s",iHp->h_linkname); break;
			case 5: break;
			default: fprintf(msg," [%d][%s]",
					ll2i(iHp->h_linkflag),iHp->h_linkname);
				break;
		}
	}
	fprintf(msg,"\n");
}
static void ntoh(Header *Hp,iHeader *iHp)
{
	strcpy(iHp->h_name,Hp->x_name);
	iHp->h_mode = otoi(Hp->x_mode,sizeof(Hp->x_mode));
	iHp->h_uid = otoi(Hp->x_uid,sizeof(Hp->x_uid));
	iHp->h_gid = otoi(Hp->x_gid,sizeof(Hp->x_gid));
	iHp->h_size = otoi(Hp->x_size,sizeof(Hp->x_size));
	iHp->h_mtime = otoi(Hp->x_mtime,sizeof(Hp->x_mtime));
	iHp->h_chksum = atoi((char*)Hp->x_chksum);
	iHp->h_linkflag = otoi(&Hp->x_linkflag,sizeof(Hp->x_linkflag));
	strcpy(iHp->h_linkname,Hp->x_linkname);
}
static int fmatch(PCStr(cfile),const char *files[])
{	int fi;
	const char *file1;

	if( files == 0 )
		return 0;
	for( fi = 0; file1 = files[fi]; fi++ ){
		if( strtailstr(cfile,file1) )
			return 1;
	}
	return 0;
}
static void putbody(iHeader *iHp,FILE *ifp,FILE *ofp,FILE *msg,PCStr(opts),int size,PCStr(boundary))
{	int ci,ch,icc,rcc,bin;
	unsigned char buf[54*20];
	FILE *sfp;

	icc = sizeof(buf);
	if( size < icc )
		icc = size;
	rcc = fread(buf,1,icc,ifp);

	bin = 0;
	if( strchr(opts,'M') )
	for( ci = 0; ci < rcc; ci++ ){
		ch = buf[ci];
		if( ch < 0x20 ){
			switch( ch ){
				case 0x1B:
				case '\t':
				case '\n':
				case '\r':
					break;
				default:
					bin = 1;
					break;
			}
		}
		if( bin )
			break;
	}

	if( bin ){
		fprintf(ofp,"Content-Type: application/octet-stream\r\n");
		fprintf(ofp,"Content-Transfer-Encoding: base64\r\n");
		fprintf(ofp,"\r\n");
		sfp = str_fopen((char*)buf,rcc,"r");
		_to64(sfp,ofp/*,rcc*/);
		str_fclose(sfp);
		if( 0 < size - rcc )
			MIME_to64X(ifp,ofp,size-rcc);
	}else{
		if( strchr(opts,'M') ){
		fprintf(ofp,"Content-Type: text/plain\r\n");
		fprintf(ofp,"\r\n");
		}
		fwrite(buf,1,rcc,ofp);
		for( ci = rcc; ci < size; ci++ )
			putc(getc(ifp),ofp);
	}
}
static int file_skip(FILE *tfp,int bsize)
{	int ci;

	for( ci = 0; ci < bsize; ci++ )
		if( getc(tfp) == EOF )
			break;
	return ci;
}
static int getbody(Header *Hp,iHeader *iHp,FILE *tfp,FILE *ofp,FILE *msg,PCStr(opts),const char *files[],PCStr(edits),PCStr(boundary))
{	int size,bsize;
	int match,ci;
	int rcode;
	int fd;
	CStr(mdate,64);

	size = iHp->h_size;
	bsize = ((size+511) / 512) * 512;
	if( bsize <= 0 )
		return 0;

	if( files == 0 || files[0] == 0 || fmatch(iHp->h_name,files) ){
		if( strchr(opts,'M') ){
		StrftimeGMT(AVStr(mdate),sizeof(mdate),TIMEFORM_RFC822,iHp->h_mtime,0);
		fprintf(ofp,"\r\n");
		fprintf(ofp,"--%s\r\n",boundary);
		fprintf(ofp,"Content-Length: %d\r\n",size);
		fprintf(ofp,"Last-Modified: %s\r\n",mdate);
		fprintf(ofp,"X-File-Name: %s\r\n",iHp->h_name);
		}
		if( edits && *edits ){
			CStr(nname,128);
			CStr(command,128);
			static FILE *tmpo,*tmpi;
			if( tmpi == NULL ){
				tmpi = TMPFILE("tar-sed-in");
				tmpo = TMPFILE("tar-sed-out");
			}else{
				Ftruncate(tmpi,0,0); fseek(tmpi,0,0);
				Ftruncate(tmpo,0,0); fseek(tmpo,0,0);
			}
			sprintf(command,"tar-sed %s",edits);
			fputs(iHp->h_name,tmpi);
			fflush(tmpi);
			fseek(tmpi,0,0);
			sedFilter(tmpi,tmpo,command,edits);
			fflush(tmpo);
			fseek(tmpo,0,0);
			nname[0] = 0;
			fgets(nname,sizeof(nname),tmpo);
/*
			fclose(tmpi);
			fclose(tmpo);
*/
			if( nname[0] && strcmp(nname,iHp->h_name) != 0 ){
/*
fprintf(msg,"Edited: filename '%s' -> '%s' by '%s'\n",iHp->h_name,nname,edits);
*/
				Xstrncpy(AVStr(Hp->x_name),nname,sizeof(Hp->x_name));
				set_chksum((HBlock*)Hp);
			}else{
			}
			fwrite(Hp,1,sizeof(HBlock),ofp);
		}

		putbody(iHp,tfp,ofp,msg,opts,size,boundary);
		rcode = fseek(tfp,bsize-size,1);

		if( edits ){
			int i;
			for( i = 0; i < bsize-size; i++ )
				putc(0,ofp);
		}
		return size;
	}

	fd = fileno(tfp);
	if( file_isreg(fd) ){
		rcode = fseek(tfp,bsize,1);
		if( file_size(fd) < ftell(tfp) ){
			fprintf(msg,"premature EOF\n");
			return -1;
		}
	}else{
		file_skip(tfp,bsize);
	}
	return 0;
}
void tar_scan(FILE *ifp,FILE *ofp,FILE *msg,PCStr(opts),PCStr(tarfile),const char *files[],PCStr(edits))
{	HBlock head;
	iHeader ihead;
	int size;
	CStr(boundary,128);

	sprintf(boundary,"[%s]",tarfile);

	if( strchr(opts,'M') ){
	fprintf(ofp,"Content-Type: multipart/mixed; boundary=\"%s\"\r\n",
		boundary);
	}

	while( !feof(ifp) ){
		if( fread(&head,1,TBLOCK,ifp) < TBLOCK ){
			break;
		}
		if( head.dbuf.x_name[0] == 0 ){
			break;
		}
		ntoh(&head.dbuf,&ihead);
		iprb(&ihead,msg);
		size = getbody(&head.dbuf,&ihead,ifp,ofp,msg,opts,files,edits,boundary);
		if( size < 0 )
			break;
	}

	if( strchr(opts,'M') ){
	fprintf(ofp,"\r\n");
	fprintf(ofp,"--%s--\r\n",boundary);
	fprintf(ofp,"\r\n");
	}
}
int tar_main(int ac,const char *av[])
{	FILE *tfp,*ofp,*msg;
	const char *files[128]; /**/
	CStr(edits,1024);
	int fileN;
	int ai;
	const char *opts;
	const char *tarfile;
	const char *arg;
	int opcode;

	if( ac < 2 ){
		fprintf(stderr,"Usage: star opts tarfile file-list\n");
		return -1;
	}

	ofp = stdout;
	msg = stderr;
	tfp = NULL;
	opts = 0;
	opcode = OP_LIST;
	files[0] = 0;
	fileN = 0;
	edits[0] = 0;

	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		if( strncmp(arg,"-e",2) == 0 ){
			if( ai+1 < ac ){
				refQStr(ep,edits); /**/
				ai++;
				opcode = OP_EDIT;
				ep = edits + strlen(edits);
				if( *ep != 0 )
					setVStrPtrInc(ep,' ');
				sprintf(ep,"-e %s",av[ai]);
			}
		}else
		if( opts == NULL ){
			opts = arg;
			if( strchr(opts,'r') )
				opcode = OP_APPEND;
			else
			if( strchr(opts,'c') )
				opcode = OP_CREATE;
			else
			if( strchr(opts,'x') )
				opcode = OP_EXTRACT;
		}else 
		if( tfp == NULL ){
			switch( opcode ){
			    case OP_APPEND:
			    case OP_CREATE:
				if( strcmp(arg,"-") == 0 )
					tfp = stdout;
				else{
					if( opcode == OP_CREATE ){
						tfp = fopen(arg,"w");
					}else{
						if( tfp = fopen(arg,"r+") )
							fseek(tfp,0,2);
					}
				}
				break;

			    case OP_EXTRACT:
				break;

			    case OP_EDIT:
			    default:
				if( strcmp(arg,"-") == 0 )
					tfp = stdin;
				else	tfp = fopen(arg,"r");
			}
			if( tfp == NULL ){
				fprintf(msg,"cannot open tar file: %s\n",arg);
				return -1;
			}
			tarfile = arg;
		}else{
			if( elnumof(files)-1 <= fileN ){
				fprintf(msg,"too many files: %s\n",arg);
			}else{
				files[fileN++] = (char*)arg;
				files[fileN] = 0;
			}
		}
	}
	switch( opcode ){
	    case OP_CREATE:
	    case OP_APPEND:
		if( tfp == NULL )
			tfp = stdout;
		tar_adding(tfp,msg,files);
		break;

	    default:
	    case OP_EDIT:
		if( tfp == NULL )
			tfp = stdin;
		tar_scan(tfp,ofp,msg,opts,tarfile,files,edits);
		break;
	}
	return 0;
}
#ifdef MAIN
main(ac,av)
	char *av[];
{
	return tar_main(ac,av);
}
#endif

static scanDirFunc dirtar1(int tarfd,PCStr(dir))
{	FILE *tfp;
	const char *files[2]; /**/

	files[0] = (char*)dir;
	files[1] = 0;
	tfp = fdopen(tarfd,"w");
	tar_adding(tfp,NULLFP(),files);
	fclose(tfp);
	return 0;
}
FILE *dirtar_fopen(PCStr(path))
{	const char *dp;
	CStr(dir,1024);
	int tarfdv[2];
	FILE *tfp;

	dp = strtailstr(path,".tar");
	if( dp == NULL )
		return NULL;

	QStrncpy(dir,path,dp-path+1);
	if( !fileIsdir(dir) )
		return NULL;

	syslog_ERROR("CREATING [%s].tar\n",dir);
	IGNRETZ pipe(tarfdv);

	if( INHERENT_thread() ){
		thread_fork(0,getthreadid(),"dirtar1",(IFUNCP)dirtar1,tarfdv[1],stralloc(dir));
		tfp = fdopen(tarfdv[0],"r");
		return tfp;
	}

	if( Fork("dirtar") != 0 ){
		close(tarfdv[1]);
		tfp = fdopen(tarfdv[0],"r");
		return tfp;
	}
	close(tarfdv[0]);
	dirtar1(tarfdv[1],dir);
	Finish(0);
	return NULL;
}
