/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1999-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	randstack.c (randomize stack base)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	991118	created
ToDo:
	- the order of environ[*] should be randomized also
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include "yalloca.h"
#include "ystring.h"
#include "fcntl.h"
#include "log.h"
long Gettimeofday(int *usec);
int IsOS2EMX();

int RANDHEAP_SIZE = 64*1024;
int RANDSTACK_RANGE = 64;
int RANDSTACK_UNIT = 128;
static unsigned int prev_rand;
int strCRC32(PCStr(str),int len);

/*
static unsigned int trand1(unsigned int max)
*/
unsigned int trand1(unsigned int max)
{	unsigned int sec,usec;
	int nrand;
	struct {
		int prand;
		int sec;
		int usec;
		int pid;
	} seed;
	unsigned int nrando;

	/*
	sec = Gettimeofday((int*)&usec);
	nrand = ((prev_rand<<8) ^ (usec >> 10)) % max;
	*/
	bzero(&seed,sizeof(seed));
	seed.prand = prev_rand;
	seed.sec = Gettimeofday((int*)&seed.usec);
	seed.pid = getpid();
	nrando = strCRC32((const char*)&seed,sizeof(seed));
	nrand = nrando % max;
	prev_rand = nrand;
	return nrand;
}

void randheap()
{	unsigned int size;
	const char *bp;

	size = trand1(RANDHEAP_SIZE);
	bp = (char*)malloc(size);
	addStrBuffer(SB_PROC,(char*)bp,size);
}

int randstack_call(int strg,iFUNCP func, ...)
{	AllocaArg arg;
	unsigned int size;
	int rcode;
	VARGS(8,func);

	if( RANDSTACK_RANGE == 0 )
		size = 0;
	else	size = trand1(RANDSTACK_RANGE);
	arg.s_what = "#### RANDSTACK";
	arg.s_sp0 = (char*)&func;
	arg.s_func = func;
	arg.s_av[0] = va[0]; arg.s_av[1] = va[1];
	arg.s_av[2] = va[2]; arg.s_av[3] = va[3];
	arg.s_av[4] = va[4]; arg.s_av[5] = va[5];
	arg.s_size = size;
	arg.s_unit = RANDSTACK_UNIT;
	arg.s_count = size;
	arg.s_trace = RAND_TRACE;
	arg.s_level = strg;
	rcode = alloca_call(&arg);
	delStrBuffer(strg);
	return rcode;
}
int allocaCall(PCStr(what),int size,iFUNCP func,...){
	AllocaArg aa;
	int rcode;
	VARGS(8,func);

	aa.s_what = (char*)what;
	aa.s_sp0 = (char*)&func;
	aa.s_func = func;
	aa.s_av[0] = (char*)va[0];
	aa.s_av[1] = (char*)va[1];
	aa.s_av[2] = (char*)va[2];
	aa.s_av[3] = (char*)va[3];
	aa.s_av[4] = (char*)va[4];
	aa.s_av[5] = (char*)va[5];
	aa.s_size = size / STACK1;
	aa.s_unit = STACK1;
	aa.s_count = size / STACK1;
	aa.s_trace = RAND_TRACE;
	aa.s_level = SB_SERV;
	rcode = alloca_call(&aa);
	delStrBuffer(SB_SERV);
	return rcode;
}

int RANDENV_RANGE = 1024;
struct _randenv_buff { defQStr(randenv_buff); } randenv_buff;
int randenv_size;
#define randenv_name "RANDENV="
void randenv()
{	int randen,ex;
	char *rande; /**/

	if( isWindowsCE() ){
		return;
	}
	if( numthreads() ){
		return;
	}
	if( RANDENV_RANGE <= 0 )
		return;

	if( randenv_size < RANDENV_RANGE ){
		if( randenv_buff.randenv_buff ){
			free((char*)randenv_buff.randenv_buff);
			setQStr(randenv_buff.randenv_buff,NULL,0);
		}
	}
	if( randenv_buff.randenv_buff == 0 ){
		randenv_size = RANDENV_RANGE;
		setQStr(randenv_buff.randenv_buff,(char*)malloc(
strlen(randenv_name)+randenv_size+1),
strlen(randenv_name)+randenv_size+1);
	}

	randen = trand1(RANDENV_RANGE);

	strcpy(randenv_buff.randenv_buff,randenv_name);
	rande = (char*)randenv_buff.randenv_buff + strlen(randenv_buff.randenv_buff);
	for( ex = 0; ex < randen; ex++ )
		rande[ex] = 'X';
	rande[ex] = 0;
	putenv((char*)randenv_buff.randenv_buff);
	if( RAND_TRACE )
		porting_dbg("#### RANDENV (%4d)",randen);
}

int RANDFD_RANGE = 32;
static int getrandfd(int tfd,int rand)
{	int fds[256],nfd,rfd,fdi,fdx,foff;

	rfd = tfd;
	for( fdx = 0; fdx < rand; ){
		nfd = dup(tfd);
		if( nfd < 0 ){
			/* no more fd, so select from available ones */
			if( 1 < fdx ){
				foff = trand1(fdx);
				rfd = fds[foff];
			}
			break;
		}
		fds[fdx++] = nfd;
		rfd = nfd;
	}
	for( fdi = 0; fdi < fdx; fdi++ ){
		close(fds[fdi]);
	}
	return rfd;
}
int getNullFd(PCStr(what));
int randfd(int fd)
{	unsigned int foff;
	int tfd,rfd;
	FILE *tmp;

	if( isWindowsCE() ){
		/* dup(), dup2() for socket is NG ? with "nul" ?
		 * and randfd() is realized more effecitivry in WinCE 
		 */
		return fd;
	}
	if( numthreads() ){
		return fd;
	}
	if( isWindows95() ){
		return fd;
	}
	if( fd < 0 )
		return fd;

	if( RANDFD_RANGE == 0 )
		return fd;

/*
	tmp = fopen("/dev/null","r");
*/
/*
	tfd = open("/dev/null",0); tmp = fdopen(tfd,"r");
*/
	/*
	if( isWindows() )
		tfd = open("nul",0);
	else	tfd = open("/dev/null",0);
	*/
	tfd = getNullFd("randfd");
	if( 0 <= tfd )
		tfd = dup(tfd);
	if( 0 <= tfd )
		tmp = fdopen(tfd,"r");
	else	tmp = NULL;

	if( tmp == NULL )
		tmp = tmpfile();
	if( tmp == NULL )
		return fd;
	tfd = fileno(tmp);

	foff = trand1(RANDFD_RANGE);

	rfd = getrandfd(tfd,foff);
	fclose(tmp);

	rfd = dup2(fd,rfd);
	if( 0 <= rfd )
		close(fd);
	else	rfd = fd;

/*
	if( RAND_TRACE ){
		fprintf(stderr,"#### RANDFD (%2d) = %2d -> %2d\n",foff,fd,rfd);
	}
*/
	return rfd;
}

/*
 * copy environ area on stack into heap and clear
 * the original environ area may be recycled for proc-title
 */
extern char **environ;
char **move_envarg(int ac,const char *av[],const char **areap,int *lengp,int *sizep)
{	int ai,ei,ex,offs;
	const char **nav;
	const char *as;
	char *asT; /**/
	const char *a0T;
	char **xenviron;
	char *es; /**/
	const char *es0;
	char *esT; /**/

	if( IsOS2EMX() ){
		/* moving env. and arg. have no effect and
		 * clearing env. var. like ETC can be harmful.
		 */
		return (char**)av;
	}
	if( isWindowsCE() ){
		/* no environ */
		return (char**)av;
	}

	/*
	 * move environ[0-] to heap area
	 */
	es0 = environ[0];
	for( ei = 0; es = environ[ei]; ei++ );
	xenviron = (char**)malloc(sizeof(char*)*(ei+2));
	esT = 0;
	for( ei = 0; es = environ[ei]; ei++ ){
		xenviron[ei] = strdup(es);
		while( *es ) *es++ = ' ';
		esT = es;
	}
	xenviron[ei] = 0;
	environ = xenviron;

	/*
	 * move arg[1-] to heap area
	 */
	nav = (const char**)malloc(sizeof(char*)*(ac+1));
	nav[0] = av[0];
	for( ai = 1; ai < ac; ai++ ){
		as = av[ai];
		nav[ai] = strdup(as);
	}
	nav[ac] = 0;

	/*
	 * some inherent support for ps-title.
	 * can be with non-writable argv and environ
	 */
	if( proc_title("start") == 0 )
		return (char**)nav;

	asT = (char*)av[ac-1] + strlen(av[ac-1]);
	/*
	 * can be with uncommon structure on initial stack
	 */
	if( asT+1 != es0 || esT == NULL )
		return (char**)nav;

	stackcopy((char**)av,ac,asT,esT,(char**)areap,lengp,sizep);

/*
	if( RAND_TRACE ){
		for( as = av[0]; as <= esT; as++ )
			fprintf(stderr,"%2X",*as);
		fprintf(stderr,"\n");
	}
*/
	return (char**)nav;
}
