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
Program:	dnode.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
	convert domain name to (local) uniq identifier.
History:
	950820	created
//////////////////////////////////////////////////////////////////////#*/

#include <stdio.h>
#include <stdlib.h>
#include "ystring.h"
#include "dns.h" /* REVERSE_DOM */
#define MAXLEV 36

typedef struct attr {
    struct attr	*a_peer;
	int	 a_flag;
	int	 a_date; /* cached time */
	int	 a_ttl;
	int	 a_leng;
	char	 a_data[1];
} Attr;

typedef struct node {
	int	 n_nid;
	int	 n_flag;
  const	char	*n_label;
	int	 n_phase;
	Attr	*n_attr;
    struct node *n_parent;
    struct node *n_child;
    struct node *n_peer;
} Node;
#define NF_LEAF		1

static Node NoNode     = {0,NF_LEAF,"?"};
static Node TopNodeBuf = {1,NF_LEAF,""};
static Node *TopNode = &TopNodeBuf;
static Node *Nodes0[] = {&NoNode, &TopNodeBuf};
static Node **Nodes = Nodes0;
static int NodesA;
static int NodesX = 2;
static int NID = 1;

#define NBSIZE 128
static Node *Nodebank;
static int Nodebanki;
static Node *NewNode(){
	Node *Np;
	if( Nodebank == 0 || Nodebanki == NBSIZE ){
		Nodebank = (Node*)malloc(NBSIZE*sizeof(Node));
		Nodebanki = 0;
	}
	Np = &Nodebank[Nodebanki++];
	bzero(Np,sizeof(Node));
	return Np;
}
#define SBSIZE 512
static char *Stringb;
static int Stringi;
static char *NewString(int len){
	char *sp;
	if( Stringi == 0 || SBSIZE-Stringi < len ){
		Stringb = (char*)malloc(SBSIZE);
		Stringi = 0;
	}
	sp = Stringb+Stringi;
	Stringi += len;
	return sp;
}
static const char *NewLabel(PCStr(label)){
	char *lp;
	int len;
	len = strlen(label) + 1;
	lp = NewString(len);
	Xstrcpy(ZVStr(lp,len),label);
	return lp;
}
#define RBSIZE 512
static int *Recordb;
static int Recordi;
static int *NewRecord(int siz){
	int isiz;
	int *rp;

	isiz = (siz+sizeof(int)-1)/sizeof(int) +1/*for safety?*/;
	if( Recordi == 0 || RBSIZE-Recordi < isiz ){
		Recordb = (int*)malloc(RBSIZE*sizeof(int));
		Recordi = 0;
	}
	rp = &Recordb[Recordi];
	Recordi += isiz;
	return rp;
}

#define getnode(nid)	Nodes[nid]

static Node *newnode()
{	Node *Np;
	int ox,nsize;
	Node **nnodes;

	++NID;
	if( NodesX <= NID ){
		NodesX = ++NodesA * MAXLEV;
		nsize = NodesX * sizeof(Node*);
		if( nsize < 1024 ){
			/* 9.7.0 to reduce realloc() */
			nsize = 1024;
		}
		if( Nodes == Nodes0 ){
			Nodes = (Node**)malloc(nsize);
			Nodes[0] = Nodes0[0];
			Nodes[1] = Nodes0[1];
		}else	Nodes = (Node**)realloc(Nodes,nsize);
		debug(DBG_ANY,"newnode() id=%d %d %X\n",NID,NodesX,p2i(Nodes));
	}

	/*
	Np = NewStruct(Node);
	*/
	Np = NewNode();
	Nodes[NID] = Np;
	Np->n_nid = NID;
	return Np;
}

static Node *nsearch(PCStr(name),int create)
{	const char *np;
	char oct;
	const char *labelv[MAXLEV]; /**/
	CStr(labelb,512);
	refQStr(lp,labelb); /**/
	const char *xp = &labelb[sizeof(labelb)-1];
	const char *label;
	int lc,lx;
	Node *Np,*Lp,*Tp;

	np = name;
	for(lc = 0; *np; lc++){
		if( xp <= lp )
			break;
		if( elnumof(labelv) <= lc ){
			debug(DBG_FORCE,"FATAL: nsearch(%s) too deep\n",name);
			break;
		}
		labelv[lc] = (char*)lp;
		while( oct = *np ){
			np++;
			if( oct == '.' )
				break;
			setVStrPtrInc(lp,oct);
		}
		setVStrPtrInc(lp,0);
	}
	Np = Lp = TopNode;

	if( lc == 1 && labelv[0][0] == 0 ){
		/* ROOT "." */
	}else
	for(lx = lc - 1; 0 <= lx; lx--){
		label = labelv[lx];
		for( Lp = Np->n_child; Lp; Lp = Lp->n_peer ){
			if( strcasecmp(Lp->n_label,label) == 0 )
				break;
		}
		if( Lp == NULL ){
			if( !create )
				return &NoNode;

			Lp = newnode();
			/*
			Lp->n_label = stralloc(label);
			*/
			Lp->n_label = NewLabel(label);
			Lp->n_parent = Np;
			Tp = Np->n_child;
			Np->n_child = Lp;
			Lp->n_peer = Tp;
		}
		Np = Lp;
	}
	if( create )
		Np->n_flag |= NF_LEAF;
	return Np;
}
static int getnodename(Node *Np,PVStr(name))
{	refQStr(np,name); /**/
	int lc;

	for( lc = 0; Np; lc++ ){
		strcpy(np,Np->n_label);
		np += strlen(np);
		Np = Np->n_parent;
		if( Np == TopNode )
			break;
		setVStrPtrInc(np,'.');
	}
	setVStrEnd(np,0);
	return lc;
}

void gethostdomname(PVStr(name),PCStr(addr),int len,int type)
{	const unsigned char *ap;

	ap = (unsigned char*)addr;
	sprintf(name,"%d.%d.%d.%d.%s.",ap[3],ap[2],ap[1],ap[0],REVERSE_DOM);
}

void addr2dom(PCStr(addr),PVStr(inaddr),int isize)
{	int a1,a2,a3,a4;

	sscanf(addr,"%d.%d.%d.%d",&a1,&a2,&a3,&a4);
	sprintf(inaddr,"%d.%d.%d.%d.%s",a4,a3,a2,a1,REVERSE_DOM);
}

int ipv6_domain(PCStr(addr),PVStr(dom));
int DNS_putbyaddr(PCStr(addr))
{	CStr(name,256);
	int a1,a2,a3,a4;
	int ns;

	ns =
	sscanf(addr,"%d.%d.%d.%d",&a1,&a2,&a3,&a4);
	if( ns == 4 )
	sprintf(name,"%d.%d.%d.%d.%s",a4,a3,a2,a1,REVERSE_DOM);
	else{
		ipv6_domain(addr,AVStr(name));
	}
	return DNS_putbyname(name);
}
int DNS_getbyaddr(PCStr(addr))
{	CStr(name,256);

	/* should care IPv6 address here ...*/
	sprintf(name,"%s.%s",addr,REVERSE_DOM);
	return DNS_getbyname(name);
}

int DNS_putbyname(PCStr(name))
{	Node *Np;

	Np = nsearch(name,1);
	return Np->n_nid;
}
int DNS_getbyname(PCStr(name))
{	Node *Np;

	Np = nsearch(name,0);
	return Np->n_nid;
}
int DNS_parent(int nid)
{	Node *Np,*Pp;

	Np = getnode(nid);
	if( Pp = Np->n_parent )
		return Pp->n_nid;
	else	return 0;
}
int DNS_nodename(int nid,PVStr(name))
{
	return getnodename(getnode(nid),AVStr(name));
}
int DNS_putattr(int nid,int flag,int ttl,PCStr(data),int leng)
{	Node *Np;
	Attr *Sp,*Ap;

	Np = getnode(nid);

	for( Ap = Np->n_attr; Ap; Ap = Ap->a_peer ){
		if( flag == Ap->a_flag && 
		    leng == Ap->a_leng && bcmp(Ap->a_data,data,leng) == 0 )
			return 0;
	}

	/*
	Ap = (Attr*)malloc(sizeof(Attr)+leng);
	*/
	Ap = (Attr*)NewRecord(sizeof(Attr)+leng);
	Ap->a_flag = flag;
	Ap->a_leng = leng;
	Ap->a_date = time(0);
	Ap->a_ttl  = ttl;
	bcopy(data,Ap->a_data,leng); /**/

	Sp = Np->n_attr;
	Np->n_attr = Ap;
	Ap->a_peer = Sp;
	return 1;
}
static int expireattr(Node *Np,int flag,int ttl){
	int now = time(0);
	int doexpire = 0;
	Attr *Ap;

	if( ttl <= 0 ){
		return 0;
	}
	for( Ap = Np->n_attr; Ap; Ap = Ap->a_peer ){
		if( flag & Ap->a_flag ){
			if( Ap->a_date + Ap->a_ttl <= now
			 || Ap->a_date + ttl <= now
			){
	debug(DBG_FORCE,"#### DNS expireattr %X ttl=%X+%d/%d %d\n",
	now,Ap->a_date,Ap->a_ttl,ttl,Ap->a_date+Ap->a_ttl-now);
				doexpire = 1;
				break;
			}
		}
	}
	if( doexpire == 0 ){
		return 0;
	}

	/* clear all attr. of the type to force total refresh */
	/* to avoid making a chimera of old and new RRs */
	for( Ap = Np->n_attr; Ap; Ap = Ap->a_peer ){
		if( flag & Ap->a_flag ){
			Ap->a_flag = 0;
		}
	}
	return 0;
}
int DNS_getattr(int nid,int flag,int ttl,int ac,char *av[])
{	Node *Np;
	Attr *Ap;
	int ai;

	Np = getnode(nid);
	ai = 0;
	expireattr(Np,flag,ttl); /* 9.9.8 expiring on mem. RR by TTL */
	for( Ap = Np->n_attr; Ap; Ap = Ap->a_peer ){
		if( flag & Ap->a_flag ){
			av[ai++] = Ap->a_data;
			if( ac <= ai )
				break;
		}
	}
	return ai;
}

int DNS_nodephase(int nid,int phase)
{	Node *Np;
	int ophase;

	Np = getnode(nid);
	ophase = Np->n_phase;
	Np->n_phase = phase;
	return ophase;
}

void DNS_nodedump(int nid)
{	Node *Np;
	CStr(name,512);
	Attr *Ap;
	const unsigned char *dp;

	Np = getnode(nid);
	if( Np->n_attr != NULL ){
		getnodename(Np,AVStr(name));
		fprintf(stderr,"%6d: %s\n",Np->n_nid,name);

		for( Ap = Np->n_attr; Ap; Ap = Ap->a_peer ){
			dp = (unsigned char*)Ap->a_data;
			fprintf(stderr,"%6s+ ATTR-%d=%d %d %d %d %d %d\n",
				"",Ap->a_flag,dp[0],dp[1],dp[2],dp[3],dp[4],dp[5]);
		}
	}
}
void DNS_dump()
{	int nid;
	Node *Np;

	for( nid = 1; nid <= NID; nid++ ){
		Np = getnode(nid);
		if( Np->n_flag & NF_LEAF )
			DNS_nodedump(Np->n_nid);
	}
}
