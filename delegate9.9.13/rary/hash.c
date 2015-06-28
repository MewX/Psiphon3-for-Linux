/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1995 Electrotechnical Laboratry (ETL), AIST, MITI

Permission to use, copy, modify, and distribute this material for any
purpose and without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies, and
that the name of ETL not be used in advertising or publicity pertaining
to this material without the specific, prior written permission of an
authorized representative of ETL.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	hash.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	951226	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include "ystring.h"

typedef struct {
  const char	*he_key;
  const	char	*he_data;
} HEntry;

typedef struct {
	HEntry	*ht_array;
	int	 ht_size;
	int	 ht_filled;
	int	 ht_acc;	/* access count */
	int	 ht_col;	/* colision count */
  const	char	*ht_nulval;
} HTable;

static HTable **ht_list;
static int ht_size;

static int new_ht()
{	int htid;

	for( htid = 1; htid < ht_size; htid++ )
		if( ht_list[htid] == NULL )
			return htid;
	return 0;
}
static void expand_hts()
{	int osize,hx;

	osize = ht_size;
	ht_size += 16;
	if( ht_list == NULL )
		ht_list = (HTable**)malloc(ht_size*sizeof(HTable*));
	else	ht_list = (HTable**)realloc(ht_list,ht_size*sizeof(HTable*));

	for( hx = osize; hx < ht_size; hx++ )
		ht_list[hx] = NULL;
}

int Hcreate(int nelem,PCStr(nulval))
{	int htid;
	int xnelem;
	HTable *ht;

	htid = new_ht();
	if( htid == 0 ){
		expand_hts();
		htid = new_ht();
	}
	ht = (HTable*)calloc(1,sizeof(HTable));
	ht_list[htid] = ht;
	xnelem = nelem;
	ht->ht_size = xnelem;
	ht->ht_filled = 0;
	ht->ht_array = (HEntry*)calloc(xnelem,sizeof(HEntry));
	ht->ht_nulval = nulval;
	ht->ht_col = 0;
	ht->ht_acc = 0;
	return htid;
}
void Hstat(int htid)
{	HTable *ht;

	ht = ht_list[htid];
	fprintf(stderr,"HASH[%d] %d col. / %d acc.\n",
		htid,ht->ht_col,ht->ht_acc);
}

void Hdestroy(int htid)
{
}

unsigned long elfhash(unsigned char *key){
	unsigned long kx = 0;
	unsigned long g;
	while( *key ){
		kx = (kx << 4) + *key++;
		g = kx & 0xF0000000L;
		if( g ) kx ^= g >> 24;
		kx &= ~g;
	}
	return kx;
}
static int index1(unsigned char *key)
{	const unsigned char *ks;
	int kc,kx;

	kx = 0;
	for( ks = key; kc = *ks++; )
		kx = (kx << 2) ^ kc;
	return kx;
}
/*
#define index1(key)	FQDN_hash(key)
*/
#define index1(key)	elfhash(key)

const char *Hsearch(int htid,PCStr(key),PCStr(data))
{	HTable *ht;
	HEntry *he;
	unsigned int hsize,kx,kn;

	if( htid <= 0 )
		return 0;
	ht = ht_list[htid];
	hsize = ht->ht_size;

	kx = index1((unsigned char*)key);
	kn = 0;

	ht->ht_acc++;
	for( kn = 0; kn < hsize; kn++ ){
		if( hsize <= kx )
			kx = kx % hsize;
		he = &ht->ht_array[kx];
		if( he->he_key == NULL ){
			if( data == ht->ht_nulval )
				return ht->ht_nulval;
			he->he_key = key;
			he->he_data = data;
			return he->he_data;
		}
		if( strcmp(key,he->he_key) == 0 ){
			if( data != ht->ht_nulval )
				he->he_data = data;
			return he->he_data;
		}
		ht->ht_col++;
		kx++;
	}
	return ht->ht_nulval;
}

int Hnext(int htid,int kx,const char **keyp,const char **datap)
{	HTable *ht;
	HEntry *he;
	unsigned int hsize;

	if( htid <= 0 )
		return -1;

	ht = ht_list[htid];
	hsize = ht->ht_size;
	if( kx < 0 )
		kx = 0;
	else	kx++;

	for(; kx < hsize; kx++ ){
		he = &ht->ht_array[kx];
		if( he->he_key != NULL ){
			if(keyp) *keyp = (char*)he->he_key;
			if(datap) *datap = (char*)he->he_data;
			return kx;
		}
	}
	return -1;
}
