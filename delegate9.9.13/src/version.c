/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2014 National Institute of Advanced Industrial Science and Technology (AIST)
AIST-Product-ID: 2000-ETL-198715-01, H14PRO-049, H15PRO-165, H18PRO-443

Permission to use this material for noncommercial and/or evaluation
purpose, copy this material for your own use, and distribute the copies
via publicly accessible on-line media, without fee, is hereby granted
provided that the above copyright notice and this permission notice
appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
////////////////////////////////////////////////////////////////////////*/
#include <stdio.h>
#include "ystring.h"
#include "dglib.h"
#include "log.h"

#define NAME	"DeleGate"
#define VERSION	"9.9.13"
#define DATE	"October 31, 2014"
#define DSTATUS	"STABLE"
#define AUTHOR	"Yutaka Sato"
#define A_ORG	"National Institute of Advanced Industrial Science and Technology"
#define A_EMAIL	"ysato AT delegate DOT org"
#define A_SITE	"delegate.org"

#define COPYRIGHT "\
AIST-Product-ID: 2000-ETL-198715-01, H14PRO-049, H15PRO-165, H18PRO-443\r\n\
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI\r\n\
Copyright (c) 2001-2014 National Institute of Advanced Industrial Science and Technology (AIST)"

#ifndef _VERSION_H
extern const char *MyVer;

static char _VERSION[32] = VERSION;
static char _DATE[32] = DATE;
static char DGSIGN_default[] = "VRPYMD";
/* DGSIGN="V.R.P/Y.M.D" */
void scan_DGSIGN(DGC*Conn,const char *mysig){
	if( mysig ){
		char vf[8];
		char vs[6][32];
		CStr(ver,32);
		CStr(date,32);
		int i;
		for( i = 0; i < 6; i++ )
			vf[i] = 'x';
		ver[0] = date[0] = 0;
		Xsscanf(mysig,"%[^/]/%s",AVStr(ver),AVStr(date));
		sscanf(ver,"%c.%c.%c",&vf[0],&vf[1],&vf[2]);
		sscanf(date,"%c.%c.%c",&vf[3],&vf[4],&vf[5]);
		Xsscanf(VERSION,"%[^.].%[^.].%s",
			FVStr(vs[0]),FVStr(vs[1]),FVStr(vs[2]));
		Xsscanf(DATE,"%s %[^,], %s",
			FVStr(vs[4]),FVStr(vs[5]),FVStr(vs[3]));
		for( i = 0; i < 6; i++ ){
			if( strchr("-0xX",vf[i]) ){
				vs[i][0] = vf[i];
				vs[i][1] = 0;
			}
		}
		Xsprintf(FVStr(_VERSION),"%s.%s.%s",vs[0],vs[1],vs[2]);
		Xsprintf(FVStr(_DATE),"%s %s, %s",vs[4],vs[5],vs[3]);
		InitLog("DGSIGN VERSION: %s\n",_VERSION);
		InitLog("DGSIGN DATE: %s\n",_DATE);
	}
}
#undef VERSION
#undef DATE
#define VERSION	_VERSION
#define DATE	_DATE


static const char *copyright;
const char *DELEGATE_copyright(){
	CStr(buf,0x2000);
	int len;
	if( copyright == 0 ){
		strcpy(buf,COPYRIGHT);
		if( LICENSEE != 0 && *LICENSEE != 0 ){
			strcat(buf,"\r\nLicensee: ");
			len = strlen(buf);
			XStrncpy(QVStr(buf+len,buf),LICENSEE,sizeof(buf)-len);
		}
		copyright = StrAlloc(buf);
	}
	return copyright;
}
const char *DELEGATE_licensee(){
	if( LICENSEE != 0 && *LICENSEE )
		return LICENSEE;
	else	return "non-commercial and/or evaluation users";
}

const char *DELEGATE_ver()
{
	MyVer = VERSION;
	return VERSION;
}
const char *DELEGATE_date()
{
	return DATE;
}
int getExeVer(PVStr(ver)){
	int v[4];
	int n;
	v[0] = v[1] = v[2] = v[3] = 0;
	if( sscanf(VERSION,"%d.%d.%d-pre%d",&v[0],&v[1],&v[2],&v[3]) == 4 ){
	}else{
		sscanf(VERSION,"%d.%d.%d-fix%d",&v[0],&v[1],&v[2],&v[3]);
		v[3] = 0x80 | v[3];
	}
	setVStrElem(ver,0,v[0]);
	setVStrElem(ver,1,v[1]);
	setVStrElem(ver,2,v[2]);
	setVStrElem(ver,3,v[3]);
	return (v[0] << 24) | (v[1] << 16) | (v[2] << 8) | v[3];
}
static const char *verdate;
const char *DELEGATE_verdate(){
	CStr(buf,128);
	if( verdate == 0 ){
		sprintf(buf,"%s/%s (%s)",NAME,VERSION,DATE);
		verdate = StrAlloc(buf);
	}
	return verdate;
}
static const char *version;
const char *DELEGATE_version(){
	CStr(buf,128);
	if( version == 0 ){
		sprintf(buf,"%s/%s by %s",
					NAME,VERSION, A_EMAIL);
		version = StrAlloc(buf);
	}
	return version;
}
static const char *Ver;
const char *DELEGATE_Ver(){
	CStr(buf,128);
	if( Ver == 0 ){
		sprintf(buf,"%s/%s (%s) by %s (%s)",
					NAME,VERSION, DATE, AUTHOR, A_ORG);
		Ver = StrAlloc(buf);
	}
	return Ver;
}
static const char *Version;
const char *DELEGATE_Version(){
	CStr(buf,128);
	if( Version == 0 ){
		sprintf(buf,"%s (%s) %s", DELEGATE_version(), AUTHOR, DATE);
		Version = StrAlloc(buf);
	}
	return Version;
}

const char *DELEGATE_Distribution(){
	return "ftp://ftp.delegate.org/pub/DeleGate/";
}

const char *DELEGATE_homepage(){
	return "http://www.delegate.org/delegate/";
}
const char *DELEGATE_builtout(){
	return "http://www.delegate.org/delegate/ext/builtin/*";
}

void put_identification(FILE *out)
{
	fprintf(out,"%s\r\n",DELEGATE_verdate());
	fprintf(out,"%s\r\n",DELEGATE_copyright());
	fprintf(out,"--\r\n");
	fprintf(out,"FTP: <URL:%s>\r\n",DELEGATE_Distribution());
	fprintf(out,"WWW: <URL:http://www.%s/>\r\n",A_SITE);
	fprintf(out,"Mail:<URL:mailto:feedback@%s>\r\n",A_SITE);
	fprintf(out,"     <URL:http://www.%s/feedback/>\r\n",A_SITE);
}

const char *DELEGATE_pubkey = "\
-----BEGIN PUBLIC KEY-----\r\n\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDb/8XpXTswqHMXW0teUA+8nYRS\r\n\
nT01WzFEcrNWxD43Zx6jqBSq3741RGpa6aYnXBpowbJBs4dIy3YrXHhoGKWtXfvN\r\n\
iaDXL4z+x+oRvaQulEFUFOdZxFMYDL7AgXN/wFoRktkbrd6I0HdMoPPdekJC6216\r\n\
m5E5y+hrNTxYSOMP/QIDAQAB\r\n\
-----END PUBLIC KEY-----\r\n\
";

const char *DELEGATE_srcsign();
const char *DELEGATE_SrcSign();
int checkVer(){
	const char *ver;
	CStr(xver,128);
	CStr(xdate,128);
	const char *xsign;

	ver = DELEGATE_ver();
	truncVStr(xver);
	truncVStr(xdate);
	Xsscanf(DELEGATE_srcsign(),"%[^:]:%[^:]",AVStr(xver),AVStr(xdate));
	if( xsign = strrchr(DELEGATE_srcsign(),':') )
		xsign++;
	else	xsign = "";
	if( strcmp(ver,xver) != 0 ){
		fprintf(stderr,"!! inconsistent version (DeleGate/%s) !!\n",
			ver);
		return -1;
	}
	return 0;
}
unsigned int verFpi(int crc){
	char oct;
	const char *fp;
	int ovf;
	int bi;
	const char *vsign = DELEGATE_SrcSign();

	/*
	for( fp = DELEGATE_srcsign(); oct = *fp; fp++ ){
	*/
	for( fp = vsign; oct = *fp; fp++ ){
		for( bi = 0; bi < 8; bi++ ){
			/*
			ovf = (crc < 0) ^ (oct < 0);
			*/
			ovf = (crc < 0) ^ ((oct & 0x80) != 0);
			crc <<= 1;
			oct <<= 1;
			if( ovf ) crc ^= 0x04C11DB7;
		}
	}
	return crc;
}
#endif
