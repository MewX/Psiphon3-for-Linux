/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2011 Yutaka Sato

Permission to use this material for evaluation, copy this material for
your own use, and distribute the copies via publically accessible on-line
media, without fee, is hereby granted provided that the above copyright
notice and this permission notice appear in all copies.
//////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	xflash.c (X11 - Flash Gateway)
Author:		Yutaka Sato <ysato@delegate.org>
Description:
	RFC1013
	X Window System Protocol, X Consotium Standard, X11 R6.7
	http://www.x.org/releases/X11R7.6/doc/xproto/x11protocol.pdf (R6.8)

History:
	110115	created
//////////////////////////////////////////////////////////////////////#*/
/* '"DiGEST-OFF"' */

#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include "ystring.h"
#include "delegate.h"
#include "fpoll.h"
#include "proc.h"
int bgexecX(PCStr(mode),PCStr(path),char *av[],char *ev[],int *ph);
int bgwait(int pid,int ph,double timeout);

#define OPdef(b,a)	OP_##a = b
enum _OpCode {
	OPdef(256,InitialResp),
	OPdef( 16,InternAtom),
	OPdef( 20,GetProperty),
	OPdef( 38,QueryPointer),
	OPdef( 98,QueryExtension),
	OPdef(131,Shape), // Darwin?
	OPdef(135,BigRequest), // Darwin?
	OPdef(149,XFree86_Bigfont), // Darwin?
	OPdef(151,Render), // Darwin?

	OPdef(  1,CreateWindow),
	OPdef(  2,ChangeWindowAttributes),
	OPdef(  8,MapWindow),
	OPdef(  9,MapSubwindows),
	OPdef( 18,ChangeProperty),
	OPdef( 43,GetInputFocus),
	OPdef( 45,OpenFont),
	OPdef( 53,CreatePixmap),
	OPdef( 54,FreePixmap),
	OPdef( 55,CreateGC),
	OPdef( 56,ChangeGC),
	OPdef( 60,FreeGC),
	OPdef( 61,ClearArea),
	OPdef( 62,CopyArea),
	OPdef( 69,FillPoly),
	OPdef( 70,PolyFillRectangle),
	OPdef( 71,PolyFillArc),
	OPdef( 72,PutImage),
	OPdef( 76,ImageText8),
} OpCode;

#define EVdef(b,a)	EV_##a = b
enum _EvCode {
	EVdef(  1,RETURN),
	EVdef(  2,KeyPress),
	EVdef(  3,KeyRelease),
	EVdef(  4,ButtonPress),
	EVdef(  5,ButtonRelease),
	EVdef(  6,MotionNotify),
	EVdef(  7,EnterNotify),
	EVdef(  8,LeaveNotify),
} EvCode;

typedef struct {
	int	op_code;
    const char *op_name;
	int	op_withret;
} Op;
typedef struct {
	int	ev_code;
    const char *ev_name;
} Ev;

#define Quoted(s) #s
#define OpNS(ret,n)	{ OP_##n, Quoted(n), ret }
static Op ops[128] = {
	OpNS(1,InitialResp),
	OpNS(1,InternAtom),
	OpNS(1,GetProperty),
	OpNS(1,QueryPointer),
	OpNS(1,QueryExtension),
	OpNS(1,Shape), // Darwin?
	OpNS(1,BigRequest), // Darwin?
	OpNS(1,XFree86_Bigfont), // Darwin?
	OpNS(1,Render), // Darwin?

	OpNS(0,CreateWindow),
	OpNS(0,ChangeWindowAttributes),
	OpNS(0,MapWindow),
	OpNS(0,MapSubwindows),
	OpNS(0,ChangeProperty),
	OpNS(0,GetInputFocus),
	OpNS(0,OpenFont),
	OpNS(0,CreatePixmap),
	OpNS(0,FreePixmap),
	OpNS(0,CreateGC),
	OpNS(0,ChangeGC),
	OpNS(0,FreeGC),
	OpNS(0,ClearArea),
	OpNS(0,CopyArea),
	OpNS(0,FillPoly),
	OpNS(0,PolyFillRectangle),
	OpNS(0,PolyFillArc),
	OpNS(0,PutImage),
	OpNS(0,ImageText8),
};
#define EvNS(n)	{ EV_##n, Quoted(n) }
static Ev evs[128] = {
	EvNS(RETURN),
	EvNS(KeyPress),
	EvNS(KeyRelease),
	EvNS(ButtonPress),
	EvNS(ButtonRelease),
	EvNS(MotionNotify),
	EvNS(EnterNotify),
	EvNS(LeaveNotify),
};

        
/* FrOM-HERE 
##########################################################################
    CAUTION: re-distributing the copy of this file is not permitted.
##########################################################################
 */                     

typedef struct {
	Connection *xf_Conn;
	int	xf_cstid;
	int	xf_sctid;
	int	xf_fptid;
	int	xf_xfsockfd;
	FILE   *xf_xfsockfp;
	char	xf_string8[1024];
	int	xf_drawable;
	int	xf_gcontext;
} XFlash;
static int toFlash(XFlash *Xf,PCStr(fmt),...);

#define Getc(fc,ts)	fputc(fgetc(fc),ts)
static int LEND;
static int GetInt2(FILE *fc,FILE *ts)
{	int iv;

	iv = Getc(fc,ts);
	if( LEND )
		iv = (Getc(fc,ts) << 8) | iv;
	else	iv = (iv << 8) | Getc(fc,ts);
	return iv;
}
static int GetInt4(FILE *fc,FILE *ts)
{	int iv;

	iv = GetInt2(fc,ts);
	if( LEND )
		iv = (GetInt2(fc,ts) << 16) | iv;
	else	iv = (iv << 16) | GetInt2(fc,ts);
	return iv;
}

static const char *opsym(int opcode,int *withret){
	int oi;
	Op *op;
	for( oi = 0; oi < elnumof(ops); oi++ ){
		op = &ops[oi];
		if( op->op_code == opcode ){
			if( withret ) *withret = op->op_withret;
			return op->op_name;
		}
	}
	return 0;
}
static const char *opsymX(int opcode){
	const char *sym;
	static IStr(buf,32);
	if( sym = opsym(opcode,0) )
		return sym;
	sprintf(buf,"??%d",opcode);
	return buf;
}
static const char *evsym(int evcode){
	int ei;
	Ev *ev;
	for( ei = 0; ei < elnumof(evs); ei++ ){
		ev = &evs[ei];
		if( ev->ev_code == evcode ){
			return ev->ev_name;
		}
	}
	return 0;
}

typedef struct _IOStr {
	FILE *in_fp;
	int in_level;
	int in_nolog;
	const char *in_cssc;
	const char *in_base;
	const char *in_ptr;
	const char *in_next;
	XFlash *in_Xf;
} IOStr;
static int IOinit(IOStr *io,XFlash *Xf,const char *cssc,const char *in,int len){
	io->in_Xf = Xf;
	io->in_cssc = cssc;
	io->in_base = in;
	io->in_ptr = in;
	io->in_next = in + len;
	return 0;
}
static int IOoff(IOStr *io){
	return io->in_ptr - io->in_base;
}
static int remLeng(IOStr *io){
	int len;
	if( io->in_ptr < io->in_next ){
		len = io->in_next - io->in_ptr;
	}else{
		len = 0;
	}
	return len;
}
static int nextoct_FL(IOStr *io,int pad,const char *F,int L){
	int iv;
	if( io->in_next <= io->in_ptr ){
		fprintf(stderr,"IN Error: %d/%d <= %s:%d\n",
			io->in_ptr,io->in_next,F,L);
		sleep(1);
		return EOF;
	}else{
		iv = (0xFF & io->in_ptr[0]);
		if( pad ){
			((char*)io->in_ptr)[0] = 0;
		}
		io->in_ptr++;
		return iv;
	}
}

typedef struct _OpQue {
	int	oq_code;
	int	oq_seq;
} OpQue;
static OpQue queue[128];
static int qtop;
static int qtail;
static int Qseq = 0;

static OpQue *enqOp(int seq,int op){
	OpQue *qop;
	if( elnumof(queue) <= qtail - qtop ){
		fprintf(stderr,"----ERROR full queue\n");
		return 0;
	}else{
		qop = &queue[qtail % elnumof(queue)];
		qop->oq_code = op;
		qop->oq_seq = seq;
		qtail++;
		return qop;
	}
}
static int deqOp(int *seq,OpQue *qop){
	int op;
	if( qtop < qtail ){
		*qop = queue[qtop % elnumof(queue)];
		*seq = qop->oq_seq;
		op = qop->oq_code;
		qtop++;
		return op;
	}else{
		fprintf(stderr,"----ERROR empty queue (%d %d)\n",qtop,qtail);
		return -1;
	}
}

#define nextoct(io,pad) nextoct_FL(io,pad,__FILE__,__LINE__)
#define IN_CLEAR	1
#define IN_PEEK		2

static int getPadN(IOStr *io,const char *what,int n){
	int off0 = IOoff(io);
	int iv = 0;
	int o1;
	int ix;

	fprintf(stderr,"%s IN %3d %s {",io->in_cssc,off0,what);
	for( ix = 0; ix < n; ix++ ){
		if( (o1 = nextoct(io,1)) == EOF ){
			break;
		}
		if( 0x20 <= o1 && o1 < 0x7F ){
			fprintf(stderr,"%c",o1);
		}else{
			fprintf(stderr,"(%02X)",o1);
		}
	}
	fprintf(stderr,"}\n");
	return 0;
}
static int getIntN(IOStr *io,const char *what,int n,int flags){
	int ix;
	int iv = 0;
	int o1;
	int off0 = IOoff(io);

	for( ix = 0; ix < n; ix++ ){
		if( (o1 = nextoct(io,(flags&IN_CLEAR))) == EOF ){
			break;
		}
		iv = (iv << 8) | (0xFF & o1);
	}
	fprintf(stderr,"%s IN %3d %s %u\n",io->in_cssc,off0,what,iv);
	return iv;
}
static int getInt1(IOStr *io,const char *what){
	return getIntN(io,what,1,0);
}
static int getInt2(IOStr *io,const char *what){
	return getIntN(io,what,2,0);
} 
static int getInt4(IOStr *io,const char *what){
	return getIntN(io,what,4,0);
} 
static int getSTRING8(IOStr *io,const char *what,int n){
	int ix;
	int iv;
	int ch;
	int off0 = IOoff(io);
	char *sp = io->in_Xf->xf_string8;
	const char *sx = &io->in_Xf->xf_string8[sizeof(io->in_Xf->xf_string8)-1];

	fprintf(stderr,"%s IN %3d STRING8(%d) %s \"",io->in_cssc,off0,n,what);
	for( ix = 0; ix < n; ix++ ){
		if( (ch = nextoct(io,0)) == EOF ){
			break;
		}
		if( sp < sx ){
			*sp++ = ch;
		}
		iv = ch;
		if( 0x20 <= iv && iv < 0x7F ){
			fprintf(stderr,"%c",iv);
		}else{
			fprintf(stderr,"(%02X)",iv);
		}
	}
	*sp = 0;
	fprintf(stderr,"\"\n");
	return 0;
}
static int skipPad(IOStr *io,const char *what,int pad){
	int ix;
	int ch;
	int iv;
	int off = IOoff(io);

	fprintf(stderr,"%s IN %3d %s",io->in_cssc,off,what);
	for( ix = 0; remLeng(io); ix++ ){
		off = IOoff(io);
		if( off % pad == 0 ){
			break;
		}
		if( (ch = nextoct(io,1)) == EOF ){
			break;
		}
		iv = ch;
		if( 0x20 <= iv && iv < 0x7F ){
			fprintf(stderr,"%c",iv);
		}else{
			fprintf(stderr,"(%02X)",iv);
		}
	}
	fprintf(stderr,"\n");
	return 0;
}

static int relayRequest(XFlash *Xf,OpQue *qop,FILE *fc,FILE *ts,int len){
	int ci;
	int rem;
	int ch;

	ci = 0;
	for( rem = (len-1)*4; 0 < rem; rem-- ){
		ch = Getc(fc,ts);
		if( ci++ < 32 ){
			fprintf(stderr," %02X",0xFF&ch);
		}
	}
	fprintf(stderr,"\n");
	return 0;
}
static int relayClearArea(XFlash *Xf,FILE *fc,FILE *ts,int len,int slen){
	IOStr iob,*io = &iob;
	IStr(buf,32*1024);
	int rcc;
	int wcc;
	int rv;
	int W,g,x,y,w,h;

	rcc = fread(buf,1,(len-1)*4,fc);
	IOinit(io,Xf," cs CA",buf,rcc);
	W = rv = getInt4(io,"WINDOW/window");
	x = rv = getInt2(io,"INT16/x");
	y = rv = getInt2(io,"INT16/y");
	w = rv = getInt2(io,"CARD16/width");
	h = rv = getInt2(io,"CARD16/height");
	toFlash(Xf,"ClearArea W=%u x=%d y=%d w=%d h=%d ",W,x,y,w,h);
	wcc = fwrite(buf,1,rcc,ts);
	return 0;
}
static int relayCopyArea(XFlash *Xf,FILE *fc,FILE *ts,int len,int slen){
	IOStr iob,*io = &iob;
	IStr(buf,32*1024);
	int rcc;
	int wcc;
	int rv;
	int d,D,g,X,x,Y,y,w,h;

	rcc = fread(buf,1,(len-1)*4,fc);
	IOinit(io,Xf," cs CA",buf,rcc);
	D = rv = getInt4(io,"DRAWABLE/src-drawable");
	d = rv = getInt4(io,"DRAWABLE/dst-drawable");
	g = rv = getInt4(io,"GCONTEXT/gc");
	X = rv = getInt2(io,"INT16/src-x");
	Y = rv = getInt2(io,"INT16/src-y");
	x = rv = getInt2(io,"INT16/dst-x");
	y = rv = getInt2(io,"INT16/dst-y");
	w = rv = getInt2(io,"CARD16/width");
	h = rv = getInt2(io,"CARD16/height");
	toFlash(Xf,"CopyArea gc=%d x=%d y=%d w=%d h=%d ",g,x,y,w,h);
	wcc = fwrite(buf,1,rcc,ts);
	return 0;
}
static int relayImageText8(XFlash *Xf,FILE *fc,FILE *ts,int len,int slen){
	IOStr iob,*io = &iob;
	IStr(buf,32*1024);
	int rcc;
	int wcc;
	int rv;
	int d,g,x,y;

	rcc = fread(buf,1,(len-1)*4,fc);
	IOinit(io,Xf," cs IT",buf,rcc);
	fprintf(stderr," -\n");
	d = rv = getInt4(io,"DRAWABLE/drawable");
	g = rv = getInt4(io,"GCONTEXT/gc");
	x = rv = getInt2(io,"INT16/x");
	y = rv = getInt2(io,"INT16/y");
	    rv = getSTRING8(io,"STRING8/string",slen);
	toFlash(Xf,"X %d\n",x);
	toFlash(Xf,"TEXT8 gc=%d x=%d y=%d str=\"%s\"",g,x,y,Xf->xf_string8);
	wcc = fwrite(buf,1,rcc,ts);
	return 0;
}
static int relayInternAtom(XFlash *Xf,FILE *fc,FILE *ts,int len){
	IStr(buf,32*1024);
	int rcc;
	int wcc;
	int rv;
	int nl;
	IOStr iob,*io = &iob;

	rcc = fread(buf,1,(len-1)*4,fc);
	IOinit(io,Xf," cs IA",buf,rcc);
	fprintf(stderr," -\n");
	nl = getInt2(io,"length-of-name");
	rv = getPadN(io,"unused",2);
	rv = getSTRING8(io,"STRING8/name",nl);
rv = skipPad(io,"Pad",8);
	wcc = fwrite(buf,1,rcc,ts);
	return 0;
}
static int relayQueryExtension(XFlash *Xf,OpQue *qop,FILE *fc,FILE *ts,int len){
	IOStr iob,*io = &iob;
	IStr(buf,32*1024);
	int rcc;
	int wcc;
	int rv;
	int nl;

	rcc = fread(buf,1,(len-1)*4,fc);
	IOinit(io,Xf," cs QE",buf,rcc);
	fprintf(stderr," -\n");
	nl = getInt2(io,"length");
	rv = getPadN(io,"unused",2);
	rv = getSTRING8(io,"STRING8/QueryExtension",nl);
fprintf(stderr,"------------- #%d got string, put it into Op Table\n",qop?qop->oq_seq:0);
	rv = skipPad(io,"Pad",8);
	wcc = fwrite(buf,1,rcc,ts);
	return 0;
}
static int scanARC(IOStr *io,const char *what,int gc){
	int rv,x,y,w,h,a,b;
	x = rv = getInt2(io,"INT16/x");
	y = rv = getInt2(io,"INT16/y");
	w = rv = getInt2(io,"CARD16/width");
	h = rv = getInt2(io,"CARD16/height");
	a = rv = getInt2(io,"INT16/angle1");
	b = rv = getInt2(io,"INT16/angle2");
	toFlash(io->in_Xf,"X %d\n",x);
	toFlash(io->in_Xf,"Y %d\n",y);
	toFlash(io->in_Xf,"ARC gc=%d x=%d y=%d w=%d h=%d a1=%d a2=%d",gc,x,y,w,h,a,b);
	return 0;
}
static int relayPolyFillArc(XFlash *Xf,OpQue *qop,FILE *fc,FILE *ts,int len){
	IOStr iob,*io = &iob;
	IStr(buf,32*1024);
	int rcc;
	int wcc;
	int rv;
	int nl;

	rcc = fread(buf,1,(len-1)*4,fc);
	IOinit(io,Xf," cs PF",buf,rcc);
	fprintf(stderr," ----\n");
	rv = getInt4(io,"DRAWABLE/drawable");
	rv = getInt4(io,"GCONTEXT/gc");
	while( 12 <= remLeng(io) ){
		scanARC(io,"ARC",rv);
	}
	wcc = fwrite(buf,1,rcc,ts);
	return 0;
}
static int relayFillPoly(XFlash *Xf,FILE *fc,FILE *ts,int len){
	IOStr iob,*io = &iob;
	IStr(buf,32*1024);
	int rcc;
	int wcc;
	int rv;
	int nl;
	int d,g,s,m,x,y;
	IStr(poly,1024);
	refQStr(pp,poly);

	rcc = fread(buf,1,(len-1)*4,fc);
	IOinit(io,Xf," cs FP",buf,rcc);
	fprintf(stderr," ----\n");
	d = rv = getInt4(io,"DRAWABLE/drawable");
	g = rv = getInt4(io,"GCONTEXT/gc");
	s = rv = getInt1(io,"shape");
	m = rv = getInt1(io,"coordinate-mode");
	    rv = getInt2(io,"unused");
	while( 4 <= remLeng(io) ){
		x = rv = getInt2(io,"INT16/x");
		y = rv = getInt2(io,"INT16/y");
		if( poly < pp ){
			setVStrPtrInc(pp,',');
		}
		sprintf(pp,"%d/%d",x,y);
		pp += strlen(pp);
	}
	toFlash(Xf,"FillPoly gc=%d poly={%s}",g,poly);
	wcc = fwrite(buf,1,rcc,ts);
	return 0;
}


/* X11R6.7DRAFT p.122 */
static int scanVISUALTYPE(IOStr *io,const char *what){
	int rv;
	rv = getInt4(io,"VISUALID/visual-id");
	rv = getInt1(io,"class");
	rv = getInt1(io,"CARD8/bits-per-rgb-value");
	rv = getInt2(io,"CARD16/colormap-entries");
	rv = getInt4(io,"CARD32/red-mask");
	rv = getInt4(io,"CARD32/green-mask");
	rv = getInt4(io,"CARD32/blue-mask");
	rv = getPadN(io,"unused",4);
	return 0;
}
static int scanDEPTH(IOStr *io,const char *what){
	int di;
	int rv;
	int nl;
	int iv;

	rv = getInt1(io,"CARD8/depth");
	rv = getPadN(io,"unused",1);
	nl = getInt2(io,"number-of-VISUALTYPES-in-visuls");
	rv = getPadN(io,"unused",4);
	for( iv = 0; iv < nl; iv++ ){
		if( remLeng(io) <= 0 ){
			return EOF;
		}
		scanVISUALTYPE(io,"Visual");
	}
	return 0;
}
static int scanSCREEN(IOStr *io,const char *what,int sn){
	int rv;
	int nl;
	int di;

	rv = getInt4(io,"WINDOW/root");
	rv = getInt4(io,"COLORMAP/default-colormap");
	rv = getInt4(io,"CARD32/white-pixel");
	rv = getInt4(io,"CARD32/black-pixel");
	rv = getInt4(io,"SETofEVENT/corrent-input-masks");
	rv = getInt2(io,"CARD16/width-in-pixels");
	rv = getInt2(io,"CARD16/height-in-pixels");
	rv = getInt2(io,"CARD16/width-in-millimeters");
	rv = getInt2(io,"CARD16/height-in-millimeters");
	rv = getInt2(io,"CARD16/min-installed-maps");
	rv = getInt2(io,"CARD16/max-installed-maps");
	rv = getInt4(io,"VISUALID/root-visual");
	rv = getInt1(io,"VISUALID/backing-stores");
	rv = getInt1(io,"VISUALID/save-unders");
	rv = getInt1(io,"VISUALID/root-depth");
	nl = getInt1(io,"VISUALID/number-of-DEPTHs-in-allowed-depth");
	for( di = 0; di < nl; di++ ){
		if( remLeng(io) <= 0 ){
			return EOF;
		}
		rv = scanDEPTH(io,"LISTofDEPTH/allowed-depath");
	}
	return 0;
}
static int scanFORMAT(IOStr *io,const char *what){
	int rv;
	rv = getInt1(io,"CARD8/depth");
	rv = getInt1(io,"CARD8/bits-per-pixel");
	rv = getInt1(io,"CARD8/scanline-pad");
	rv = getInt1(io,"Pad");
	rv = getInt4(io,"Pad");
	return 0;
}
static int relayInitialResp(IOStr *io,int op){
	int rv;
	int vl;
	int sl;
	int nl;
	int fi;

	rv = getInt1(io,"Sucess");
	rv = getPadN(io,"unused",1);
	rv = getInt2(io,"major_version");
	rv = getInt2(io,"minor_version");
	rv = getInt2(io,"length/4");
	rv = getInt4(io,"release-number");
	rv = getInt4(io,"resource-id-base");
	rv = getInt4(io,"resource-id-mask");
	rv = getInt4(io,"motion-bufffer-size");
	vl = getInt2(io,"length-of-vendor");
	rv = getInt2(io,"maximum-request-length");
	sl = getInt1(io,"number-of-SCREENs-in-roots");
	nl = getInt1(io,"number-for-FORMATs-in-pixmap-formats");
	rv = getInt1(io,"image-byte-order");
	rv = getInt1(io,"bitmap-format-bit-order");
	rv = getInt1(io,"bitmap-format-scanline-unit");
	rv = getInt1(io,"bitmap-format-scanline-pad");
	rv = getInt1(io,"min-keycode");
	rv = getInt1(io,"max-keycode");
	rv = getPadN(io,"unused",4);
	rv = getSTRING8(io,"Vendor",vl);
rv = skipPad(io,"unused-Padding",4);
	for( fi = 0; fi < nl; fi++ ){
		rv = scanFORMAT(io,"Format");
	}
	rv = scanSCREEN(io,"Screen",sl);
rv = skipPad(io,"Pad",8);
	return 0;
}
static int scanresp(IOStr *io,int op,int seq,OpQue *qop,const char *resp,int rcc){
	int rv;
	int nl;

	if( op == OP_InitialResp ){
		relayInitialResp(io,op);
	}else
	if( resp[0] == EV_KeyPress ){
		fprintf(stderr," seq=%d\n",seq);
		rv = getInt1(io,"evcode");
		rv = getInt1(io,"KEYCODE");
			toFlash(io->in_Xf,"KeyPress code=%d",rv);
		rv = getInt2(io,"CARD16/Seq#");
		/*
		if( resp[0] == EV_KeyPress ){
			rv = getInt4(io,"TIMESTAMP/time");
			rv = getInt4(io,"WINDOW/root");
			rv = getInt4(io,"WINDOW/event");
			rv = getInt4(io,"WINDOW/child");
			rv = getInt2(io,"INT16/root-x");
			rv = getInt2(io,"INT16/root-y");
			rv = getInt2(io,"INT16/event-x");
			rv = getInt2(io,"INT16/event-y");
			rv = getInt2(io,"SETofKEYBUTMASK/state");
			rv = getInt1(io,"BOOL/same-screen");
		}
		*/
	}else{
		fprintf(stderr," seq=%d\n",seq);
		rv = getInt1(io,"Reply");
		rv = getInt1(io,"opt");
		rv = getInt2(io,"CARD16/Seq#");
		if( op == OP_QueryExtension ){
			rv = getInt4(io,"CARD32/length");
			rv = getInt1(io,"BOOL/present");
			rv = getInt1(io,"CARD8/major-opcode");
fprintf(stderr,"------------- #%d got opcode=%d, put it into Op Table\n",qop?qop->oq_seq:0,rv);
//addop(rv);
			rv = getInt1(io,"CARD8/first-event");
			rv = getInt1(io,"CARD8/first-error");
		}else
		if( op == OP_InternAtom ){
			rv = getInt4(io,"CARD32/length");
			rv = getInt4(io,"ATOM/atom");
		}else
		if( op == OP_GetProperty ){
			rv = getInt4(io,"CARD32/length");
			rv = getInt4(io,"ATOM/atom");
			rv = getInt4(io,"CARD32/bytes-after");
			rv = getInt4(io,"CARD32/length-of-value-in-format-units");
			rv = getPadN(io,"unused",12);
		}else
		if( op == OP_QueryPointer ){
			rv = getInt4(io,"CARD32/length");
			rv = getInt4(io,"WINDOW/root");
			rv = getInt4(io,"WINDOW/child");
			rv = getInt2(io,"INT16/root-x");
			rv = getInt2(io,"INT16/root-y");
			rv = getInt2(io,"INT16/win-x");
			rv = getInt2(io,"INT16/win-y");
			rv = getInt2(io,"SETofKEYBUTMASK/mask");
		}
	}
	return 0;
}

static int XCS(XFlash *Xf){
	Connection *Conn = Xf->xf_Conn;
	int count;
	int total;
	FILE *fc;
	FILE *ts;
	int ch,op;
	int b_order;
	int min; /* minor opcode ? */
	int len;
	int rem;
	int ci;
	int ver,rev,nan,nad;
	OpQue *qop = 0;

	total = count = 0;
	fc = fdopen(FromC,"r");
	ts = fdopen(ToS,"w");

	if( 1 ){ /* CS specific ? */
		b_order = Getc(fc,ts);
		fprintf(stderr,"CS BYTEORDER: %X:%c\n",b_order,b_order);
		if( b_order == 'l' || b_order == 'L' ){
			Verbose("#### LITTLE ENDIEN ####\n");
			LEND = 1;
		}else	LEND = 0;
		Getc(fc,ts); /* padding */

		ver = GetInt2(fc,ts);
		rev = GetInt2(fc,ts);
		fprintf(stderr,"CS VERSION: %d.%d\n",ver,rev);
		nan = GetInt2(fc,ts);
		nad = GetInt2(fc,ts);
		GetInt2(fc,ts); /* padding */

		for(;;){
			const char *sop = 0;
			int withret;

			if( ready_cc(fc) == 0 )
				fflush(ts);
			op = getc(fc);
			if( op == EOF ){
				fprintf(stderr,"EOF from the client\n");
				break;
			}
			if( putc(op,ts) == EOF ){
				fprintf(stderr,"EOF from the server\n");
				break;
			}
			min = Getc(fc,ts);
			len = GetInt2(fc,ts);
			Qseq++;
			sop = opsym(op,&withret);
			if( sop != 0 && withret ){
				qop = enqOp(Qseq,op);
			}else{
				qop = 0;
			}
			if( sop ){
				fprintf(stderr,"#%d CS %-20s %3d %4d",Qseq,sop,min,len);
			}else{
				fprintf(stderr,"#%d CS ?%-19d %3d %4d ----",Qseq,op,min,len);
			}

			switch( op ){
				case OP_ClearArea:
					relayClearArea(Xf,fc,ts,len,min);
					break;
				case OP_ImageText8:
					relayImageText8(Xf,fc,ts,len,min);
					break;
				case OP_InternAtom:
					relayInternAtom(Xf,fc,ts,len);
					break;
				case OP_QueryExtension:
					relayQueryExtension(Xf,qop,fc,ts,len);
					break;
				case OP_FillPoly:
					relayFillPoly(Xf,fc,ts,len);
					break;
				case OP_PolyFillArc:
					relayPolyFillArc(Xf,qop,fc,ts,len);
					break;
				default:
					relayRequest(Xf,qop,fc,ts,len);
					break;
			}
			fflush(ts);
			fflush(stderr);
			count += 1;
			total += 1;
		}
	}
	fprintf(stderr,"---- CS-RELAY[%d>%d]: %dBytes %dI/O\n",FromC,ToS,total,count);
	return total;
}
static int XSC(XFlash *Xf,int fsbsize){
	Connection *Conn = Xf->xf_Conn;
	IStr(buf,0x4000);
	int rcc,wcc;
	int count,total;
	int pi;
	int ri;
	const char *ev;
	IStr(evb,128);
	IOStr io;
	int op;
	int seq = -1;
	OpQue qop;

	enqOp(0,OP_InitialResp);
	io.in_fp = fdopen(FromS,"r");
	total = count = 0;
	if( fsbsize == 0 )
		fsbsize = 1;
	if( sizeof(buf) < fsbsize )
		fsbsize = sizeof(buf);
	if( 1 ){
		for( ri = 0; ; ri++ ){
			if( ri == 0 ){
				rcc = read(FromS,buf,QVSSize(buf,fsbsize));
			}else{
				rcc = read(FromS,buf,32);
			}
			if( rcc <= 0 ){
				break;
			}
			op = -1;
			qop.oq_code = -1;
			qop.oq_seq = -1;

			switch( buf[0] ){
				case  1:
					op = deqOp(&seq,&qop);
					sprintf(evb,"RETURN(%s)",opsymX(op));
					ev = evb;
					break;

				default:
					ev = evsym(0xFF & buf[0]);
					if( ev == 0 ){
						sprintf(evb,"#%d",0xFF & buf[0]);
						ev = evb;
					}
			}

			count += 1;
			total += rcc;
			if( (wcc = write(ToC,buf,rcc)) <= 0 )
				break;

			fprintf(stderr,"SC %-20s %3d ",ev,rcc);
			for( pi = 0; pi < 32; pi++ ){
				fprintf(stderr," %02X",0xFF & buf[pi]);
			}
			fprintf(stderr,"\n");
			fflush(stderr);

			IOinit(&io,Xf," sc",buf,rcc);
			scanresp(&io,op,seq,&qop,buf,rcc);
		}
		if( rcc <= 0 ) sv1log("SC-EOF\n");
	}
	sv1log("---- SC-RELAY[%d<%d]: %dBytes %dI/O buf=%d\n",
		ToC,FromS,total,count,fsbsize);
	return total;
}

static int toFlash(XFlash *Xf,PCStr(fmt),...){
	VARGS(16,fmt);

	fprintf(stderr,"####[%4X] XFlash ",PRTID(getthreadid()));
	fprintf(stderr,fmt,VA16);
	fprintf(stderr,"\n");
	if( Xf->xf_xfsockfp != NULL ){
		fprintf(Xf->xf_xfsockfp,fmt,VA16);
		fprintf(Xf->xf_xfsockfp,"\r\n");
		fflush(Xf->xf_xfsockfp);
	}
	return 0;
}
static int Xnew(XFlash *Xf,int svsock){
	Connection *Conn = Xf->xf_Conn;
	int client;
	int server;

	for(;;){
		client = ACCEPT(svsock,0,-1,0);
		server = client_open("XFlash","XCFlash","127.0.0.1",6001);
		if( server < 0 ){
			continue;
		}
		FromC = ToC = client;
		FromS = ToS = server;
		Xf->xf_cstid = thread_fork(0,0,"XFlash-CS",(IFUNCP)XCS,Xf);
		Xf->xf_sctid = thread_fork(0,0,"XFlash-SC",(IFUNCP)XSC,Xf,1024);
	}
	return 0;
}
static int forkXclient(char *arg,char *dispenv){
	int client,server;
	int ph;
	char *av[2];
	char *ev[2];

	av[0] = arg;
	av[1] = 0;
	ev[0] = dispenv;
	ev[1] = 0;
 putenv(dispenv);
	bgexecX("e",arg,av,ev,&ph);
	return 0;
}
static int XFlashClient(XFlash *Xf){
	Connection *Conn = Xf->xf_Conn;
	FILE *fc;
	FILE *tc;
	IStr(req,128);
	IStr(com,128);
	IStr(arg,128);
	const char *dp;
	IStr(svhost,128);
	int svsock;
	int port;
	IStr(dispenv,128);
	int actid;

	fc = fdopen(FromC,"r");
	tc = fdopen(ToC,"w");
	if( tc == NULL || fc == NULL ){
		return -1;
	}
	Xf->xf_xfsockfp = tc;
	toFlash(Xf,"INIT2");
	fflush(tc);

	strcpy(svhost,"127.0.0.1");
	for( port = 6001; port < 6010; port++ ){
		svsock = server_open("XFlash",AVStr(svhost),port,1);
		if( 0 <= svsock ){
			break;
		}
	}
	sprintf(dispenv,"DISPLAY=127.0.0.1:%d.0",port-6000);
	fprintf(stderr,"--- env[%s]\n",dispenv);
	actid = thread_fork(0,0,"XFlash-TH",(IFUNCP)Xnew,Xf,svsock);

	for(;;){
		if( fgets(req,sizeof(req),fc) == NULL ){
			break;
		}
		dp = wordScan(req,com);
		dp = lineScan(dp,arg);
		fprintf(stderr,"---- [%s][%s]\n",com,arg);
		if( strcaseeq(com,"quit") || strcaseeq(com,"exit") ){
			break;
		}
		if( strcaseeq(com,"x") ){
			forkXclient(arg,dispenv);
		}
	}
	return 0;
}
static int XFP(XFlash *Xf,int server){
	IStr(svhost,MaxHostNameLen);
	int svport;
	int svsock;
	int timeout = 0;
	Connection *Conn = Xf->xf_Conn;

	if( !server ){
		XFlashClient(Xf);
		return 0;
	}

	/* observers */
	strcpy(svhost,"0.0.0.0");
	svport = 6003;
	svsock = server_open("XFlash",AVStr(svhost),svport,1);
	for(;;){
		/* broad casting ? */
		Xf->xf_xfsockfd = ACCEPT(svsock,0,-1,timeout);
		Xf->xf_xfsockfp = fdopen(Xf->xf_xfsockfd,"w+");
		fprintf(stderr,"---- xfsock[%d]\n",Xf->xf_xfsockfd);
		toFlash(Xf,"INIT");
	}
	return 0;
}

static int relayTee(Connection *Conn,int fcbsize,int fsbsize,int server){
	int scerr,cserr;
	XFlash Xf;

	fprintf(stderr,"---relayTee\n");
	Xf.xf_Conn = Conn;
	Xf.xf_xfsockfd = -1;
	Xf.xf_xfsockfp = 0;

	if( server ){
		Xf.xf_cstid = thread_fork(0,0,"XFlash-CS",(IFUNCP)XCS,&Xf);
		Xf.xf_sctid = thread_fork(0,0,"XFlash-SC",(IFUNCP)XSC,&Xf,fsbsize);
		Xf.xf_fptid = thread_fork(0,0,"XFlash-Player",(IFUNCP)XFP,&Xf,server);
		cserr = thread_wait(Xf.xf_cstid,0);
		scerr = thread_wait(Xf.xf_sctid,1);
		sv1log("---- XFinished %X/%d %X/%d\n",
			PRTID(Xf.xf_cstid),cserr,PRTID(Xf.xf_sctid),scerr);
	}else{
		XFP(&Xf,server);
	}
	return 0;
}
int service_XCFlash(Connection *Conn){
	fprintf(stderr,"---XCFlash [%d %d]\n",FromC,ToC);
	relayTee(Conn,0x1000,0x1000,0);
	return 0;
}
int service_XSFlash(Connection *Conn){
	if( ToS < 0 ){
		sv1log("No connection\n");
		return -1;
	}
	relayTee(Conn,0x1000,0x1000,1);
	return 0;
}
