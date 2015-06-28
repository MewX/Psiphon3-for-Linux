/*
 * 2005-10-22 ysato AT delegate DOT org
 */
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>

#ifdef NOSEARCH_H
typedef enum { FIND, ENTER } ACTION;
typedef struct { char *key; void *data; } ENTRY;
extern "C" {
	ENTRY *hsearch(ENTRY item,ACTION act);
	int hcreate(unsigned size);
}
#else
#include <search.h>
#endif

static int o_dumpnew = 1;
static char *ifmts = "%s %*s %*s [%[^]]] \"%[^\"]\" %s %s %s \"%[^\"]\" %s";

#define LINEWIN		1024
#define LINESIZE	2048

static int h_init;
static int h_id[128];
static struct data {
	int	d_id;
	int	d_count;
	time_t	d_itvl;
	time_t	d_prev;
	int	d_type;
  const char   *d_key;
 struct data   *d_link;
} data;
static struct data *dlist[128];
static struct data *getid(int htype,const char *key,time_t udate){
	char hkey[1024];
	ENTRY he;
	ENTRY *hep;
	struct data *dp;

	if( h_init == 0 ){
		hcreate(32*1024);
		h_init = 1;
	}
	hkey[0] = htype;
	strcpy(hkey+1,key);
	he.key = hkey;
	he.data = 0;
	if( hep = hsearch(he,FIND) ){
		dp = (struct data*)hep->data;
		dp->d_count++;
		dp->d_itvl = udate - dp->d_prev;
		dp->d_prev = udate;
		return (struct data*)hep->data;
	}else{
		h_id[htype] += 1;
		data.d_count = 0;
		dp = (struct data*)malloc(sizeof(data));
		dp->d_count = 1;
		dp->d_itvl = 0;
		dp->d_prev = udate;
		dp->d_id = h_id[htype];
		dp->d_type = htype;
		dp->d_key = strdup(key);
		dp->d_link = dlist[htype];
		dlist[htype] = dp;

		he.key = strdup(hkey);
		he.data = (char*)dp;
		hsearch(he,ENTER);
		if( o_dumpnew )
			printf("+ %d%c=%s\n",dp->d_id,htype,key);
		return (struct data*)he.data;
	}
}
static int dsort(const void *a,const void *b){
	if( (*(struct data**)a)->d_count < (*(struct data**)b)->d_count )
		return 1;
	else	return -1;
}
static void dump_hosts(){
	struct data *dp;
	struct data *ds[0x10000];
	int dx,di;
	int tcount = 0;
	int tcum = 0;

	dx = 0;
	for( dp = dlist['H']; dp; dp = dp->d_link ){
		ds[dx++] = dp;
		tcount += dp->d_count;
		if( 0x10000 <= dx )
			break;
	}
	fprintf(stderr,"Host: total=%d count=%d\n",dx,tcount);
	qsort(ds,dx,sizeof(struct data*),dsort);
	for( di = 0; di < dx; di++ ){
		dp = ds[di];
		tcum += dp->d_count;
		printf("- %5d %6d %6.2f%% %4dH %4dJ %s\n",
			di+1,tcum,(tcum*100.0)/tcount,
			dp->d_id,dp->d_count,dp->d_key+1);
	}
}

static const char *Month[] =
{"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec",0};
static int montoi(const char *mon){
	int i;
	const char *mo;
	for( i = 0; mo = Month[i]; i++ )
		if( strcmp(mo,mon) == 0 )
			return i+1; 
	return 0;
}
static int scan_hldate(const char *date,char *sdate){
	char y[128],m[128],d[128],hms[128];
	int H,M,S;
	struct tm tm;
	time_t udate;

	y[0] = m[0] = d[0] = hms[0] = 0;
	sscanf(date,"%[^/]/%[^/]/%[^:]:%[^ ]]",d,m,y,hms);
	sprintf(sdate,"%s/%02d/%s-%s",y,montoi(m),d,hms);

	H = M = S = 0;
	sscanf(hms,"%d:%d:%d",&H,&M,&S);

	tm.tm_sec = S;
	tm.tm_min = M;
	tm.tm_hour = H;
	tm.tm_mday = atoi(d);
	tm.tm_mon = montoi(m)-1;
	tm.tm_year = atoi(y) - 1900;
	tm.tm_wday = 0;
	tm.tm_yday = 0;
	tm.tm_isdst = 0;
	udate = mktime(&tm);
	return udate;
}

/*
static char *ifmtx0 = "%d %s %s %*s %*s \"%[^\"]\" %s %s %s \"%[^\"]\" %s";
*/
static char *ifmtx = "%d %s %s %*s %*s \"%S\" %s %s \"%S\" \"%S\" %s";
static int lscanf(const char *str,const char *fmt,...){
	va_list ap;
	const char *sp;
	const char *fp;
	char fc;
	int nf = 0;
	char *dp;
	int *ip;
	int ign;

	va_start(ap,fmt);
	sp = str;
	for( fp = fmt; fc = *fp; fp++ ){
		if( fc == ' ' ){
			while( *sp == ' ' )
				sp++;
		}else
		if( fc == '%' ){
			if( fp[1] == 0 )
				break;
			fc = *++fp;
			if( ign = (fc == '*') ){
				if( fp[1] == 0 )
					break;
				fc = *++fp;
			}
			if( fc == 'S' ){
				if( fp[1] == 0 )
					break;
				fc = *++fp;
				if( ign ){
					while( *sp && *sp != fc ){
						*sp++;
					}
				}else{
					dp = va_arg(ap,char*);
					while( *sp && *sp != fc ){
						*dp++ = *sp++;
					}
					*dp = 0;
					if( *sp == fc )
						sp++;
					nf++;
				}
			}else
			if( fc == 's' ){
				if( ign ){
					while( *sp && *sp != ' ' )
						*sp++;
				}else{
					dp = va_arg(ap,char*);
					while( *sp && *sp != ' ' ){
						*dp++ = *sp++;
					}
					*dp = 0;
					nf++;
				}
			}else
			if( fc == 'd' ){
				if( ign ){
				}else{
					ip = va_arg(ap,int *);
					*ip = atoi(sp);
					nf++;
				}
				if( *sp == '-' )
					sp++;
				while( *sp && isdigit(*sp) )
					sp++;
			}
		}else{
			if( *sp != fc ){
/*
fprintf(stderr,"error nf=%d [%s][%s]\n",nf,fp,sp);
*/
				break;
			}
			sp++;
		}
	}
	return nf;
}

#define F_ALL		0x00
#define F_CLHOST	0x01
#define F_CLIDENT	0x02
#define F_CLAUTH	0x03
#define F_DATE		0x04
#define F_REQ		0x05
#define F_QMETHOD	0x06
#define F_QURL		0x07
#define F_QVER		0x08
#define F_RCODE		0x09
#define F_RSIZE		0x0A
#define F_REF		0x0B
#define F_UA		0x0C
#define F_DGEXT		0x0D
#define F_SDATE		0x1F
#define F_REFI		0x1E
#define F_UAI		0x1D

typedef struct {
	char	 fields[32][LINESIZE];
	time_t	 f_Udate;
} Fields;

#define line	fields->fields[F_ALL]
#define host	fields->fields[F_CLHOST]
#define date	fields->fields[F_DATE]
#define req	fields->fields[F_REQ]
#define rcode	fields->fields[F_RCODE]
#define rsize	fields->fields[F_RSIZE]
#define ref	fields->fields[F_REF]
#define refi	fields->fields[F_REFI]
#define ua	fields->fields[F_UA]
#define uai	fields->fields[F_UAI]
#define ext	fields->fields[F_DGEXT]
#define sdate	fields->fields[F_SDATE]
#define Udate	fields->f_Udate

typedef struct {
	char	*l_lines[LINEWIN];
	char	 l_linesb[LINEWIN][LINESIZE];
	int	 l_linesN;
	int	 l_linesI; /* next point to be input */
	int	 l_linesO; /* next point to be output */
	int	 l_Nin;
	int	 l_Nso; /* sorted */
	int	 l_Nlines;
	int	 l_Nbad;
} Lines;
static Lines *linesp;
#define lines	linesp->l_lines
#define linesb	linesp->l_linesb
#define linesN	linesp->l_linesN
#define linesI	linesp->l_linesI
#define linesO	linesp->l_linesO
#define Nin	linesp->l_Nin
#define Nso	linesp->l_Nso
#define Nlines	linesp->l_Nlines
#define Nbad	linesp->l_Nbad

static int lsort(const void *a,const void *b){
	return strcmp(*(char**)a,*(char**)b);
}
static char *fgetline1(char *lbuff,int lsize,FILE *fp){
	char *dp;
	char *ep;
	time_t udate;
	char lb[LINESIZE];
	char sd[LINESIZE];

	if( fgets(lb,LINESIZE,fp) == NULL )
		return NULL;
	if( dp = strpbrk(lb,"\r\n") )
		*dp = 0;

	if( (dp = strchr(lb,'[')) && (ep = strchr(dp+1,']')) ){
		udate = scan_hldate(dp+1,sd);
		if( ep[1] == ' ' )
			ep++;
		strcpy(dp,ep+1);
		snprintf(lbuff,lsize,"%d %s %s",udate,sd,lb);
	}else{
		snprintf(lbuff,lsize,"0 - %s",lb);
	}
	return lbuff;
}
static void bubble_sort(Lines *linesp,int lout,int lin){
	int li;
	char *li0 = lines[(lin-1)%LINEWIN];
	char **lcp;
	int n0 = atoi(li0);
	int ni;

	for( li = lin-2; lout <= li; li-- ){
		lcp = &lines[li%LINEWIN];
		if( n0 < atoi(*lcp) ){
			lines[(li+1)%LINEWIN] = *lcp;
			*lcp = li0;
		}else{
			break;
		}
	}
}
static int fgetline(Fields *fields,FILE *fp){
	int li;
	int nf;

	if( lines[0] == 0 ){
		for( li = 0; li < LINEWIN; li++ ){
			if( fgetline1(linesb[li],LINESIZE,fp) == NULL )
				break;
			lines[li] = linesb[li];
		}
		linesN = li;
		qsort(lines,linesN,sizeof(char*),lsort);
		linesI = li;
		linesO = 0;
	}
	if( !feof(fp) && linesN < LINEWIN ){
		int lp;
		lp  = (linesI-1)%LINEWIN;
		Nin++;
		li = linesI%LINEWIN;
		if( fgetline1(lines[li],LINESIZE,fp) != NULL ){
			linesI++;
			linesN++;
			if( 1 < linesN && atoi(lines[li]) < atoi(lines[lp]) ){
				Nso++;
				bubble_sort(linesp,linesO,linesI);
			}
		}
	}
	if( linesN <= 0 )
		return -1;

	strcpy(line,lines[linesO%LINEWIN]);
	linesO++;
	linesN--;

/*
	nf = sscanf(line,ifmtx0,&Udate,sdate,host,req,rcode,rsize,ref,ua,ext);
fprintf(stderr,"-A- %d [%s][%s][%s][%s][%s]\n",nf,req,rcode,rsize,ref,ua);
*/
	nf = lscanf(line,ifmtx,&Udate,sdate,host,req,rcode,rsize,ref,ua,ext);
	return nf;
}

int main(int ac,char *av[]){
	Lines linesBuf;
	Fields fieldsb;
	Fields *fields = &fieldsb;
	const char *hostp;
	char *hp;
	char hc;
	char *fmt;
	char fc;
	char *fp;
	FILE *out = stdout;
	struct data *he;
	struct data *re;
	struct data *ae;
	char fmtb[32];
	char *fx = &fmtb[sizeof(fmtb)-1];
	int fi;
	int nf;

	if( 1 < ac )
		fmt = av[1];
	else	fmt = "%d %RR %SS %AA %HH %II %JJ";

	linesp = &linesBuf;
	bzero(&linesBuf,sizeof(linesBuf));
	for(;;){
		for( fi = 0; fi < 32; fi++ ){
			Udate = 0;
			fields->fields[fi][0] = 0;
		}
		if( 1 ){
			if( (nf = fgetline(fields,stdin)) < 0 ){
				break;
			}
			if( nf != 9 ){
				printf("? %s\n",line);
				Nbad++;
				continue;
			}
		}else{
			if( fgets(line,sizeof(line),stdin) == NULL ){
				break;
			}
			nf = sscanf(line,ifmts,
				host,date,req,rcode,rsize,ref,ua,ext);
			if( nf != 8 ){
				printf("? %s\n",line);
				Nbad++;
				continue;
			}
			Udate = scan_hldate(date,sdate);
		}
		Nlines++;
		if( hostp = strchr(host,':') )
			hostp++;
		else	hostp = host;
		for( hp = (char*)hostp; hc = *hp; hp++ ){
			if( isupper(hc) )
				*hp = tolower(hc);
		}

		he = getid('H',hostp,Udate);
		re = getid('R',ref,Udate);
		ae = getid('A',ua,Udate);

		for( fp = fmt; fc = *fp; fp++ ){
			if( fc != '%' || fp[1] == 0 ){
				putc(fc,out);
				continue;
			}
			fc = *++fp;
			switch( fc ){
				case '%': putc(fc,out); break;
				case 'Z':
					fputs(line,out);
					break;
				case 'h':
					fputs(hostp,out);
					break;
				case 'H': /*host-id*/
					fprintf(out,"%5d",he->d_id);
					break;
				case 'I': /* host-id interval */
					fprintf(out,"%6d",he->d_itvl);
					break;
				case 'J': /* host-id count */
					fprintf(out,"%5d",he->d_count);
					break;
				case 'd':
					fputs(sdate,out); break;
				case 'D':
					fprintf(out,"%d",Udate);
					break;
				case 'q': fputs(req,out); break;
				case 'm': /* request method */
					break;
				case 'u': /* request URL */
					break;
				case 'U': /* request URL-id */
					break;
				case 'v': /* request version */
					break;
				case 'r': fputs(ref,out); break;
				case 'R': /* ref-id */
					fprintf(out,"%3d",re->d_id);
					break;
				case 'S':
					fprintf(out,"%4d",re->d_count);
					break;
				case 'a': fputs(ua,out); break;
				case 'A':
					fprintf(out,"%4d",ae->d_id);
					break;
				case 'B':
					fprintf(out,"%4d",ae->d_count);
					break;
				case 'x': fputs(ext,out); break;

				case 'Q': /* req-id */
				default:
					fprintf(stderr,"--- unkown %c\n",fc);
					break;
			}
		}
		fputs("\n",stdout);
	}

	fprintf(stderr,"sorted locally: %d / %d\n",Nso,Nin);
	fprintf(stderr,"bad line: %d / %d\n",Nbad,Nlines);

	dump_hosts();
	return 0;
}
