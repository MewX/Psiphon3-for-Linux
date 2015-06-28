#ifndef _URL_H_
#define _URL_H_

#define ODGU_MARK	"=@="
#define NDGU_MARK	"-_-"
#define URLSZ		(16*1024)
typedef char URLStr[URLSZ];

#define scan_Hostport1(hp,h)	scan_hostport1X(hp,AVStr(h),sizeof(h))
#define scan_Hostport1p(p,hp,h)	scan_hostport1pX(p,hp,AVStr(h),sizeof(h))

typedef struct {
	UTag	ut_method;
	UTag	ut_prefix;
	UTag	ut_proto;
	UTag	ut_user;
	UTag	ut_host;
	UTag	ut_port;
	UTag	ut_path;
} TUrl;

typedef struct {
  const char   *u_method;
  const char   *u_proto;
  const char   *u_host;
	int	u_port;
  const char   *u_path;
  const char   *u_hostport;
  const char   *u_base;
	int	u_pri; /* use this prior to others (BASEURL than Host) */
} UrlX;

typedef struct {
	MStr(	r_curtag,32); /* in the tag now */
	MStr(	r_curscript,16); /* now scanning <SCRIPT> */
	MStr(	r_curstyle,16); /* now in the <STYLE> */
	char    r_curquote; /* the quote char. of the current quote string */
} TagCtx;

/*
 * the context of the base document including URLs to be rewritten
 */
typedef struct {
	UrlX	r_sv;	/* URL of target */
	UrlX	r_my;	/* real URL of me (DeleGate) */
	UrlX	r_vb;	/* virtual base URL of me for client */
	UrlX	r_qvbase; /* v9.9.11 per request URL vbase (SSI vbase) */
	UrlX	r_requrl; /* v9.9.11 decomposed original request URL */
	int	r_flags;  /* v9.9.11 reverse MOUNT control flags */
  const	char   *r_cType; /* type of base data {html, css, header} */
	TagCtx	r_tagctx;
	defQStr(r_altbuf);
} Referer;

#define UMF_QUERY_FULL	1 /* fullify HREF="?query" to "full-url?query" */

#define TX_PLAIN	1
#define TX_HTML		2
#define TX_MISC		3
#define TX_CSS		4
#define TX_JAVASCRIPT	5
#define TX_XML		6

#define URL_IN_HEAD		0x0001 /* in HTTP header like Location: ... */
#define URL_IN_HTML_TAG		0x0010 /* in HTML tag like <A HREF=...> */
#define URL_IN_ATTR_STYLE	0x0020 /* in HTML tag attr like STYLE=... */
#define URL_IN_ATTR_SCRIPT	0x0040 /* in HTML tag attr like onClick=... */
#define URL_IN_ATTR_EMBED	(URL_IN_ATTR_STYLE|URL_IN_ATTR_SCRIPT)
#define URL_IN_HTML_STYLE	0x0080 /* in <STYLE>...</STYLE> */
#define URL_IN_HTML_SCRIPT	0x0100 /* in <SCRIPT>...</SCRIPT> */
#define URL_IN_HTML_EMBED	(URL_IN_HTML_STYLE|URL_IN_HTML_SCRIPT)
#define URL_IN_STYLE		0x1000 /* in text/css */
#define URL_IN_SCRIPT		0x2000 /* in text/javascript */
#define URL_IN_SCRIPTs (URL_IN_ATTR_SCRIPT|URL_IN_HTML_SCRIPT|URL_IN_SCRIPT)
#define URL_IN_SWF		0x4000 /* in Shockwave-Flash */
#define URL_IN_XML		0x8000 /* in XML document */
#define URL_IN_ANY		0xFFFF

extern int URL_SEARCH;

#endif /* _URL_H_ */
