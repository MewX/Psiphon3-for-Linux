#ifndef _HTADM_H
#define _HTADM_H

/*-- /-/admin/ */
typedef struct {
	char	*ad_AdminUser;
	char	*ad_AdminPass; /* in MD5 */
	int	 ad_Form_argc;
	int	 ad_Form_argcmax;
	const char  **ad_Form_argv;
	int	 ad_admin_genc;
	const char	*ad_admin_genv[64];
	int	 ad_getv_mask[4];
	int	 ad_config_errors[4];

	defQStr( ad_respmssg);
	const char	*ad_admcom;
	const char	*ad_admpath;
	const char	*ad_com;
	const char	*ad_act;
	const char	*ad_prevact;
	const char	*ad_command;
	char	*ad_stat;
	MStr(	 ad_user,64);
	MStr(	 ad_domain,64);
	char	 ad_basic;
	FILE	*ad_mssg;
	const char	*sd_dir;
	FILE	*sd_fc;
	FileSize sd_fileHead;
} AdminCtx;
AdminCtx *myAdminCtx(Connection *Conn);
#define myAdmCtx myAdminCtx(Conn)

#define AdminUser	myAdmCtx->ad_AdminUser
#define AdminPass	myAdmCtx->ad_AdminPass
#define Form_argc	myAdmCtx->ad_Form_argc
#define Form_argcmax	myAdmCtx->ad_Form_argcmax
#define Form_argv	myAdmCtx->ad_Form_argv
#define admin_genc	myAdmCtx->ad_admin_genc
#define admin_genv	myAdmCtx->ad_admin_genv
#define admin_getv_mask	myAdmCtx->ad_getv_mask
#define config_errors	myAdmCtx->ad_config_errors

#define admin_respmssg	myAdmCtx->ad_respmssg
#define admin_admcom	myAdmCtx->ad_admcom
#define admin_admpath	myAdmCtx->ad_admpath
#define admin_com	myAdmCtx->ad_com
#define admin_act	myAdmCtx->ad_act
#define admin_prevact	myAdmCtx->ad_prevact
#define admin_command	myAdmCtx->ad_command
#define admin_stat	myAdmCtx->ad_stat
#define admin_user	myAdmCtx->ad_user
#define admin_domain	myAdmCtx->ad_domain
#define admin_basic	myAdmCtx->ad_basic
#define admin_mssg	myAdmCtx->ad_mssg
#define sd_dir		myAdmCtx->sd_dir
#define sd_fc		myAdmCtx->sd_fc
#define fileHead	myAdmCtx->sd_fileHead

void HTML_putmssg(Connection *Conn,PVStr(mssg),PCStr(fmt),...);
#if defined(_MSC_VER) || defined(NONC99)
	/* putMssg() will be expanded in mkcpp */
#else
#define putMssg(mb,fmt,...) HTML_putmssg(Conn,mb,fmt,##__VA_ARGS__)
#endif

const char *admin_getvX(Connection *Conn,PCStr(name));
#define admin_getv(nm) admin_getvX(Conn,nm)

void set_conferrorX(Connection *Conn,PCStr(confname));
void clear_conferrorX(Connection *Conn);
#define get_conferror(cn) get_conferrorX(Conn,cn)
#define set_conferror(cn) set_conferrorX(Conn,cn)
#define clear_conferror() clear_conferrorX(Conn)

int conf2formX(Connection *Conn,PVStr(msg),PCStr(cf),int mac,const char *av[]);
int form2confX(Connection *Conn,PVStr(msg),FILE *tc,int toHTML,int ln);
FILE *fopen_lockconfX(Connection *Conn,PVStr(msg),PCStr(name),PCStr(mode),PVStr(path),int create);
#define conf2form(msg,conf,mac,av)  conf2formX(Conn,msg,conf,mac,av)
#define form2conf(msg,tc,toHTML,ln) form2confX(Conn,msg,tc,toHTML,ln)
#define fopen_lockconf(b,n,m,p,c)   fopen_lockconfX(Conn,b,n,m,p,c)

#endif
