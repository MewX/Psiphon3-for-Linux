#ifndef _PWD_H
#define _PWD_H
struct passwd {
  const	char	*pw_name;
  const	char	*pw_passwd;
	short	 pw_uid;
	short	 pw_gid;
	int	 pw_quota;
  const	char	*pw_comment;
  const	char	*pw_gecos;
  const	char	*pw_dir;
  const	char	*pw_shell;
};
#endif

#ifndef _GRP_H
#define _GRP_H
struct group {
  const	char	*gr_name;
  const	char	*gr_passwd;
	int	 gr_gid;
  const	char	**gr_mem;
};
#endif
