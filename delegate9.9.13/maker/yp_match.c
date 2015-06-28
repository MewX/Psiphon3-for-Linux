int SUBST_yp_match = 1;
int porting_dbg(const char *fmt,...);

#if defined(__cplusplus)
extern "C" {
#endif
int yp_match(const char *dom,const char *map,const char *key,int keylen,char **val,int *vallen)
{
	*val = "";
	*vallen = 0;
	return 5;
}
int yp_get_default_domain(char **domain)
{
	porting_dbg("** NO NIS module **");
	*domain = "";
	return 12;
}
#if defined(__cplusplus)
}
#endif
