int porting_dbg(const char *fmt,...);
#ifdef __cplusplus
extern "C" {
#endif
	int SSL_get_servername_NONE = 1;

	typedef void SSL;
	typedef void SSL_CTX;
	const char *SSL_get_servername(const SSL *s, const int type){
		porting_dbg("## SSL_get_servername() NONE\n");
		return 0;
	}
	int SSL_get_servername_type(const SSL *s){
		porting_dbg("## SSL_get_servername_type() NONE\n");
		return 0;
	}
	SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX* ctx){
		porting_dbg("## SSL_set_SSL_CTX() NONE\n");
		return 0;
	}
#ifdef __cplusplus
}
#endif
