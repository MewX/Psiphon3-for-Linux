int SUBST_SSL_CTX = 1;

#define SSL_CTRL_SET_TMP_RSA_CB 4
void SSL_CTX_ctrl(int,int,int,void(*)());
void SSL_CTX_set_tmp_rsa_callback(int ctx,void (*tmprsa_callback)())
{
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_RSA_CB,0,tmprsa_callback);
}
