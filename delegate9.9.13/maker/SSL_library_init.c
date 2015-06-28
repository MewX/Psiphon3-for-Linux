int SUBST_Library = 1;

int SSLeay_add_ssl_algorithms();
int SSL_library_init()
{
	return SSLeay_add_ssl_algorithms();
}
