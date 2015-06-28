#ifdef __cplusplus
extern "C" {
#endif

int SUBST_strdup = 1;

unsigned int strlen(const char *str);
void *malloc(unsigned int);
void *memcpy(void *dest,const void *src,unsigned int n);

char *strdup(const char *str)
{
	return (char*)memcpy(malloc(strlen(str)+1),str,strlen(str)+1);
}

#ifdef __cplusplus
}
#endif
