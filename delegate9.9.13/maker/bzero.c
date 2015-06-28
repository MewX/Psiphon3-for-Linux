int SUBST_bzero = 1;
void bzero(void *b,unsigned int length)
{	int i;

	for( i = 0; i < length; i++ )
		((char*)b)[i] = 0;
}
