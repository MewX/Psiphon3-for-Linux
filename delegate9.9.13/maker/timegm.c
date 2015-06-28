int SUBST_timegm = 1;

int Timegm(struct tm *tm);
int Timelocal(struct tm *tm);

long int timegm(struct tm *tm)
{
	return Timegm(tm);
}
unsigned int timelocal(struct tm *tm)
{
	return Timelocal(tm);
}
