unsigned int alarm(unsigned int seconds);
int Ualarm(int usecs){
	if( 1 <= usecs/1000000 )
		return alarm(usecs/1000000);
	else	return alarm(1);
}
