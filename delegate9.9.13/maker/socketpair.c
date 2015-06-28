int SUBST_socketpair = 1;

int SocketPair(int,int,int,int[2]);
int socketpair(int d,int type,int protocol,int sv[2])
{
	return SocketPair(d,type,protocol,sv);
}
