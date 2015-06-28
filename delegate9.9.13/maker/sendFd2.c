#include "ystring.h"
#include "vsocket.h"
#include "delegate.h"

const char *ver_sendFd(){ return "sendFd2"; };

int sendFd(int sockfd,int fd,int pid){
	struct msghdr msg;
	struct iovec vec;
	char *str = "x";
	int rcode;

	msg.msg_name = 0;
	msg.msg_namelen = 0;

	vec.iov_base = str;
	vec.iov_len = 1;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_accrights = (caddr_t)&fd;
	msg.msg_accrightslen = sizeof(fd);
	rcode = sendmsg(sockfd,&msg,0);
	return rcode;
}

int recvFd(int sockfd){
	struct msghdr msg;
	struct iovec iov;
	char buf[1];
	int rcode;
	int fd;

	iov.iov_base = buf;
	iov.iov_len = 1;

	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_accrights = (caddr_t)&fd;
	msg.msg_accrightslen = sizeof(int);
	rcode = recvmsg(sockfd,&msg,0);
	if( rcode != 1 ){
		return -1;
	}
	return fd;
}
