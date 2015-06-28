#include "ystring.h"
#include "vsocket.h"
#include "delegate.h"

const char *ver_sendFd(){ return "sendFd1"; };

int sendFd(int sockfd,int fd,int pid){
	struct msghdr msg;
	char ccmsg[CMSG_SPACE(sizeof(fd))];
	struct cmsghdr *cmsg;
	struct iovec vec;  /* stupidity: must send/receive at least one byte */
	char *str = "x";
	int rcode;

	msg.msg_name = 0;
	msg.msg_namelen = 0;

	vec.iov_base = str;
	vec.iov_len = 1;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;

	msg.msg_control = ccmsg;
	msg.msg_controllen = sizeof(ccmsg);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	*(int*)CMSG_DATA(cmsg) = fd;

	msg.msg_controllen = cmsg->cmsg_len;
	msg.msg_flags = 0;
	rcode = sendmsg(sockfd,&msg,0);
	return rcode;
}

int recvFd(int sockfd){
	struct msghdr msg;
	struct iovec iov;
	char buf[1];
	int rcode;
	int fd;
	int connfd = -1;
	char ccmsg[CMSG_SPACE(sizeof(connfd))];
	struct cmsghdr *cmsg;

	iov.iov_base = buf;
	iov.iov_len = 1;

	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = ccmsg;
	msg.msg_controllen = sizeof(ccmsg); /* ? seems to work... */

	rcode = recvmsg(sockfd,&msg,0);
	if( rcode != 1 ){
		return -1;
	}
	cmsg = CMSG_FIRSTHDR(&msg);
	if( cmsg->cmsg_type != SCM_RIGHTS ){
		fprintf(stderr, "got control message of unknown type %d\n",
			cmsg->cmsg_type);
		return -1;
	}
	fd = *(int*)CMSG_DATA(cmsg);
	return fd;
}
