#include <sys/file.h>

int lock_ext = 0;

int SHlockB(int fd){	return flock(fd,LOCK_SH); }
int SHlockNB(int fd){	return flock(fd,LOCK_SH|LOCK_NB); }
int EXlockB(int fd){	return flock(fd,LOCK_EX); }
int EXlockNB(int fd){	return flock(fd,LOCK_EX|LOCK_NB); }
int UNlock(int fd){	return flock(fd,LOCK_UN); }
