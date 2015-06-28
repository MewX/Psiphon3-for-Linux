#include <fcntl.h>

int lock_ext = 0;

static struct flock flocksh = { F_RDLCK };
static struct flock flockex = { F_WRLCK };
static struct flock flockun = { F_UNLCK };

int SHlockB(int fd){	return fcntl(fd,F_SETLKW,&flocksh); }
int SHlockNB(int fd){	return fcntl(fd,F_SETLK, &flocksh); }
int EXlockB(int fd){	return fcntl(fd,F_SETLKW,&flockex); }
int EXlockNB(int fd){	return fcntl(fd,F_SETLK, &flockex); }
int UNlock(int fd){	return fcntl(fd,F_SETLK, &flockun); }
