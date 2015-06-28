#ifndef _SGTTY_H
#define _SGTTY_H
const char *sgTTyType();
int getTTySize(int fd,int *width,int *height);
int setTTySize(int fd,int width,int height);
int setTTyMode(int fd,const char *mode);
int getTTyStat(int fd,void *sg,int sz);
int setTTyStat(int fd,void *sg,int sz);
int issetTTyMode(void *sg,const char *mode);
int getTTyMode(int fd,const char *mode);
int sendTTySize(FILE *ts,int col,int row);
void *dumpTTyStat(int fd);
int restoreTTyStat(int fd,void *sg);
int freeTTyStat(void *sg);
#endif
