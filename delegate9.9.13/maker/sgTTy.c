#include <stdio.h>
const char *sgTTyType(){
	return "NA";
}
int getTTySize(int fd,int *width,int *height){
	return -1;
}
int setTTySize(int fd,int width,int height){
	return -1;
}
int setTTyMode(int fd,const char *mode){
	return -1;
}
int getTTyStat(int fd,void *sg,int sz){
	return -1;
}
int setTTyStat(int fd,void *sg,int sz){
	return -1;
}
int issetTTyMode(void *sg,const char *mode){
	return -1;
}
int getTTyMode(int fd,const char *mode){
	return -1;
}
int addTTyMode(void *sg,const char *mode){
	return -1;
}
int clrTTyMode(void *sg,const char *mode){
	return -1;
}
void *dumpTTyStat(int fd){
	return 0;
}
int restoreTTyStat(int fd,void *sg){
	return -1;
}
int freeTTyStat(void *sg){
	return -1;
}
