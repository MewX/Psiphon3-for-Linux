#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "ystring.h"
#include "ysocket.h"
#include "vsignal.h"
#include "fpoll.h"
#include "proc.h"
#include "dglib.h"

void callDelegate1(int clsock,PCStr(msg),PCStr(telehost),int teleport);
void addBeforeExit(PCStr(what),vFUNCP func,void *arg);
int Write(int fd,PCStr(buf),int len);
int connectToMyself(PCStr(what));
void shiobar(PCStr(script));

int QZencode(int ctx,PCStr(prefix),PVStr(buf),PCStr(ibuf),int len);
int QZdecode(int ctx,PVStr(obuf),PCStr(buf),int len);
