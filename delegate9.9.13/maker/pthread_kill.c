#include "ystring.h"
int (*ThreadKill)(int,int) = 0;
int (*ThreadDestroy)(int) = 0;
int (*ThreadSigmask)(const char *show,SigMaskInt nmaski,SigMaskInt *omaski) = 0;
