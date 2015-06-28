#ifndef _YSIGNAL_H
#define _YSIGNAL_H
/* 9.9.4 MTSS */

typedef struct {
	int	s_set;
	int	s_mask;
} SSigMask;

extern int cnt_SSigMask;

int set_SSigMask(SSigMask *sMask,int force);
#define setSSigMask(sMask) set_SSigMask(&sMask,0)
#define setSSigMaskX(sMask,force) set_SSigMask(&sMask,force)

int reset_SSigMask(SSigMask *sMask);
#define resetSSigMask(sMask) reset_SSigMask(&sMask)

#endif
