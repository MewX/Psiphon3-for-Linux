/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994 Electrotechnical Laboratry (ETL)

Permission to use, copy, modify, and distribute this material for any
purpose and without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies, and
that the name of ETL not be used in advertising or publicity pertaining
to this material without the specific, prior written permission of an
authorized representative of ETL.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:   program/C; charset=US-ASCII
Program:        SLL.h (Simple LL parser)
Author:         Yutaka Sato <ysato@etl.go.jp>
Description:
History:
        940320  created
//////////////////////////////////////////////////////////////////////#*/

typedef struct _state {
  const	char		*r_name;
  const	char		*r_gate;
	struct _state	*r_dest;
	int		 r_flag;
/*
	int		 r_glen;
  const	char		*r_from;
  const	char		*r_to;
*/
} SLLRule;

#define ISRULE(s)	extern SLLRule s[]
#ifdef _AIX
#define RULE(s)		SLLRule s[] =
#else
#define RULE(s)		SLLRule s[] =
#endif
#define ALT(s)		RULE(s){ {"s",0,0,ISALT},
#define SEQ(s)		RULE(s){ {"s",0,0,ISSEQ},
#define END		0};

static char IMM[] = "";

#define SUCCESS		((SLLRule*)1)
#define NEXT		((SLLRule*)2)
#define FAILURE		((SLLRule*)3)

#define ISSEQ		 1
#define ISALT		 2
#define xOPTIONAL	 4
#define CHARSET		 8
#define PUTVAL		16
#define PUTGATE		32
#define IGNCASE		64

typedef void (*putvFunc)(PCStr(name),PCStr(src),int len,PVStr(out));
void SLL_putval(PCStr(name),PCStr(val),int len,PVStr(out));
int SLLparse(int lev,SLLRule *prp,PCStr(srca),const char **nsrcp,putvFunc putv,PVStr(vala),int size,char **nvalp);
