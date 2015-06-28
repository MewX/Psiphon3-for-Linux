#/*////////////////////////////////////////////////////////////////////////
#Copyright (c) 2004 National Institute of Advanced Industrial Science and Technology (AIST)
#
#Permission to use this material for evaluation, copy this material for
#your own use, and distribute the copies via publically accessible on-line
#media, without fee, is hereby granted provided that the above copyright
#notice and this permission notice appear in all copies.
#AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
#MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
#OR IMPLIED WARRANTIES.
#/////////////////////////////////////////////////////////////////////////
#Content-Type:	program/C; charset=US-ASCII
#Program:	Makefile for include
#Author:	Yutaka Sato <ysato@delegate.org>
#Description:
#History:
#	041018	created
#//////////////////////////////////////////////////////////////////////#*/

CFLAGS =	-O
TARGET =	all
target:		$(TARGET)
MKMAKE =	exit 1
libx:		Makefile.go
		$(MAKE) -f Makefile.go $(LIBFILE) MAKEFILE=Makefile.go MKMAKE="$(MKMAKE)" SHELL="$(SHELL)" HDRDIR="$(HDRDIR)" LIBDIR="$(LIBDIR)"

#ifdef MSWIN ######################################################
COPY = copy
#endif #############
#ifdef OS2EMX #####################################################
#endif #############
#ifdef UNIX #######################################################
MKDEF =	-$(SHELL) ./mkdef typedefs.h "$(CC)" $(CFLAGS) $(HDRDIR)
#endif #############
#ifdef UNIX,OS2EMX ################################################
COPY = cp
#endif #############

#---BGN---
#---END---

all:		typedefs.h
typedefs.h:	Makefile.go mkdef typedefs.c
		$(COPY) _typedefs.h typedefs.h
		$(MKDEF)

Makefile.go:	Makefile
		"$(MKMAKE)" -cksum *.h *.c
		"$(MKMAKE)" -mkmake "$(MAKE)" $@ "$(CC)" "$(CFLAGS)" "" "$(LDFLAGS)" "$(RANLIB)" "$(NETLIB)" NETLIB
