#!/bin/sh

SUBINS="dgpam dgbind dgchroot dgcpnod"
sudo sh -c "chown root $SUBINS; chmod 6550 $SUBINS"
if [ $? != 0 ]; then
  su root -c "chown root $SUBINS; chmod 6550 $SUBINS"
fi
if [ $? != 0 ]; then
  su root -c "chown root $SUBINS; chmod 6550 $SUBINS"
fi
ls -l $SUBINS
