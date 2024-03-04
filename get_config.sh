#/bin/bash

#
# This is a helper script to get what the current build configuration is
#

TAGS=0
if [ -f config.log ] ; then
  echo "Last ./configure build"
  echo ""
  cat config.log | grep -E "      libcoap|      host s" | cut -d\  -f7-
  cat config.log | grep -E "result:   " | cut -d\  -f3- | cut -d\  -f7-
  echo ""
  TAGS=1
fi
for f in `find . -name CMakeCache.txt -print` ; do
  DIR=`dirname $f`
  echo "Last cmake build in $DIR"
  echo ""
  (cd $DIR ; cmake -LH . | cut -d\  -f2- | grep -E "\.\." | grep -E "^[A-Z][A-Z]")
  echo ""
  TAGS=1
done

if [ "$TAGS" = 0 ] ; then
  echo "Current git source"
  echo ""
  git describe --tags --dirty --always
  echo ""
fi
