#/bin/bash

#
# Check if there are any missing file updates
#

make update-map-file > /dev/null

git diff > diff_check

WC=`cat diff_check | wc -l`
if [ $WC != 0 ] ; then
	echo
	echo "Please correct the following files that were changed by"
	echo "./configure (by updating its master file)"
	echo "or 'make update-map-file'."
	echo
	cat diff_check
	exit 1
fi
exit 0
