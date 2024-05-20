#/bin/bash

#
# Check if there are any missing file updates
#

make update-map-file > /dev/null

git diff > diff_check

WC=`cat diff_check | wc -l`
if [ $WC != 0 ] ; then
	echo
	echo "Please update the master file (usually .in) for the following files"
	echo "that had the changes reverted by the running of './configure'."
	echo "There is no need to update the original files, just commit the"
	echo "changed .in files."
	echo
	echo "Or run 'make update-map-file' and commit the changes to"
	echo "libcoap-3.map and libcoap-3.sym."
	echo
	cat diff_check
	exit 1
fi
exit 0
