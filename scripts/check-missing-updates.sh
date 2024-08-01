#/bin/bash

#
# Check if there are any missing file updates
#

make update-map-file > /dev/null

#
# Check for any version revision changes
#
. scripts/fix_version.sh

git diff > diff_check

WC=`cat diff_check | wc -l`
if [ $WC != 0 ] ; then
	echo
	echo "Please correct any header files for the appropriate revision"
	echo "changes. It is possible to do this by running"
	echo "  . scripts/fix_version.sh"
	echo "and then commit the changes to the header files."
	echo
	echo "Or run 'make update-map-file' and commit the changes to"
	echo "libcoap-3.map and libcoap-3.sym."
	echo
	cat diff_check
	exit 1
fi
exit 0
