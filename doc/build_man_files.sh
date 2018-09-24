#!/bin/sh

#
# general initialization cleanup
#
rm -f DoxygenLayout.xml
rm -rf man_tmp
mkdir -p man_tmp
rm -rf man_html
mkdir -p man_html

#
# Prefix the start of the 2 files
#
echo '    <tab type="usergroup" visible="yes" url="@ref manpage" title="Manual Pages" intro="">' > insert_file
echo '/** @page manpage Manual Pages' > man_tmp/manpage.dox
echo '  Here is a list of libcoap API manual pages, some of which have code examples:' >> man_tmp/manpage.dox
echo '   <table class="directory">' >> man_tmp/manpage.dox

FILES=`( cd ../man ; ls coap.txt.in ; ls coap_*.txt.in ; ls coap-*.txt.in )`
ID=0
ROW_EVEN=" class=\"even\""

for FILE in $FILES ; do
    BASE=`echo $FILE | cut -d. -f 1`
    MANUAL=`cat ../man/$FILE | egrep -B 1 "^====" | head -1`
    SUMMARY=`cat ../man/$FILE | egrep -B 2 "^SYNOPSIS" | sed 's/coap-//g' | cut -d\- -f2 | cut -c2- | head -1`

    #
    # Build the manual insert page
    #
    echo "/// @page man_$BASE $MANUAL" > man_tmp/$MANUAL.dox
    echo "/// @htmlinclude $BASE.html $MANUAL" >> man_tmp/$MANUAL.dox

    #
    # Update insert_file
    #
    echo "      <tab type=\"user\" visible=\"yes\" url=\"@ref man_$BASE\" title=\"$MANUAL - $SUMMARY\" intro=\"\"/>" >> insert_file

    #
    # Update the summary man page
    #
    echo "   <tr id=\"row_${ID}_\"$ROW_EVEN>" >> man_tmp/manpage.dox
    echo "   <td class=\"entry\" align=\"left\"> @ref man_$BASE </td><td class=\"desc\" align=\"left\">$MANUAL - $SUMMARY</td>" >> man_tmp/manpage.dox
    echo "   </tr>" >> man_tmp/manpage.dox
    ID=`expr $ID + 1`
    if [ -z $ROW_EVEN ] ; then
        ROW_EVEN=" class=\"even\""
    else
        ROW_EVEN=
    fi
done

#
# Close off the man page file
#
echo '   </table>' >> man_tmp/manpage.dox
echo ' */' >> man_tmp/manpage.dox

#
# Close off the insert_file
#
echo '    </tab>' >> insert_file
echo '    <tab type="user" visible="yes" url="@ref deprecated" title="Deprecated Items" intro=""/>' >> insert_file

#
# Create and Update the DoxygenLayout.xml file
#
doxygen -l
sed -i 's/<tab type="pages" visible="yes" /<tab type="pages" visible="no" /g' DoxygenLayout.xml
sed -i '/<tab type="examples" visible=.*/r insert_file' DoxygenLayout.xml
rm insert_file

#
# Fix up man html files, fixing links and UC Name and Synopsis
#
for FILE in $FILES ; do
    BASE=`echo $FILE | cut -d. -f 1`
    cat ../man/$BASE.html | sed 's^<h2>Name</h2>^<h2>NAME</h2>^g' | sed 's^<h2>Synopsis</h2>^<h2>SYNOPSIS</h2>^g' > man_html/$BASE.html

    for ENTRY in $FILES ; do
        EBASE=`echo $ENTRY | cut -d. -f 1`
        MANUAL=`cat ../man/$ENTRY | egrep -B 1 "^====" | head -1`
        SECTION=`echo $MANUAL | cut -d\( -f2 | cut -d\) -f1`

        sed -i "s^<span class=\"strong\"><strong>$EBASE</strong></span>($SECTION)^<a href=\"man_$EBASE.html\" target=\"_self\"><span class=\"strong\"><strong>$EBASE</strong></span>($SECTION)</a>^g" man_html/$BASE.html
    done
done
