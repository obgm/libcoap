#! /bin/bash

#
# This is to make sure the various HAVE_ definitions are synced across
# configure.ac, CMakeLists.txt and cmake_coap_config.h.in.
# It also checks the definitions are in alphabetical order.
#
# Copyright (C) 2026 Jon Shallow <supjps-libcoap@jpshallow.com>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# This file is part of the CoAP C library libcoap. Please see README
# and COPYING for terms of use.
#

if ! test -f configure.ac; then
    >&2 echo "$(basename $0): script must be called from the package's top directory"
    exit 1
fi

BASE=/tmp/file_
err=0
#
# Check system Headers
#
grep HAVE_ CMakeLists.txt | grep check_ | awk '{ print $2 }' | sed "s/)//g" | egrep "_H$" | LC_ALL=C sort > ${BASE}CM_h_s

grep HAVE_ CMakeLists.txt | grep check_ | tr '(' ' ' | tr '.' '_' | tr '/' '_' | awk '{ print toupper ($2) }' | sed "s/^/HAVE_/g" | egrep "_H$" > ${BASE}CM_h
grep HAVE_ CMakeLists.txt | grep check_ | awk '{ print $2 }' | sed "s/)//g" | egrep "_H$" > ${BASE}CM_h2
grep HAVE_ cmake_coap_config.h.in | awk '{ print $2 }' | egrep "_H" > ${BASE}cmake_h
grep HAVE_ cmake_coap_config.h.in | awk '{ print $3 }' | egrep "_H" | sed "s/@//g" > ${BASE}cmake_h2
grep -A 7 AC_CHECK_HEADERS configure.ac | tr './[]()\\' '__     ' | tr ' ' '\n' | egrep -v "AC_CHECK_HEADERS" | sed "/^\s*$/d" | awk '{ print toupper($0) }' | sed "s/^/HAVE_/g" > ${BASE}conf_h

diff -Nau ${BASE}CM_h_s ${BASE}CM_h
if [ $? != 0 ] ; then err=1 ; fi
diff -Nau ${BASE}CM_h_s ${BASE}CM_h2
if [ $? != 0 ] ; then err=1 ; fi
diff -Nau ${BASE}CM_h_s ${BASE}cmake_h
if [ $? != 0 ] ; then err=1 ; fi
diff -Nau ${BASE}CM_h_s ${BASE}cmake_h2
if [ $? != 0 ] ; then err=1 ; fi
diff -Nau ${BASE}CM_h_s ${BASE}conf_h
if [ $? != 0 ] ; then err=1 ; fi

#
# Check struct
#

grep HAVE_STRUCT CMakeLists.txt | tr '(' ' ' | tr ')' ' ' | awk '{ print $2 }' | grep HAVE_STRUCT | uniq | LC_ALL=C sort > ${BASE}CM_s_sa
grep HAVE_STRUCT CMakeLists.txt | tr '(' ' ' | tr ')' ' ' | awk '{ print $1 }' | grep HAVE_STRUCT | uniq | LC_ALL=C sort >> ${BASE}CM_s_sa
cat ${BASE}CM_s_sa | uniq > ${BASE}CM_s_s
rm -f ${BASE}CM_s_sa

grep HAVE_STRUCT cmake_coap_config.h.in | awk '{ print $2 }' > ${BASE}cmake_s
grep HAVE_STRUCT cmake_coap_config.h.in | awk '{ print $3 }' | sed "s/@//g" > ${BASE}cmake_s2
grep AC_CHECK_TYPES configure.ac | tr ' ' '_' | tr '[]()' '    ' | awk '{ print toupper($2) }' | sed "s/^/HAVE_/g" > ${BASE}conf_s

diff -Nau ${BASE}CM_s_s ${BASE}cmake_s
if [ $? != 0 ] ; then err=1 ; fi
diff -Nau ${BASE}CM_s_s ${BASE}cmake_s2
if [ $? != 0 ] ; then err=1 ; fi
diff -Nau ${BASE}CM_s_s ${BASE}conf_s
if [ $? != 0 ] ; then err=1 ; fi

#
# Check functions
#
grep HAVE_ CMakeLists.txt | grep check_ | awk '{ print $2 }' | sed "s/)//g" | egrep -v "_H$" | LC_ALL=C sort > ${BASE}CM_f_s

grep HAVE_ CMakeLists.txt | grep check_ | tr '(' ' ' | tr '.' '_' | tr '/' '_' | awk '{ print toupper ($2) }' | sed "s/^/HAVE_/g" | egrep -v "_H$" > ${BASE}CM_f
grep HAVE_ CMakeLists.txt | grep check_ | awk '{ print $2 }' | sed "s/)//g" | egrep -v "_H$" > ${BASE}CM_f2
grep HAVE_ cmake_coap_config.h.in | awk '{ print $2 }' | egrep -v "_H|HAVE_STRUCT_" > ${BASE}cmake_f
grep HAVE_ cmake_coap_config.h.in | awk '{ print $3 }' | egrep -v "_H|HAVE_STRUCT_" | sed "s/@//g" > ${BASE}cmake_f2
grep -A 2 AC_CHECK_FUNCS configure.ac | tr './[]()\\' '__     ' | tr ' ' '\n' | egrep -v "AC_CHECK_FUNCS" | sed "/^\s*$/d" | awk '{ print toupper($0) }' | sed "s/^/HAVE_/g" > ${BASE}conf_f

diff -Nau ${BASE}CM_f_s ${BASE}CM_f
if [ $? != 0 ] ; then err=1 ; fi
diff -Nau ${BASE}CM_f_s ${BASE}CM_f2
if [ $? != 0 ] ; then err=1 ; fi
diff -Nau ${BASE}CM_f_s ${BASE}cmake_f
if [ $? != 0 ] ; then err=1 ; fi
diff -Nau ${BASE}CM_f_s ${BASE}cmake_f2
if [ $? != 0 ] ; then err=1 ; fi
diff -Nau ${BASE}CM_f_s ${BASE}conf_f
if [ $? != 0 ] ; then err=1 ; fi

#
# Check source header usage is defined
#
if [ -d .git ] ; then
	grep HAVE_ `git ls-files | egrep "\.c$|\.h$"` | grep "#if" | sed "s/defined(//g" | tr '()&|!' '     ' | tr ' ' '\n' | egrep -v "^include" | grep "HAVE_" | egrep "_H$" | LC_ALL=C sort -u > ${BASE}source

	WC=`diff -Nau ${BASE}source ${BASE}CM_h_s | egrep "^-H" | wc -l`
	if [ $WC != 0 ] ; then
		echo "Missing header checks"
		diff -Nau ${BASE}source ${BASE}CM_h_s | egrep "^-|^\+\+"
       	 err=1
	fi
fi

if [ $err != 0 ] ; then
	echo
	echo "Please correct the differences between headers, structures and functions"
	echo "as indicated by the following file naming"
	echo "Prefix"
	echo " file_CM    CMakeLists.txt"
	echo " file_cmake cmake_coap_config.h.in"
	echo " file_conf  configure.ac"
	echo " source     Checking all the .c and .h files under git control"
	echo "Suffix"
	echo " _h         header files (first definition)"
	echo " _h2        header files (matching second definition)"
	echo " _h_s       header files (sorted - used as order check)"
	echo " _f         functions (first definition)"
	echo " _f         functions ((matching second definition)"
	echo " _f_s       functions (sorted - used as order check)"
	echo " _s         structs"
	echo " _s_s       structs (sorted - used as order check)"
	echo
	echo "The file definition may be in lowercase, translated to uppercase with"
	echo "/ and . converted to _."
	echo
	echo "Note: sorting is done by 'LC_ALL=C sort' for consistency."
	exit 1
fi
exit 0
