#!/bin/bash

if [ "$(which rpmbuild)" == "" ];
then
  echo "To build an rpm the tool rpmbuild needs to be installed first"
  exit -1
fi 

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ -z $1 ];
then
  echo "Usage $0 \"release\""
  exit -1
fi

cd ${DIR}/..

rm -f google-authenticator-*.tar.gz
./bootstrap.sh && ./configure && make dist &&
(
   mkdir -p "${DIR}/_rpmbuild/SOURCES"
   cp google-authenticator-*.tar.gz "${DIR}/_rpmbuild/SOURCES/"
   rpmbuild -ba contrib/rpm.spec --define "_topdir ${DIR}/_rpmbuild" --define "_release $1"

   echo "=============="
   echo "Available RPMs"
   find "${DIR}/_rpmbuild/" -type f -name '*.rpm' | fgrep -- "-$1."
) || echo "Something went wrong"
