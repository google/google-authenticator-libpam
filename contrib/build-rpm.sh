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

rm google-authenticator-*.tar.gz
./bootstrap.sh && ./configure && make dist &&
(
   mkdir -p _rpmbuild/SOURCES
   cp google-authenticator-*.tar.gz _rpmbuild/SOURCES/ 
   rpmbuild -ba contrib/rpm.spec --define '_topdir _rpmbuild' --define "_release $1"
   find _rpmbuild -type f -name '*.rpm'
) || echo "Something went wrong"
