#!/bin/bash
set -ev

if [ "${TRAVIS_PULL_REQUEST}" -ne "false" ]; then
  TRAVIS_DIR=$(pwd)
  cp kvasir.yaml.travis kvasir.yaml
  cd ..
  git clone https://github.com/web2py/web2py web2py
  ln -s $TRAVIS_DIR web2py/applications/kvasir
  cd web2py
  ./web2py -S kvasir -M -R applications/kvasir/private/user.py -A -u test -p test
fi
