#!/bin/bash
set -ev

if [ "${TRAVIS_PULL_REQUEST}" != "false" ]; then
  TRAVIS_DIR=$(pwd)
  cp kvasir.yaml.travis kvasir.yaml
  cd $HOME
  git clone https://github.com/web2py/web2py web2py
  ln -s $TRAVIS_BUILD_DIR web2py/applications/kvasir
  cd web2py
  W2P_HOME=$(pwd)
  PYTHONPATH=$W2P_HOME
  ./web2py -S kvasir -M -R applications/kvasir/private/user.py -A -u test -p test
  cd applications/kvasir/modules/skaldship
  nosetests --with-doctest
fi
