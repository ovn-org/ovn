#!/bin/sh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

OVN_BRANCH=$1
GITHUB_SRC=$2

# get ovs source always from master as its needed as dependency
mkdir /build; cd /build
git clone --depth 1 -b master https://github.com/openvswitch/ovs.git
cd ovs;
mkdir _gcc;

# build and install
./boot.sh
cd _gcc
../configure --localstatedir="/var" --sysconfdir="/etc" --prefix="/usr" \
--enable-ssl
cd ..; make -C _gcc install; cd ..


# get ovn source
git clone --depth 1 -b $OVN_BRANCH $GITHUB_SRC
cd ovn

# build and install
./boot.sh
./configure --localstatedir="/var" --sysconfdir="/etc" --prefix="/usr" \
--enable-ssl --with-ovs-source=/build/ovs/ --with-ovs-build=/build/ovs/_gcc
make -j8; make install
