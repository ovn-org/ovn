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

KERNEL_VERSION=$1
OVN_BRANCH=$2
GITHUB_SRC=$3

# Install deps
linux="linux-image-$KERNEL_VERSION linux-headers-$KERNEL_VERSION"
build_deps="apt-utils libelf-dev build-essential libssl-dev python3 \
python3-six wget gdb autoconf libtool git automake bzip2 debhelper \
dh-autoreconf openssl"

apt-get update
apt-get install -y ${linux} ${build_deps}

# get ovs source always from master as its needed as dependency
mkdir /build; cd /build
git clone --depth 1 -b master https://github.com/openvswitch/ovs.git
cd ovs;
mkdir _gcc;

# build and install
./boot.sh
cd _gcc
../configure --localstatedir="/var" --sysconfdir="/etc" --prefix="/usr" \
--with-linux=/lib/modules/$KERNEL_VERSION/build --enable-ssl
cd ..; make -C _gcc install; cd ..


# get ovn source
git clone --depth 1 -b $OVN_BRANCH $GITHUB_SRC
cd ovn

# build and install
./boot.sh
./configure --localstatedir="/var" --sysconfdir="/etc" --prefix="/usr" \
--with-linux=/lib/modules/$KERNEL_VERSION/build --enable-ssl \
--with-ovs-source=/build/ovs/ --with-ovs-build=/build/ovs/_gcc
make -j8; make install

# remove deps to make the container light weight.
apt-get remove --purge -y ${build_deps}
apt-get autoremove -y --purge
cd ..; rm -rf ovn; rm -rf ovs
basic_utils="vim kmod net-tools uuid-runtime iproute2"
apt-get install -y ${basic_utils}
