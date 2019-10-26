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

# Install deps
build_deps="apt-utils libelf-dev build-essential libssl-dev python3 \
python3-six wget gdb autoconf libtool git automake bzip2 debhelper \
dh-autoreconf openssl"

apt-get update
apt-get install -y ${build_deps}

./install_ovn.sh $OVN_BRANCH $GITHUB_SRC

# remove deps to make the container light weight.
apt-get remove --purge -y ${build_deps}
apt-get autoremove -y --purge
cd ..; rm -rf ovn; rm -rf ovs
basic_utils="vim kmod net-tools uuid-runtime iproute2"
apt-get install -y ${basic_utils}
