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
build_deps="rpm-build yum-utils yum-builddep automake autoconf openssl-devel \
epel-release python3 gdb libtool git bzip2 perl-core zlib-devel openssl git \
libtool"

yum update -y
yum install @'Development Tools'  ${build_deps} -y

./install_ovn.sh $OVN_BRANCH $GITHUB_SRC

# remove unused packages to make the container light weight.
for i in $(package-cleanup --leaves --all);
    do yum remove -y $i; yum autoremove -y;
done
yum remove ${build_deps} -y
cd ..; rm -rf ovs; rm -rf ovn

# Install basic utils
basic_utils="vim-minimal.x86_64 net-tools.x86_64 uuid.x86_64 iproute.x86_64"
yum install -y ${basic_utils}
