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

set -e

OVN_BRANCH=$1
GITHUB_SRC=$2

# Get ovn source.
git clone --depth 1 -b $OVN_BRANCH $GITHUB_SRC
cd ovn

# Get OVS submodule, build and install OVS.
git submodule update --init
cd ovs
./boot.sh
./configure --localstatedir="/var" --sysconfdir="/etc" --prefix="/usr" \
--enable-ssl
make -j8 install
cd ..

# Build and install OVN.
./boot.sh
./configure --localstatedir="/var" --sysconfdir="/etc" --prefix="/usr" \
--enable-ssl
make -j8 install
