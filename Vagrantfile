# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"
Vagrant.require_version ">=1.7.0"

$bootstrap_ovs_fedora = <<SCRIPT
dnf -y update
dnf -y install autoconf automake openssl-devel libtool \
               python-devel python3-devel \
               python-twisted python-zope-interface \
               desktop-file-utils groff graphviz rpmdevtools nc curl \
               wget python-six pyftpdlib checkpolicy selinux-policy-devel \
               libcap-ng-devel kernel-devel-`uname -r` ethtool python-tftpy \
               lftp
echo "search extra update built-in" >/etc/depmod.d/search_path.conf
SCRIPT

$bootstrap_ovs_debian = <<SCRIPT
aptitude -y update
aptitude -y upgrade
aptitude -y install -R \
                build-essential dpkg-dev lintian devscripts fakeroot \
                debhelper dh-autoreconf uuid-runtime \
                autoconf automake libtool \
                python-all python-twisted-core python-twisted-conch \
                xdg-utils groff graphviz netcat curl \
                wget python-six ethtool \
                libcap-ng-dev libssl-dev python-dev openssl \
                python-pyftpdlib python-flake8 python-tftpy \
                linux-headers-`uname -r` \
                lftp
SCRIPT

$bootstrap_ovs_centos = <<SCRIPT
yum -y update
yum -y install autoconf automake openssl-devel libtool \
               python-twisted-core python-zope-interface \
               desktop-file-utils groff graphviz rpmdevtools nc curl \
               wget python-six pyftpdlib checkpolicy selinux-policy-devel \
               libcap-ng-devel kernel-devel-`uname -r` ethtool net-tools \
               lftp
SCRIPT

$configure_ovs = <<SCRIPT
cd /vagrant/ovs
./boot.sh
[ -f Makefile ] && ./configure && make distclean
mkdir -pv ~/build/ovs
cd ~/build/ovs
/vagrant/ovs/configure --prefix=/usr
SCRIPT

$build_ovs = <<SCRIPT
cd ~/build/ovs
make -j$(($(nproc) + 1)) V=0
make install
SCRIPT

$configure_ovn = <<SCRIPT
cd /vagrant/ovn
./boot.sh
[ -f Makefile ] && \
./configure --prefix=/usr --with-ovs-source=/vagrant/ovs \
  --with-ovs-build=${HOME}/build/ovs && make distclean
mkdir -pv ~/build/ovn
cd ~/build/ovn
/vagrant/ovn/configure --prefix=/usr --with-ovs-source=/vagrant/ovs \
  --with-ovs-build=${HOME}/build/ovs
SCRIPT

$build_ovn = <<SCRIPT
cd ~/build/ovn
make -j$(($(nproc) + 1))
make install
SCRIPT

$test_ovn = <<SCRIPT
cd ~/build/ovn
make check RECHECK=yes
SCRIPT

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.define "debian-8" do |debian|
       debian.vm.box = "debian/jessie64"
       debian.vm.synced_folder ".", "/vagrant", disabled: true
       debian.vm.synced_folder ".", "/vagrant/ovn", type: "rsync"
       debian.vm.synced_folder "../ovs", "/vagrant/ovs", type: "rsync"
       debian.vm.provision "bootstrap_ovs", type: "shell",
                           inline: $bootstrap_ovs_debian
       debian.vm.provision "configure_ovs", type: "shell",
                           inline: $configure_ovs
       debian.vm.provision "build_ovs", type: "shell", inline: $build_ovs
       debian.vm.provision "configure_ovn", type: "shell",
                           inline: $configure_ovn
       debian.vm.provision "build_ovn", type: "shell", inline: $build_ovn
       debian.vm.provision "test_ovn", type: "shell", inline: $test_ovn
  end
  config.vm.define "fedora-29" do |fedora|
       fedora.vm.box = "fedora/29-cloud-base"
       fedora.vm.synced_folder ".", "/vagrant", disabled: true
       fedora.vm.synced_folder ".", "/vagrant/ovn", type: "rsync"
       fedora.vm.synced_folder "../ovs", "/vagrant/ovs", type: "rsync"
       fedora.vm.provision "bootstrap_ovs", type: "shell",
                           inline: $bootstrap_ovs_fedora
       fedora.vm.provision "configure_ovs", type: "shell",
                           inline: $configure_ovs
       fedora.vm.provision "build_ovs", type: "shell", inline: $build_ovs
       fedora.vm.provision "configure_ovn", type: "shell",
                           inline: $configure_ovn
       fedora.vm.provision "build_ovn", type: "shell", inline: $build_ovn
       fedora.vm.provision "test_ovn", type: "shell", inline: $test_ovn
  end
  config.vm.define "centos-7" do |centos|
       centos.vm.box = "centos/7"
       centos.vm.synced_folder ".", "/vagrant", disabled: true
       centos.vm.synced_folder ".", "/vagrant/ovn", type: "rsync"
       centos.vm.synced_folder "../ovs", "/vagrant/ovs", type: "rsync"
       centos.vm.provision "bootstrap_ovs", type: "shell",
                           inline: $bootstrap_ovs_centos
       centos.vm.provision "configure_ovs", type: "shell",
                           inline: $configure_ovs
       centos.vm.provision "build_ovs", type: "shell", inline: $build_ovs
       centos.vm.provision "configure_ovn", type: "shell",
                           inline: $configure_ovn
       centos.vm.provision "build_ovn", type: "shell", inline: $build_ovn
       centos.vm.provision "test_ovn", type: "shell", inline: $test_ovn
  end
end
