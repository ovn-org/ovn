# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"
Vagrant.require_version ">=1.7.0"

$bootstrap_ovs_fedora = <<SCRIPT
#dnf -y update ||:  ; # save your time. "vagrant box update" is your friend

# loop to deal with flaky dnf
cnt=0
until [ $cnt -ge 3 ] ; do
   dnf -y -vvv install autoconf automake openssl-devel libtool \
               python3-devel \
               python3-twisted python3-zope-interface python3-six \
               desktop-file-utils groff graphviz rpmdevtools nc curl \
               wget pyftpdlib checkpolicy selinux-policy-devel \
               libcap-ng-devel kernel-devel-`uname -r` ethtool python-tftpy \
               lftp
   if [ "$?" -eq 0 ]; then break ; fi
   (( cnt++ ))
   >&2 echo "Sad panda: dnf failed ${cnt} times."
done

echo "search extra update built-in" >/etc/depmod.d/search_path.conf
SCRIPT

$bootstrap_ovs_debian = <<SCRIPT
update-alternatives --install /usr/bin/python python /usr/bin/python3 1
apt-get update
#apt-get -y upgrade  ; # save your time. "vagrant box update" is your friend
apt-get -y install build-essential fakeroot graphviz autoconf automake bzip2 \
                   debhelper dh-autoreconf libssl-dev libtool openssl procps \
                   python-all python-qt4 python-twisted-conch python-zopeinterface \
                   python-six libcap-ng-dev libunbound-dev
SCRIPT

$bootstrap_ovs_centos7 = <<SCRIPT
yum -y update  ; # save your time. "vagrant box update" is your friend
yum -y install autoconf automake openssl-devel libtool \
               python3-devel python3-twisted-core python3-zope-interface \
               desktop-file-utils groff graphviz rpmdevtools nc curl \
               wget python-six pyftpdlib checkpolicy selinux-policy-devel \
               libcap-ng-devel kernel-devel-`uname -r` ethtool net-tools \
               lftp
pip3 install six
SCRIPT

$bootstrap_ovs_centos = <<SCRIPT
dnf -y update ||:  ; # save your time. "vagrant box update" is your friend
dnf -y install autoconf automake openssl-devel libtool \
               python3-devel \
               python3-twisted python3-zope-interface python3-six \
               desktop-file-utils graphviz rpmdevtools nc curl \
               wget checkpolicy selinux-policy-devel \
               libcap-ng-devel kernel-devel-`uname -r` ethtool \
               lftp
echo "search extra update built-in" >/etc/depmod.d/search_path.conf
pip3 install pyftpdlib tftpy
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
exit_rc_when_failed=0 ; # make this non-zero to halt provision
make check RECHECK=yes || {
   >&2 echo "ERROR: CHECK FAILED $?"
   exit ${exit_rc_when_failed}
}
SCRIPT

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.define "debian-10" do |debian|
       debian.vm.hostname = "debian-10"
       debian.vm.box = "debian/buster64"
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
  config.vm.define "fedora-31" do |fedora|
       fedora.vm.hostname = "fedora-31"
       fedora.vm.box = "fedora/31-cloud-base"
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
  config.vm.define "centos-7", autostart: false do |centos7|
       centos7.vm.hostname = "centos-7"
       centos7.vm.box = "centos/7"
       centos7.vm.synced_folder ".", "/vagrant", disabled: true
       centos7.vm.synced_folder ".", "/vagrant/ovn", type: "rsync"
       centos7.vm.synced_folder "../ovs", "/vagrant/ovs", type: "rsync"
       centos7.vm.provision "bootstrap_ovs", type: "shell",
                           inline: $bootstrap_ovs_centos7
       centos7.vm.provision "configure_ovs", type: "shell",
                           inline: $configure_ovs
       centos7.vm.provision "build_ovs", type: "shell", inline: $build_ovs
       centos7.vm.provision "configure_ovn", type: "shell",
                           inline: $configure_ovn
       centos7.vm.provision "build_ovn", type: "shell", inline: $build_ovn
       centos7.vm.provision "test_ovn", type: "shell", inline: $test_ovn
  end
  config.vm.define "centos-8" do |centos|
       centos.vm.hostname = "centos-8"
       centos.vm.box = "generic/centos8"
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
