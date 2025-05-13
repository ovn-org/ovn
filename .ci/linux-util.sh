#!/bin/bash

function free_up_disk_space_ubuntu()
{
    local pkgs='azure-cli aspnetcore-* dotnet-* ghc-* firefox*
                google-chrome-stable google-cloud-cli libmono-* llvm-*
                microsoft-edge-stable mono-* msbuild mysql-server-core-*
                php-* php7* powershell* temurin-* zulu-*'

    # Use apt patterns to only select real packages that match the names
    # in the list above.
    local pkgs=$(echo $pkgs | sed 's/[^ ]* */~n&/g')

    sudo apt update && sudo apt-get --auto-remove -y purge $pkgs

    local paths='/usr/local/lib/android/ /usr/share/dotnet/ /opt/ghc/
                 /usr/local/share/boost/'
    sudo rm -rf $paths
}

function set_containers_apparmor_profile()
{
    local profile=$1

    sed -i "s/^#apparmor_profile = \".*\"$/apparmor_profile = \"$profile\"/" \
        /usr/share/containers/containers.conf
}

function fix_etc_hosts()
{
    cp /etc/hosts ./hosts.bak
    sed -E -n \
      '/^[[:space:]]*(#.*|[0-9a-fA-F:.]+([[:space:]]+[a-zA-Z0-9.-]+)+|)$/p' \
      ./hosts.bak | sudo tee /etc/hosts

    diff -u ./hosts.bak /etc/hosts || true
}
