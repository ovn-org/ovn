#export OVN_BRANCH=master
#export OVN_VERSION=2.12
#export KERNEL_VERSION=4.15.0-54-generic
#export DISTRO=debian
#export GITHUB_SRC=https://github.com/ovn-org/ovn.git
#export DOCKER_REPO=ovn-org/ovn

# Example:
#   make build
#   make push

REPO = ${DOCKER_REPO}
tag = ${OVN_VERSION}_${KERNEL_VERSION}

build: ;docker build -t ${REPO}:${tag} --build-arg DISTRO=${DISTRO} \
--build-arg OVN_BRANCH=${OVN_BRANCH} \
--build-arg KERNEL_VERSION=${KERNEL_VERSION} \
--build-arg GITHUB_SRC=${GITHUB_SRC} -f ${DISTRO}/Dockerfile .

.PHONY: build

push: ;docker push ${REPO}:${tag}
