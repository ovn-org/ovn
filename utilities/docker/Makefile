#export OVN_BRANCH=master
#export OVN_VERSION=2.12
#export DISTRO=debian
#export GITHUB_SRC=https://github.com/ovn-org/ovn.git
#export DOCKER_REPO=ovn-org/ovn

# Example:
#   make build
#   make push

REPO = ${DOCKER_REPO}
tag = ${OVN_VERSION}_${DISTRO}_${OVN_BRANCH}

build: ;docker build -t ${REPO}:${tag} --build-arg DISTRO=${DISTRO} \
--build-arg OVN_BRANCH=${OVN_BRANCH} \
--build-arg GITHUB_SRC=${GITHUB_SRC} -f ${DISTRO}/Dockerfile .

.PHONY: build

push: ;docker push ${REPO}:${tag}
