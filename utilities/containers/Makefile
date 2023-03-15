CONTAINER_CMD ?= podman
IMAGE_NAME ?= "ovn-org/ovn-tests"
CONTAINERS_PATH ?= "."

distros := fedora ubuntu

.PHONY: $(distros)

$(distros):
	$(CONTAINER_CMD) build --no-cache --rm -t $(IMAGE_NAME):$@ \
	-f $@/Dockerfile . --build-arg=CONTAINERS_PATH=$(CONTAINERS_PATH)
