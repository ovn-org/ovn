CONTAINER_CMD ?= podman
DISTRO ?= fedora
IMAGE_NAME ?= "ovn-org/ovn-tests"
CONTAINERS_PATH ?= "."

.PHONY: build

build:
	$(CONTAINER_CMD) build --no-cache --rm -t $(IMAGE_NAME) \
	-f $(DISTRO)/Dockerfile . --build-arg=CONTAINERS_PATH=$(CONTAINERS_PATH)
