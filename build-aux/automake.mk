EXTRA_DIST += \
	build-aux/automake.mk \
    build-aux/build-common.sh \
    build-aux/build-common-version-test.sh \
    build-aux/build-debs.sh \
	build-aux/calculate-pipeline-cksum \
    build-aux/build-rpms.sh \
	build-aux/calculate-schema-cksum \
	build-aux/cccl \
	build-aux/cksum-pipeline-check \
	build-aux/cksum-schema-check \
	build-aux/dist-docs \
	build-aux/dpdkstrip.py \
	build-aux/generate-dhparams-c \
	build-aux/initial-tab-whitelist \
	build-aux/libtool-deps \
	build-aux/sodepends.py \
	build-aux/soexpand.py \
	build-aux/text2c \
	build-aux/xml2nroff

FLAKE8_PYFILES += \
    $(srcdir)/build-aux/xml2nroff \
    build-aux/dpdkstrip.py \
    build-aux/sodepends.py \
    build-aux/soexpand.py
