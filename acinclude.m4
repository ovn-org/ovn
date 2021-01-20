# -*- autoconf -*-

# Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Nicira, Inc.
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

dnl OVS_ENABLE_WERROR
AC_DEFUN([OVS_ENABLE_WERROR],
  [AC_ARG_ENABLE(
     [Werror],
     [AC_HELP_STRING([--enable-Werror], [Add -Werror to CFLAGS])],
     [], [enable_Werror=no])
   AC_CONFIG_COMMANDS_PRE(
     [if test "X$enable_Werror" = Xyes; then
        OVS_CFLAGS="$OVS_CFLAGS -Werror"
      fi])

   # Unless --enable-Werror is specified, report but do not fail the build
   # for errors reported by flake8.
   if test "X$enable_Werror" = Xyes; then
     FLAKE8_WERROR=
   else
     FLAKE8_WERROR=-
   fi
   AC_SUBST([FLAKE8_WERROR])

   # If --enable-Werror is specified, fail the build on sparse warnings.
   if test "X$enable_Werror" = Xyes; then
     SPARSE_WERROR=-Wsparse-error
   else
     SPARSE_WERROR=
   fi
   AC_SUBST([SPARSE_WERROR])])

dnl Checks for net/if_dl.h.
dnl
dnl (We use this as a proxy for checking whether we're building on FreeBSD
dnl or NetBSD.)
AC_DEFUN([OVS_CHECK_IF_DL],
  [AC_CHECK_HEADER([net/if_dl.h],
                   [HAVE_IF_DL=yes],
                   [HAVE_IF_DL=no])
   AM_CONDITIONAL([HAVE_IF_DL], [test "$HAVE_IF_DL" = yes])
   if test "$HAVE_IF_DL" = yes; then
      AC_DEFINE([HAVE_IF_DL], [1],
                [Define to 1 if net/if_dl.h is available.])

      # On these platforms we use libpcap to access network devices.
      AC_SEARCH_LIBS([pcap_open_live], [pcap])
   fi])

dnl Checks for buggy strtok_r.
dnl
dnl Some versions of glibc 2.7 has a bug in strtok_r when compiling
dnl with optimization that can cause segfaults:
dnl
dnl http://sources.redhat.com/bugzilla/show_bug.cgi?id=5614.
AC_DEFUN([OVS_CHECK_STRTOK_R],
  [AC_CACHE_CHECK(
     [whether strtok_r macro segfaults on some inputs],
     [ovs_cv_strtok_r_bug],
     [AC_RUN_IFELSE(
        [AC_LANG_PROGRAM([#include <stdio.h>
                          #include <string.h>
                         ],
                         [[#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 8
                           /* Assume bug is present, because relatively minor
                              changes in compiler settings (e.g. optimization
                              level) can make it crop up. */
                           return 1;
                           #else
                           char string[] = ":::";
                           char *save_ptr = (char *) 0xc0ffee;
                           char *token1, *token2;
                           token1 = strtok_r(string, ":", &save_ptr);
                           token2 = strtok_r(NULL, ":", &save_ptr);
                           freopen ("/dev/null", "w", stdout);
                           printf ("%s %s\n", token1, token2);
                           return 0;
                           #endif
                          ]])],
        [ovs_cv_strtok_r_bug=no],
        [ovs_cv_strtok_r_bug=yes],
        [ovs_cv_strtok_r_bug=yes])])
   if test $ovs_cv_strtok_r_bug = yes; then
     AC_DEFINE([HAVE_STRTOK_R_BUG], [1],
               [Define if strtok_r macro segfaults on some inputs])
   fi
])

dnl ----------------------------------------------------------------------
dnl These macros are from GNU PSPP, with the following original license:
dnl Copyright (C) 2005, 2006, 2007 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([_OVS_CHECK_CC_OPTION], [dnl
  m4_define([ovs_cv_name], [ovs_cv_[]m4_translit([$1], [-= ], [__])])dnl
  AC_CACHE_CHECK([whether $CC accepts $1], [ovs_cv_name], 
    [ovs_save_CFLAGS="$CFLAGS"
     dnl Include -Werror in the compiler options, because without -Werror
     dnl clang's GCC-compatible compiler driver does not return a failure
     dnl exit status even though it complains about options it does not
     dnl understand.
     dnl
     dnl Also, check stderr as gcc exits with status 0 for options
     dnl rejected at getopt level.
     dnl    % touch /tmp/a.c
     dnl    % gcc -g -c -Werror -Qunused-arguments /tmp/a.c; echo $?
     dnl    gcc: unrecognized option '-Qunused-arguments'
     dnl    0
     dnl    %
     dnl
     dnl In addition, GCC does not complain about a -Wno-<foo> option that
     dnl it does not understand, unless it has another error to report, so
     dnl instead of testing for -Wno-<foo>, test for the positive version.
     CFLAGS="$CFLAGS $WERROR m4_bpatsubst([$1], [-Wno-], [-W])"
     AC_COMPILE_IFELSE(
       [AC_LANG_SOURCE([int x;])],
       [if test -s conftest.err && grep "unrecognized option" conftest.err
        then
          ovs_cv_name[]=no
        else
          ovs_cv_name[]=yes
        fi],
       [ovs_cv_name[]=no])
     CFLAGS="$ovs_save_CFLAGS"])
  if test $ovs_cv_name = yes; then
    m4_if([$2], [], [:], [$2])
  else
    m4_if([$3], [], [:], [$3])
  fi
])

dnl OVS_CHECK_WERROR
dnl
dnl Check whether the C compiler accepts -Werror.
dnl Sets $WERROR to "-Werror", if so, and otherwise to the empty string.
AC_DEFUN([OVS_CHECK_WERROR],
  [WERROR=
   _OVS_CHECK_CC_OPTION([-Werror], [WERROR=-Werror])])

dnl OVS_CHECK_CC_OPTION([OPTION], [ACTION-IF-ACCEPTED], [ACTION-IF-REJECTED])
dnl Check whether the given C compiler OPTION is accepted.
dnl If so, execute ACTION-IF-ACCEPTED, otherwise ACTION-IF-REJECTED.
AC_DEFUN([OVS_CHECK_CC_OPTION],
  [AC_REQUIRE([OVS_CHECK_WERROR])
   _OVS_CHECK_CC_OPTION([$1], [$2], [$3])])

dnl OVS_ENABLE_OPTION([OPTION])
dnl Check whether the given C compiler OPTION is accepted.
dnl If so, add it to WARNING_FLAGS.
dnl Example: OVS_ENABLE_OPTION([-Wdeclaration-after-statement])
AC_DEFUN([OVS_ENABLE_OPTION], 
  [OVS_CHECK_CC_OPTION([$1], [WARNING_FLAGS="$WARNING_FLAGS $1"])
   AC_SUBST([WARNING_FLAGS])])

dnl OVS_CONDITIONAL_CC_OPTION([OPTION], [CONDITIONAL])
dnl Check whether the given C compiler OPTION is accepted.
dnl If so, enable the given Automake CONDITIONAL.

dnl Example: OVS_CONDITIONAL_CC_OPTION([-Wno-unused], [HAVE_WNO_UNUSED])
AC_DEFUN([OVS_CONDITIONAL_CC_OPTION],
  [OVS_CHECK_CC_OPTION(
    [$1], [ovs_have_cc_option=yes], [ovs_have_cc_option=no])
   AM_CONDITIONAL([$2], [test $ovs_have_cc_option = yes])])
dnl ----------------------------------------------------------------------

dnl Check for too-old XenServer.
AC_DEFUN([OVS_CHECK_XENSERVER_VERSION],
  [AC_CACHE_CHECK([XenServer release], [ovs_cv_xsversion],
    [if test -e /etc/redhat-release; then
       ovs_cv_xsversion=`sed -n 's/^XenServer DDK release \([[^-]]*\)-.*/\1/p' /etc/redhat-release`
     fi
     if test -z "$ovs_cv_xsversion"; then
       ovs_cv_xsversion=none
     fi])
  case $ovs_cv_xsversion in
    none)
      ;;

    [[1-9]][[0-9]]* |                    dnl XenServer 10 or later
    [[6-9]]* |                           dnl XenServer 6 or later
    5.[[7-9]]* |                         dnl XenServer 5.7 or later
    5.6.[[1-9]][[0-9]][[0-9]][[0-9]]* |  dnl XenServer 5.6.1000 or later
    5.6.[[2-9]][[0-9]][[0-9]]* |         dnl XenServer 5.6.200 or later
    5.6.1[[0-9]][[0-9]])                 dnl Xenserver 5.6.100 or later
      ;;

    *)
      AC_MSG_ERROR([This appears to be XenServer $ovs_cv_xsversion, but only XenServer 5.6.100 or later is supported.  (If you are really using a supported version of XenServer, you may override this error message by specifying 'ovs_cv_xsversion=5.6.100' on the "configure" command line.)])
      ;;
  esac])

dnl OVS_CHECK_SPARSE_TARGET
dnl
dnl The "cgcc" script from "sparse" isn't very good at detecting the
dnl target for which the code is being built.  This helps it out.
AC_DEFUN([OVS_CHECK_SPARSE_TARGET],
  [AC_CACHE_CHECK(
    [target hint for cgcc],
    [ac_cv_sparse_target],
    [AS_CASE([`$CC -dumpmachine 2>/dev/null`],
       [i?86-* | athlon-*], [ac_cv_sparse_target=x86],
       [x86_64-*], [ac_cv_sparse_target=x86_64],
       [ac_cv_sparse_target=other])])
   AS_CASE([$ac_cv_sparse_target],
     [x86], [SPARSEFLAGS= CGCCFLAGS=-target=i86],
     [x86_64], [SPARSEFLAGS=-m64 CGCCFLAGS=-target=x86_64],
     [SPARSEFLAGS= CGCCFLAGS=])
   AC_SUBST([SPARSEFLAGS])
   AC_SUBST([CGCCFLAGS])])

dnl OVS_SPARSE_EXTRA_INCLUDES
dnl
dnl The cgcc script from "sparse" does not search gcc's default
dnl search path. Get the default search path from GCC and pass
dnl them to sparse.
AC_DEFUN([OVS_SPARSE_EXTRA_INCLUDES],
    AC_SUBST([SPARSE_EXTRA_INCLUDES],
           [`$CC -v -E - </dev/null 2>&1 >/dev/null | sed -n -e '/^#include.*search.*starts.*here:/,/^End.*of.*search.*list\./s/^ \(.*\)/-I \1/p' |grep -v /usr/lib | grep -x -v '\-I /usr/include' | tr \\\n ' ' `] ))

dnl OVS_ENABLE_SPARSE
AC_DEFUN([OVS_ENABLE_SPARSE],
  [AC_REQUIRE([OVS_CHECK_SPARSE_TARGET])
   AC_REQUIRE([OVS_SPARSE_EXTRA_INCLUDES])
   : ${SPARSE=sparse}
   AC_SUBST([SPARSE])
   AC_CONFIG_COMMANDS_PRE(
     [CC='$(if $(C:0=),env REAL_CC="'"$CC"'" CHECK="$(SPARSE) $(SPARSE_WERROR) -I $(ovs_srcdir)/include/sparse $(SPARSEFLAGS) $(SPARSE_EXTRA_INCLUDES) " cgcc $(CGCCFLAGS),'"$CC"')'])

   AC_ARG_ENABLE(
     [sparse],
     [AC_HELP_STRING([--enable-sparse], [Run "sparse" by default])],
     [], [enable_sparse=no])
   AM_CONDITIONAL([ENABLE_SPARSE_BY_DEFAULT], [test $enable_sparse = yes])])

dnl OVS_CTAGS_IDENTIFIERS
dnl
dnl ctags ignores symbols with extras identifiers. This builds a list of
dnl specially handled identifiers to be ignored.
AC_DEFUN([OVS_CTAGS_IDENTIFIERS],
    AC_SUBST([OVS_CTAGS_IDENTIFIERS_LIST],
           [`printf %s '-I "'; sed -n 's/^#define \(OVS_[A-Z_]\+\)(\.\.\.)$/\1+/p' ${OVSDIR}/include/openvswitch/compiler.h  | tr \\\n ' ' ; printf '"'`] ))

dnl OVS_PTHREAD_SET_NAME
dnl
dnl This checks for three known variants of pthreads functions for setting
dnl the name of the current thread:
dnl
dnl   glibc: int pthread_setname_np(pthread_t, const char *name);
dnl   NetBSD: int pthread_setname_np(pthread_t, const char *format, void *arg);
dnl   FreeBSD: int pthread_set_name_np(pthread_t, const char *name);
dnl
dnl For glibc and FreeBSD, the arguments are just a thread and its name.  For
dnl NetBSD, 'format' is a printf() format string and 'arg' is an argument to
dnl provide to it.
dnl
dnl This macro defines:
dnl
dnl    glibc: HAVE_GLIBC_PTHREAD_SETNAME_NP
dnl    NetBSD: HAVE_NETBSD_PTHREAD_SETNAME_NP
dnl    FreeBSD: HAVE_PTHREAD_SET_NAME_NP
AC_DEFUN([OVS_CHECK_PTHREAD_SET_NAME],
  [AC_CHECK_FUNCS([pthread_set_name_np])
   if test $ac_cv_func_pthread_set_name_np != yes; then
     AC_CACHE_CHECK(
       [for pthread_setname_np() variant],
       [ovs_cv_pthread_setname_np],
       [AC_LINK_IFELSE(
         [AC_LANG_PROGRAM([#include <pthread.h>
  ], [pthread_setname_np(pthread_self(), "name");])],
         [ovs_cv_pthread_setname_np=glibc],
         [AC_LINK_IFELSE(
           [AC_LANG_PROGRAM([#include <pthread.h>
], [pthread_setname_np(pthread_self(), "%s", "name");])],
           [ovs_cv_pthread_setname_np=netbsd],
           [ovs_cv_pthread_setname_np=none])])])
     case $ovs_cv_pthread_setname_np in # (
       glibc)
          AC_DEFINE(
            [HAVE_GLIBC_PTHREAD_SETNAME_NP], [1],
            [Define to 1 if pthread_setname_np() is available and takes 2 parameters (like glibc).])
          ;; # (
       netbsd)
          AC_DEFINE(
            [HAVE_NETBSD_PTHREAD_SETNAME_NP], [1],
            [Define to 1 if pthread_setname_np() is available and takes 3 parameters (like NetBSD).])
          ;;
     esac
   fi])

dnl OVS_CHECK_LINUX_HOST.
dnl
dnl Checks whether we're building for a Linux host, based on the presence of
dnl the __linux__ preprocessor symbol, and sets up an Automake conditional
dnl LINUX based on the result.
AC_DEFUN([OVS_CHECK_LINUX_HOST],
  [AC_CACHE_CHECK(
     [whether __linux__ is defined],
     [ovs_cv_linux],
     [AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([enum { LINUX = __linux__};], [])],
        [ovs_cv_linux=true],
        [ovs_cv_linux=false])])
   AM_CONDITIONAL([LINUX], [$ovs_cv_linux])])

dnl OVN_CHECK_OVS
dnl
dnl Check for OVS sources
AC_DEFUN([OVN_CHECK_OVS], [
  AC_ARG_WITH([ovs-source],
              [AC_HELP_STRING([--with-ovs-source=/path/to/ovs/src/dir],
                              [Specify the OVS src directory])])
  AC_ARG_WITH([ovs-build],
              [AC_HELP_STRING([--with-ovs-build=/path/to/ovs/build/dir],
                              [Specify the OVS build directory])])

  AC_MSG_CHECKING([for OVS source directory])
  if test X"$with_ovs_source" != X; then
    OVSDIR=`eval echo "$with_ovs_source"`
    case $OVSDIR in
      /*) ;;
      *) OVSDIR=`pwd`/$OVSDIR ;;
    esac
    if test ! -f "$OVSDIR/vswitchd/bridge.c"; then
      AC_ERROR([$OVSDIR is not an OVS source directory])
    fi
  else
    OVSDIR=`pwd`/ovs
  fi

  AC_MSG_RESULT([$OVSDIR])
  AC_SUBST(OVSDIR)

  AC_MSG_CHECKING([for OVS build directory])
  if test X"$with_ovs_build" != X; then
    OVSBUILDDIR=`eval echo "$with_ovs_build"`
    case $OVSBUILDDIR in
      /*) ;;
      *) OVSBUILDDIR=`pwd`/$OVSBUILDDIR ;;
    esac
    if test ! -f "$OVSBUILDDIR/config.h"; then
      AC_ERROR([$OVSBUILDDIR is not a configured OVS build directory])
    fi
  elif test -f "$OVSDIR/config.h"; then
    # If separate build dir is not specified, use src dir.
    OVSBUILDDIR=$OVSDIR
  else
    AC_ERROR([OVS source dir $OVSDIR is not configured as a build directory (either run configure there or use --with-ovs-build to point to the build directory)])
  fi
  AC_MSG_RESULT([$OVSBUILDDIR])
  AC_SUBST(OVSBUILDDIR)
  OVSVERSION=`sed -n 's/^#define PACKAGE_VERSION//p' $OVSBUILDDIR/config.h | tr \\\n ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/\"//g'`
  AC_SUBST(OVSVERSION)
  AC_MSG_RESULT([OVS version is $OVSVERSION])
])
