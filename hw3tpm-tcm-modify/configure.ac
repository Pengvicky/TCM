dnl The copyright in this software is being made available under the BSD License,
dnl included below. This software may be subject to other third party and
dnl contributor rights, including patent rights, and no such rights are granted
dnl under this license.
dnl
dnl Copyright (c) Intel Corporation
dnl
dnl All rights reserved.
dnl
dnl BSD License
dnl
dnl Redistribution and use in source and binary forms, with or without modification,
dnl are permitted provided that the following conditions are met:
dnl
dnl Redistributions of source code must retain the above copyright notice, this list
dnl of conditions and the following disclaimer.
dnl
dnl Redistributions in binary form must reproduce the above copyright notice, this
dnl list of conditions and the following disclaimer in the documentation and/or
dnl other materials provided with the distribution.
dnl
dnl THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ""AS IS""
dnl AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
dnl IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
dnl DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
dnl ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
dnl (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
dnl LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
dnl ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
dnl (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
dnl SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

AC_INIT([ms-tpm-20-ref],
        [0.1],
        [https://github.com/microsoft/ms-tpm-20-ref/issues],
        [],
        [https://github.com/microsoft/ms-tpm-20-ref])
AC_CONFIG_MACRO_DIR([.])
AC_PROG_CC
AC_PROG_LN_S
AC_PROG_RANLIB
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_FILES([Makefile])
AC_SUBST([DISTCHECK_CONFIGURE_FLAGS],[$ac_configure_args])

dnl By enabling this feature tpm simulator gets seeds derived from hardware parameters.
dnl It is enabled only for linux devices.
dnl Note that the seeds are not derived from secure hardware source.

AC_ARG_ENABLE(usedeviceid,
    AS_HELP_STRING([--enable-usedeviceid],
    [tpm simulator get seeds derived from hardware parameters. Seeds are not derived from secure hardware source.]))

LDFLAGS="$LDFLAGS -L/usr/local/lib -Wl,-rpath,/usr/local/lib"
CPPFLAGS="$CPPFLAGS -I/usr/local/include"

AC_CHECK_HEADERS([ \
    hitls/crypto/crypt_eal_init.h \
    hitls/bsl/bsl_init.h \
],, [AC_MSG_ERROR([Required openhitls header not found in /usr/local/include])])

dnl Force pthread linking with --no-as-needed to prevent linker from dropping it
PTHREAD_LIBS="-Wl,--no-as-needed -lpthread -Wl,--as-needed"
AC_SUBST([PTHREAD_LIBS])

dnl Check for dl library
AC_SEARCH_LIBS([dlopen], [dl], [], [
    AC_MSG_ERROR([libdl is required for openHITLS])
])

dnl Check for boundscheck library
AC_CHECK_LIB([boundscheck], [memcpy_s], 
    [BOUNDSCHECK_LIBS="-lboundscheck"],
    [AC_MSG_ERROR([libboundscheck is required. Install from OpenHitls/libboundscheck])],
    [])

dnl For library checks, use explicit --no-as-needed for pthread
saved_LIBS="$LIBS"
LIBS="$LIBS -Wl,--no-as-needed -lpthread -Wl,--as-needed -ldl -lboundscheck"

dnl Check for hitls_bsl
AC_CHECK_LIB([hitls_bsl], [BSL_GLOBAL_Init],
    [HITLS_BSL_LIBS="-lhitls_bsl"],
    [AC_MSG_ERROR([libhitls_bsl does not provide BSL_GLOBAL_Init. Check installation.])],
    [])

dnl Check for hitls_crypto
AC_CHECK_LIB([hitls_crypto], [CRYPT_EAL_Init], 
    [HITLS_CRYPTO_LIBS="-lhitls_crypto"],
    [AC_MSG_ERROR([libhitls_crypto does not provide CRYPT_EAL_Init. Check installation.])],
    [-lhitls_bsl])

LIBS="$saved_LIBS"

dnl Assemble all crypto libraries with proper pthread handling
dnl Use --no-as-needed to force pthread linking even if direct symbols aren't used
LIBCRYPTO_LIBS="-lhitls_crypto -lhitls_bsl -lboundscheck -Wl,--no-as-needed -lpthread -Wl,--as-needed -ldl"
AC_SUBST([LIBCRYPTO_LIBS])

AC_MSG_NOTICE([========================================])
AC_MSG_NOTICE([Using openHITLS library flags: $LIBCRYPTO_LIBS])
AC_MSG_NOTICE([========================================])

AC_DEFINE([HASH_LIB], [Ohitls], [Crypto lib for hash algorithms])
AC_DEFINE([SYM_LIB], [Ohitls], [Crypto lib for symmetric encryption algorithms])
AC_DEFINE([MATH_LIB], [TpmBigNum], [Crypto lib for asymmetric operations])
AC_DEFINE([BN_MATH_LIB], [Ohitls], [Math lib for tpmbignum operations])

ADD_COMPILER_FLAG([-std=gnu11])
ADD_COMPILER_FLAG([-Werror])
ADD_COMPILER_FLAG([-Wall])
ADD_COMPILER_FLAG([-Wformat-security])
ADD_COMPILER_FLAG([-fstack-protector-all])
ADD_COMPILER_FLAG([-fPIC])

# This is needed when compiling against OpenSSL 3.0, as the Ossl bindings use:
#  - EC_POINT_set_affine_coordinates_GFp / EC_POINTs_mul
#  - AES_set_encrypt_key / AES_encrypt
#  - Camellia_set_key / Camellia_encrypt
ADD_COMPILER_FLAG([-Wno-error=deprecated-declarations])

AS_IF([test "x$enable_usedeviceid" = "xyes"], [
    ADD_COMPILER_FLAG([-DNDEBUG])
    ADD_COMPILER_FLAG([-g])
    ADD_COMPILER_FLAG([-DUSE_PLATFORM_EPS])
    dnl Check for pkg-config
    AC_PATH_PROG([PKG_CONFIG], [pkg-config], [no])
    AS_IF([test "x$PKG_CONFIG" = "xno"], [
        AC_MSG_ERROR([pkg-config is required when using --enable-usedeviceid])
    ])
    dnl Use pkg-config to check for libudev
    $PKG_CONFIG --exists libudev || AC_MSG_ERROR([libudev not found])
    LIBUDEV_CFLAGS=`$PKG_CONFIG --cflags libudev`
    LIBUDEV_LIBS=`$PKG_CONFIG --libs libudev`
    AC_SUBST([LIBUDEV_CFLAGS])
    AC_SUBST([LIBUDEV_LIBS])
    ADDITIONAL_LIBS="$LIBUDEV_LIBS"
    AC_SUBST([ADDITIONAL_LIBS])
])

ADD_LINK_FLAG([-Wl,--no-undefined])
ADD_LINK_FLAG([-Wl,-z,noexecstack])
ADD_LINK_FLAG([-Wl,-z,now])
ADD_LINK_FLAG([-Wl,-z,relro])

AC_OUTPUT
