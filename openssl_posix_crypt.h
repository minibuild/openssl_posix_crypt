/*
 * openssl_posix_crypt() is a password encryption function aimed
 * to be a drop-in replacement for platform dependent crypt(3).
 *
 * This implementation is based on code developed by OpenSSL team,
 * so license here is the same as for original OpenSSL toolkit,
 * and its copyright provided below.
 *
 * ************************************************************************
 *
 * Copyright 2000-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
*/

#pragma once

#include <stdlib.h>

#define OPENSSL_POSIX_CRYPT_BUFSIZ 124

/*
DESCRIPTION
    If salt is a character string starting with the characters "$id$"
    followed by a string optionally terminated by "$", then the result
    has the form: $id$salt$encrypted, id identifies the encryption method
    used instead of legacy behavior (DES or MD5-AIX).

    The following values of id are supported:

    ID      | Method
    ----------------------------------------------------------------
    1       | MD5
    apr1    | MD5, Apache variant
    5       | SHA-256
    6       | SHA-512

    Wnen ID is not given, i.e. salt string doesn't start with "$id$",
    the following encryption methods are used:
        DES - when salt size is 2
        MD5, AIX style - when salt size is 8

ARGUMENTS
    key:
        a user's typed password

    salt:
        a character string to be used as salt

    dest:
        a character buffer to be used to store result data

    destlen:
        size of 'dest' character buffer,
        value of macro OPENSSL_POSIX_CRYPT_BUFSIZ should be enough
        to cover all cases

RETURN VALUE
    On success, a pointer to encrypted password is returned,
    its value is actually same as passed 'dest' argument.
    On error, NULL is returned.

ATTRIBUTES
    Thread safe since OpenSSL-1.1.0,
    for early versions check docs for 'OpenSSL thread support'.
*/

char* openssl_posix_crypt(const char *key, const char *salt, char* dest, size_t destlen);
