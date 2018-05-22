/*
 * Copyright 2000-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * ************************************************************************
 *
 * This file is a derived work, original file passwd.c may be found
 * at https://github.com/openssl/openssl/blob/master/apps/passwd.c
 *
 * When this work was started, commit hash of OpenSSL toolkit
 *   at https://github.com/openssl/openssl was the following:
 *
 *      git log -1 --format="%H"
 *      246bd8fd0507f4555432c148eed5a9322c113bf5
 */

#include <openssl_posix_crypt.h>

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#ifndef OPENSSL_NO_DES
#include <openssl/des.h>
#endif

#include <string.h>
#include <assert.h>

static unsigned const char cov_2char[64] = {
    /* from crypto/des/fcrypt.c */
    0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
    0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44,
    0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
    0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54,
    0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x61, 0x62,
    0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
    0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72,
    0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A
};

static const char ascii_dollar[] = { 0x24, 0x00 };

typedef enum {
    passwd_unset = 0,
    passwd_crypt,
    passwd_md5,
    passwd_apr1,
    passwd_sha256,
    passwd_sha512,
    passwd_aixmd5
} passwd_modes;

static const char method_id_1[] = { '1', 0 };
static const char method_id_apr1[] = { 'a', 'p', 'r', '1', 0 };
static const char method_id_5[] = { '5', 0 };
static const char method_id_6[] = { '6', 0 };

/*
 * MD5-based password algorithm (should probably be available as a library
 * function; then the static buffer would not be acceptable). For magic
 * string "1", this should be compatible to the MD5-based BSD password
 * algorithm. For 'magic' string "apr1", this is compatible to the MD5-based
 * Apache password algorithm. (Apparently, the Apache password algorithm is
 * identical except that the 'magic' string was changed -- the laziest
 * application of the NIH principle I've ever encountered.)
 */
static char *md5crypt(const char *passwd, const char *magic, const char *salt, char* out_buffer, size_t out_buflen)
{
    /* "$apr1$..salt..$.......md5hash..........\0" */
    unsigned char buf[MD5_DIGEST_LENGTH];
    char ascii_magic[5];         /* "apr1" plus '\0' */
    char ascii_salt[9];          /* Max 8 chars plus '\0' */
    char *ascii_passwd = NULL;
    char *salt_out;
    int n;
    unsigned int i;
    EVP_MD_CTX *md = NULL, *md2 = NULL;
    size_t passwd_len, salt_len, magic_len;

    if (out_buflen < 6 + 9 + 24 + 2)
        return NULL;

    passwd_len = strlen(passwd);

    out_buffer[0] = 0;
    magic_len = strlen(magic);
    strncpy(ascii_magic, magic, sizeof(ascii_magic));

    /* The salt gets truncated to 8 chars */
    strncpy(ascii_salt, salt, sizeof(ascii_salt));
    salt_len = strlen(ascii_salt);

    if (magic_len > 0) {
        strncat(out_buffer, ascii_dollar, out_buflen);

        if (magic_len > 4)    /* assert it's  "1" or "apr1" */
            goto err;

        strncat(out_buffer, ascii_magic, out_buflen);
        strncat(out_buffer, ascii_dollar, out_buflen);
    }

    strncat(out_buffer, ascii_salt, out_buflen);

    if (strlen(out_buffer) > 6 + 8) /* assert "$apr1$..salt.." */
        goto err;

    salt_out = out_buffer;
    if (magic_len > 0)
        salt_out += 2 + magic_len;

    if (salt_len > 8)
        goto err;

    md = EVP_MD_CTX_new();
    if (md == NULL
        || !EVP_DigestInit_ex(md, EVP_md5(), NULL)
        || !EVP_DigestUpdate(md, passwd, passwd_len))
        goto err;

    if (magic_len > 0)
        if (!EVP_DigestUpdate(md, ascii_dollar, 1)
            || !EVP_DigestUpdate(md, ascii_magic, magic_len)
            || !EVP_DigestUpdate(md, ascii_dollar, 1))
          goto err;

    if (!EVP_DigestUpdate(md, ascii_salt, salt_len))
        goto err;

    md2 = EVP_MD_CTX_new();
    if (md2 == NULL
        || !EVP_DigestInit_ex(md2, EVP_md5(), NULL)
        || !EVP_DigestUpdate(md2, passwd, passwd_len)
        || !EVP_DigestUpdate(md2, ascii_salt, salt_len)
        || !EVP_DigestUpdate(md2, passwd, passwd_len)
        || !EVP_DigestFinal_ex(md2, buf, NULL))
        goto err;

    for (i = (unsigned int)passwd_len; i > (unsigned int)sizeof(buf); i -= (unsigned int)sizeof(buf)) {
        if (!EVP_DigestUpdate(md, buf, sizeof(buf)))
            goto err;
    }
    if (!EVP_DigestUpdate(md, buf, i))
        goto err;

    n = (int)passwd_len;
    while (n) {
        if (!EVP_DigestUpdate(md, (n & 1) ? "\0" : passwd, 1))
            goto err;
        n >>= 1;
    }
    if (!EVP_DigestFinal_ex(md, buf, NULL))
        return NULL;

    for (i = 0; i < 1000; i++) {
        if (!EVP_DigestInit_ex(md2, EVP_md5(), NULL))
            goto err;
        if (!EVP_DigestUpdate(md2,
                              (i & 1) ? (unsigned const char *)passwd : buf,
                              (i & 1) ? passwd_len : sizeof(buf)))
            goto err;
        if (i % 3) {
            if (!EVP_DigestUpdate(md2, ascii_salt, salt_len))
                goto err;
        }
        if (i % 7) {
            if (!EVP_DigestUpdate(md2, passwd, passwd_len))
                goto err;
        }
        if (!EVP_DigestUpdate(md2,
                              (i & 1) ? buf : (unsigned const char *)passwd,
                              (i & 1) ? sizeof(buf) : passwd_len))
                goto err;
        if (!EVP_DigestFinal_ex(md2, buf, NULL))
                goto err;
    }
    EVP_MD_CTX_free(md2);
    EVP_MD_CTX_free(md);
    md2 = NULL;
    md = NULL;

    {
        /* transform buf into output string */
        unsigned char buf_perm[sizeof(buf)];
        int dest, source;
        char *output;

        /* silly output permutation */
        for (dest = 0, source = 0; dest < 14;
             dest++, source = (source + 6) % 17)
            buf_perm[dest] = buf[source];
        buf_perm[14] = buf[5];
        buf_perm[15] = buf[11];

        output = salt_out + salt_len;
        assert(output == out_buffer + strlen(out_buffer));

        *output++ = ascii_dollar[0];

        for (i = 0; i < 15; i += 3) {
            *output++ = cov_2char[buf_perm[i + 2] & 0x3f];
            *output++ = cov_2char[((buf_perm[i + 1] & 0xf) << 2) |
                                  (buf_perm[i + 2] >> 6)];
            *output++ = cov_2char[((buf_perm[i] & 3) << 4) |
                                  (buf_perm[i + 1] >> 4)];
            *output++ = cov_2char[buf_perm[i] >> 2];
        }
        assert(i == 15);
        *output++ = cov_2char[buf_perm[i] & 0x3f];
        *output++ = cov_2char[buf_perm[i] >> 6];
        *output = 0;
        assert(strlen(out_buffer) < out_buflen);
    }

    return out_buffer;

 err:
    OPENSSL_free(ascii_passwd);
    EVP_MD_CTX_free(md2);
    EVP_MD_CTX_free(md);
    return NULL;
}

/*
 * SHA based password algorithm, describe by Ulrich Drepper here:
 * https://www.akkadia.org/drepper/SHA-crypt.txt
 * (note that it's in the public domain)
 */
static char *shacrypt(const char *passwd, const char *magic, const char *salt, char* out_buffer, size_t out_buflen)
{
    /* Prefix for optional rounds specification.  */
    const char rounds_prefix[] = "rounds=";
    /* Maximum salt string length.  */
# define SALT_LEN_MAX 16
    /* Default number of rounds if not explicitly specified.  */
# define ROUNDS_DEFAULT 5000
    /* Minimum number of rounds.  */
# define ROUNDS_MIN 1000
    /* Maximum number of rounds.  */
# define ROUNDS_MAX 999999999

    /* "$6$rounds=<N>$......salt......$...shahash(up to 86 chars)...\0" */
    unsigned char buf[SHA512_DIGEST_LENGTH];
    unsigned char temp_buf[SHA512_DIGEST_LENGTH];
    size_t buf_size = 0;
    char ascii_magic[2];
    char ascii_salt[17];          /* Max 16 chars plus '\0' */
    size_t n;
    EVP_MD_CTX *md = NULL, *md2 = NULL;
    const EVP_MD *sha = NULL;
    size_t passwd_len, salt_len, magic_len;
    unsigned int rounds = 5000;        /* Default */
    char rounds_custom = 0;
    char *p_bytes = NULL;
    char *s_bytes = NULL;
    char *cp = NULL;

    if (out_buflen < 3 + 17 + 17 + 86 + 1)
        return NULL;

    passwd_len = strlen(passwd);
    magic_len = strlen(magic);

    /* assert it's "5" or "6" */
    if (magic_len != 1)
        return NULL;

    switch (magic[0]) {
    case '5':
        sha = EVP_sha256();
        buf_size = 32;
        break;
    case '6':
        sha = EVP_sha512();
        buf_size = 64;
        break;
    default:
        return NULL;
    }

    if (strncmp(salt, rounds_prefix, sizeof(rounds_prefix) - 1) == 0) {
        const char *num = salt + sizeof(rounds_prefix) - 1;
        char *endp;
        unsigned long int srounds = strtoul (num, &endp, 10);
        if (*endp == '$') {
            salt = endp + 1;
            if (srounds > ROUNDS_MAX)
                rounds = ROUNDS_MAX;
            else if (srounds < ROUNDS_MIN)
                rounds = ROUNDS_MIN;
            else
                rounds = (unsigned int)srounds;
            rounds_custom = 1;
        } else {
            return NULL;
        }
    }

    strncpy(ascii_magic, magic, sizeof(ascii_magic));

    /* The salt gets truncated to 16 chars */
    strncpy(ascii_salt, salt, sizeof(ascii_salt));
    salt_len = strlen(ascii_salt);

    out_buffer[0] = 0;
    strncat(out_buffer, ascii_dollar, out_buflen);
    strncat(out_buffer, ascii_magic, out_buflen);
    strncat(out_buffer, ascii_dollar, out_buflen);
    if (rounds_custom) {
        char tmp_buf[80]; /* "rounds=999999999" */
        sprintf(tmp_buf, "rounds=%u", rounds);
        strncat(out_buffer, tmp_buf, out_buflen);
        strncat(out_buffer, ascii_dollar, out_buflen);
    }
    strncat(out_buffer, ascii_salt, out_buflen);

    /* assert "$5$rounds=999999999$......salt......" */
    if (strlen(out_buffer) > 3 + 17 * rounds_custom + salt_len )
        goto err;

    md = EVP_MD_CTX_new();
    if (md == NULL
        || !EVP_DigestInit_ex(md, sha, NULL)
        || !EVP_DigestUpdate(md, passwd, passwd_len)
        || !EVP_DigestUpdate(md, ascii_salt, salt_len))
        goto err;

    md2 = EVP_MD_CTX_new();
    if (md2 == NULL
        || !EVP_DigestInit_ex(md2, sha, NULL)
        || !EVP_DigestUpdate(md2, passwd, passwd_len)
        || !EVP_DigestUpdate(md2, ascii_salt, salt_len)
        || !EVP_DigestUpdate(md2, passwd, passwd_len)
        || !EVP_DigestFinal_ex(md2, buf, NULL))
        goto err;

    for (n = passwd_len; n > buf_size; n -= buf_size) {
        if (!EVP_DigestUpdate(md, buf, buf_size))
            goto err;
    }
    if (!EVP_DigestUpdate(md, buf, n))
        goto err;

    n = passwd_len;
    while (n) {
        if (!EVP_DigestUpdate(md,
                              (n & 1) ? buf : (unsigned const char *)passwd,
                              (n & 1) ? buf_size : passwd_len))
            goto err;
        n >>= 1;
    }
    if (!EVP_DigestFinal_ex(md, buf, NULL))
        return NULL;

    /* P sequence */
    if (!EVP_DigestInit_ex(md2, sha, NULL))
        goto err;

    for (n = passwd_len; n > 0; n--)
        if (!EVP_DigestUpdate(md2, passwd, passwd_len))
            goto err;

    if (!EVP_DigestFinal_ex(md2, temp_buf, NULL))
        return NULL;

    if ((p_bytes = OPENSSL_zalloc(passwd_len)) == NULL)
        goto err;
    for (cp = p_bytes, n = passwd_len; n > buf_size; n -= buf_size, cp += buf_size)
        memcpy(cp, temp_buf, buf_size);
    memcpy(cp, temp_buf, n);

    /* S sequence */
    if (!EVP_DigestInit_ex(md2, sha, NULL))
        goto err;

    for (n = 16 + buf[0]; n > 0; n--)
        if (!EVP_DigestUpdate(md2, ascii_salt, salt_len))
            goto err;

    if (!EVP_DigestFinal_ex(md2, temp_buf, NULL))
        return NULL;

    if ((s_bytes = OPENSSL_zalloc(salt_len)) == NULL)
        goto err;
    for (cp = s_bytes, n = salt_len; n > buf_size; n -= buf_size, cp += buf_size)
        memcpy(cp, temp_buf, buf_size);
    memcpy(cp, temp_buf, n);

    for (n = 0; n < rounds; n++) {
        if (!EVP_DigestInit_ex(md2, sha, NULL))
            goto err;
        if (!EVP_DigestUpdate(md2,
                              (n & 1) ? (unsigned const char *)p_bytes : buf,
                              (n & 1) ? passwd_len : buf_size))
            goto err;
        if (n % 3) {
            if (!EVP_DigestUpdate(md2, s_bytes, salt_len))
                goto err;
        }
        if (n % 7) {
            if (!EVP_DigestUpdate(md2, p_bytes, passwd_len))
                goto err;
        }
        if (!EVP_DigestUpdate(md2,
                              (n & 1) ? buf : (unsigned const char *)p_bytes,
                              (n & 1) ? buf_size : passwd_len))
                goto err;
        if (!EVP_DigestFinal_ex(md2, buf, NULL))
                goto err;
    }
    EVP_MD_CTX_free(md2);
    EVP_MD_CTX_free(md);
    md2 = NULL;
    md = NULL;
    OPENSSL_free(p_bytes);
    OPENSSL_free(s_bytes);
    p_bytes = NULL;
    s_bytes = NULL;

    cp = out_buffer + strlen(out_buffer);
    *cp++ = ascii_dollar[0];

# define b64_from_24bit(B2, B1, B0, N)                                   \
    do {                                                                \
        unsigned int w = ((B2) << 16) | ((B1) << 8) | (B0);             \
        int i = (N);                                                    \
        while (i-- > 0)                                                 \
            {                                                           \
                *cp++ = cov_2char[w & 0x3f];                            \
                w >>= 6;                                                \
            }                                                           \
    } while (0)

    switch (magic[0]) {
    case '5':
        b64_from_24bit (buf[0], buf[10], buf[20], 4);
        b64_from_24bit (buf[21], buf[1], buf[11], 4);
        b64_from_24bit (buf[12], buf[22], buf[2], 4);
        b64_from_24bit (buf[3], buf[13], buf[23], 4);
        b64_from_24bit (buf[24], buf[4], buf[14], 4);
        b64_from_24bit (buf[15], buf[25], buf[5], 4);
        b64_from_24bit (buf[6], buf[16], buf[26], 4);
        b64_from_24bit (buf[27], buf[7], buf[17], 4);
        b64_from_24bit (buf[18], buf[28], buf[8], 4);
        b64_from_24bit (buf[9], buf[19], buf[29], 4);
        b64_from_24bit (0, buf[31], buf[30], 3);
        break;
    case '6':
        b64_from_24bit (buf[0], buf[21], buf[42], 4);
        b64_from_24bit (buf[22], buf[43], buf[1], 4);
        b64_from_24bit (buf[44], buf[2], buf[23], 4);
        b64_from_24bit (buf[3], buf[24], buf[45], 4);
        b64_from_24bit (buf[25], buf[46], buf[4], 4);
        b64_from_24bit (buf[47], buf[5], buf[26], 4);
        b64_from_24bit (buf[6], buf[27], buf[48], 4);
        b64_from_24bit (buf[28], buf[49], buf[7], 4);
        b64_from_24bit (buf[50], buf[8], buf[29], 4);
        b64_from_24bit (buf[9], buf[30], buf[51], 4);
        b64_from_24bit (buf[31], buf[52], buf[10], 4);
        b64_from_24bit (buf[53], buf[11], buf[32], 4);
        b64_from_24bit (buf[12], buf[33], buf[54], 4);
        b64_from_24bit (buf[34], buf[55], buf[13], 4);
        b64_from_24bit (buf[56], buf[14], buf[35], 4);
        b64_from_24bit (buf[15], buf[36], buf[57], 4);
        b64_from_24bit (buf[37], buf[58], buf[16], 4);
        b64_from_24bit (buf[59], buf[17], buf[38], 4);
        b64_from_24bit (buf[18], buf[39], buf[60], 4);
        b64_from_24bit (buf[40], buf[61], buf[19], 4);
        b64_from_24bit (buf[62], buf[20], buf[41], 4);
        b64_from_24bit (0, 0, buf[63], 2);
        break;
    default:
        goto err;
    }
    *cp = '\0';

    return out_buffer;

 err:
    EVP_MD_CTX_free(md2);
    EVP_MD_CTX_free(md);
    OPENSSL_free(p_bytes);
    OPENSSL_free(s_bytes);
    return NULL;
}

static char *descrypt(const char *passwd, const char *salt, char* out_buf, size_t out_buf_len)
{
#ifndef OPENSSL_NO_DES
    char pwbuf[9];
    if (out_buf_len < 14)
        return NULL;
    strncpy(pwbuf, passwd, 9);
    pwbuf[8] = 0;
    out_buf[0] = 0;
    return DES_fcrypt(pwbuf, salt, out_buf);
#else
    return NULL;
#endif
}

static char* do_passwd(passwd_modes mode, const char* passwd, const char* salt, char* dest, size_t destlen)
{
    char* hash = NULL;
    if (mode == passwd_crypt)
        hash = descrypt(passwd, salt, dest, destlen);
    else if (mode == passwd_md5 || mode == passwd_apr1)
        hash = md5crypt(passwd, (mode == passwd_md5 ? "1" : "apr1"), salt, dest, destlen);
    else if (mode == passwd_aixmd5)
        hash = md5crypt(passwd, "", salt, dest, destlen);
    else if (mode == passwd_sha256 || mode == passwd_sha512)
        hash = shacrypt(passwd, (mode == passwd_sha256 ? "5" : "6"), salt, dest, destlen);
    return hash;
}

char* openssl_posix_crypt(const char* key, const char* salt_in, char* dest, size_t destlen)
{
    passwd_modes mode = passwd_unset;
    char* hash = NULL;
    size_t saltlen = 0;
    size_t salt_offset = 0;
    char saltbuf[OPENSSL_POSIX_CRYPT_BUFSIZ];
    char* method_id = NULL;
    char* salt = NULL;
    char null = 0;
    const char* passwd = &null;
    char* p;
    if (key)
        passwd = key;
    if (salt_in) {
        saltlen = strlen(salt_in);
        if (salt_in[0] == ascii_dollar[0]) {
            salt_offset = 1;
            saltlen -= 1;
        }
        if (saltlen > 0 && salt_in[salt_offset + saltlen - 1] == ascii_dollar[0] && (salt_offset || saltlen > 3))
            saltlen -= 1;
    }
    if (!salt_offset) {
        if (saltlen != 2 && saltlen != 8)
            return NULL;
    }
    if (saltlen >= OPENSSL_POSIX_CRYPT_BUFSIZ)
        saltlen = OPENSSL_POSIX_CRYPT_BUFSIZ - 1;
    strncpy(saltbuf, &salt_in[salt_offset], OPENSSL_POSIX_CRYPT_BUFSIZ);
    saltbuf[saltlen] = 0;
    if (!salt_offset) {
        mode = saltlen == 2 ? passwd_crypt : passwd_aixmd5;
        salt = saltbuf;
    }
    else {
        p = strchr(saltbuf, ascii_dollar[0]);
        if (p) {
            *p = 0;
            ++p;
            method_id = saltbuf;
            salt = p;
            if (strcmp(method_id, method_id_1) == 0)
                mode = passwd_md5;
            else if (strcmp(method_id, method_id_apr1) == 0)
                mode = passwd_apr1;
            else if (strcmp(method_id, method_id_5) == 0)
                mode = passwd_sha256;
            else if (strcmp(method_id, method_id_6) == 0)
                mode = passwd_sha512;
        }
    }
    hash = do_passwd(mode, passwd, salt, dest, destlen);
    return hash;
}
