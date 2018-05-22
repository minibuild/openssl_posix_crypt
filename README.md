## openssl_posix_crypt
 **openssl_posix_crypt()** is a password encryption function aimed to be a drop-in replacement for platform dependent [crypt(3)](http://man7.org/linux/man-pages/man3/crypt.3.html).  
  
This is a derived work based on [code](https://github.com/openssl/openssl/blob/master/apps/passwd.c) developed by [OpenSSL team](https://www.openssl.org/) and depends on OpenSSL API and runtime libraries.  
  
##### __API__
`#include <openssl_posix_crypt.h>`
```
char* openssl_posix_crypt(const char *key, const char *salt, char* dest, size_t destlen);
```
##### __DESCRIPTION__
```
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
```
##### __ARGUMENTS__
```
key:
    a user's typed password
salt:
    a character string to be used as salt
dest:
    a character buffer to be used to store result data
destlen:
    size of 'dest' character buffer,
    value of macro OPENSSL_POSIX_CRYPT_BUFSIZ defined in
    file openssl_posix_crypt.h should be enough to cover all cases
```
##### __RETURN VALUE__
```
On success, a pointer to encrypted password is returned,
its value is actually same as passed 'dest' argument.

On error, NULL is returned.
```
##### __ATTRIBUTES__
```
Thread safe since OpenSSL-1.1.0
For early versions of OpenSSL check docs for 'OpenSSL thread support'.
```
##### __LICENSE__
License here is definitely the same as for original [OpenSSL](https://github.com/openssl/openssl) toolkit.  
You can obtain a copy in the file LICENSE in the source distribution or [online](https://www.openssl.org/source/license.html).