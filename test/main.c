#include <openssl_posix_crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* NULL_PTR       = "<NULL>";
static const char STATUS_OK[]     = "[OK]     -";
static const char STATUS_FAILED[] = "[FAILED] -";

static const char* strsafe(const char* v)
{
    if (v == NULL)
        return NULL_PTR;
    return v;
}

static int run_test(const char* test_id, const char* password, const char* salt, const char* expected)
{
    char* hash =  NULL;
    const char* status =  NULL;
    int passed = 0;
    char buf[OPENSSL_POSIX_CRYPT_BUFSIZ];

    hash = openssl_posix_crypt(password, salt, buf, OPENSSL_POSIX_CRYPT_BUFSIZ);

    if (hash && expected)
    {
        passed = (strcmp(hash, expected) == 0);
    }
    else if (!hash && !expected)
    {
        passed = 1;
    }
    status = passed ? STATUS_OK : STATUS_FAILED;
    printf("%s %s salt='%s' password='%s' >> %s\n", test_id, status, strsafe(salt), strsafe(password), strsafe(hash));
    if (!passed)
    {
        printf("            - expected: %s\n", strsafe(expected));
    }
    return passed ? 0 : 1;
}

typedef struct
{
    const char* TestID;
    const char* Salt;
    const char* Password;
    const char* Expected;
} TestEntry;


TestEntry TEST_LIST[] = {
    /* {">11", NULL, NULL, NULL}, *//*    jump on test 11 */
    /* {"^", NULL, NULL, NULL}, *//*    interrupt test sequence */

    {"01", NULL, NULL, NULL},
    {"02", "", "", NULL},
    {"03", "a", "", NULL},
    {"04", "$", "", NULL},
    {"05", "$$", "", NULL},
    {"06", "$$$", "", NULL},
    {"07", "$42$salt", "", NULL},
    {"08", "xx$", "", NULL},
    {"09", "xx", "", "xx95eIq3U1EUg"},
    {"10", "xx", "password", "xxj31ZMTZzkVA"},
    {"11", "xx", "passworddeadbeaf", "xxj31ZMTZzkVA"},
    {"12", "$1$xxxxxxxx", "password", "$1$xxxxxxxx$UYCIxa628.9qXjpQCjM4a."},
    {"13", "$1$xxxxxxxx$", "password", "$1$xxxxxxxx$UYCIxa628.9qXjpQCjM4a."},
    {"14", "$apr1$xxxxxxxx", "password", "$apr1$xxxxxxxx$dxHfLAsjHkDRmG83UXe8K0"},
    {"15", "$apr1$xxxxxxxx$", "password", "$apr1$xxxxxxxx$dxHfLAsjHkDRmG83UXe8K0"},
    {"16", "xxxxxxxx", "password", "xxxxxxxx$8Oaipk/GPKhC64w/YVeFD/"},
    {"17", "xxxxxxxx$", "password", "xxxxxxxx$8Oaipk/GPKhC64w/YVeFD/"},
    {"18", "$5$xxxxxxxxxxxxxxxx", "password", "$5$xxxxxxxxxxxxxxxx$fHytsM.wVD..zPN/h3i40WJRggt/1f73XkAC/gkelkB"},
    {"19", "$5$xxxxxxxxxxxxxxxx$", "password", "$5$xxxxxxxxxxxxxxxx$fHytsM.wVD..zPN/h3i40WJRggt/1f73XkAC/gkelkB"},
    {"20", "$5$saltstring", "Hello world!", "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"},
    {"21", "$5$rounds=10000$saltstringsaltst", "Hello world!", "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA"},
    {"22", "$5$rounds=10000$saltstringsaltst$", "Hello world!", "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA"},
    {"23", "$5$rounds=5000$toolongsaltstrin", "This is just a test", "$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5"},
    {"24", "$5$rounds=1400$anotherlongsalts", "a very much longer text to encrypt.  This one even stretches over morethan one line.", "$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1"},
    {"25", "$6$xxxxxxxxxxxxxxxx", "password", "$6$xxxxxxxxxxxxxxxx$VjGUrXBG6/8yW0f6ikBJVOb/lK/Tm9LxHJmFfwMvT7cpk64N9BW7ZQhNeMXAYFbOJ6HDG7wb0QpxJyYQn0rh81"},
    {"26", "$6$xxxxxxxxxxxxxxxx$", "password", "$6$xxxxxxxxxxxxxxxx$VjGUrXBG6/8yW0f6ikBJVOb/lK/Tm9LxHJmFfwMvT7cpk64N9BW7ZQhNeMXAYFbOJ6HDG7wb0QpxJyYQn0rh81"},
    {"27", "$5$rounds=77777$short", "we have a short salt string but not a short password", "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/"},
    {"28", "$5$rounds=123456$asaltof16chars..", "a short string", "$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD"},
    {"29", "$5$rounds=1000$roundstoolow", "the minimum number is still observed", "$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC"},
    {"30", "$6$saltstring", "Hello world!", "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"},
    {"31", "$6$saltstring$", "Hello world!", "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"},
    {"32", "$6$rounds=10000$saltstringsaltst", "Hello world!", "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."},
    {"33", "$6$rounds=10000$saltstringsaltst$", "Hello world!", "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."},
    {"34", "$6$rounds=5000$toolongsaltstrin", "This is just a test", "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0"},
    {"35", "$6$rounds=1400$anotherlongsalts", "a very much longer text to encrypt.  This one even stretches over morethan one line.", "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1"},
    {"36", "$6$rounds=77777$short", "we have a short salt string but not a short password", "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0"},
    {"37", "$6$rounds=123456$asaltof16chars..", "a short string", "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1"},
    {"38", "$6$rounds=1000$roundstoolow", "the minimum number is still observed", "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX."},

    {NULL, NULL, NULL, NULL}, /* terminator */
};

int main(int argc, char **argv)
{
    TestEntry* t;
    int ret = 0;
    char* key = NULL;
    char* salt = NULL;
    char* hash =  NULL;
    const char* jump = NULL;
    char buf[OPENSSL_POSIX_CRYPT_BUFSIZ];
    if (argc > 1 && (strcmp(argv[1], "@test") == 0))
    {
        for (t = &TEST_LIST[0]; t->TestID && !ret; ++t)
        {
            if (jump && (strcmp(jump, t->TestID) != 0))
                continue;
            jump = NULL;
            if (t->TestID[0] == '>')
            {
                jump = &t->TestID[1];
                printf("Forward jump on test '%s' ...\n", jump);
                continue;
            }
            if (t->TestID[0] == '^')
            {
                printf("Test sequnce interrupted.\n");
                break;
            }
            ret = run_test(t->TestID, t->Password, t->Salt, t->Expected);
        }
        return ret;
    }

    if (argc > 1)
        key = argv[1];
    if (argc > 2)
        salt = argv[2];
    hash = openssl_posix_crypt(key, salt, buf, OPENSSL_POSIX_CRYPT_BUFSIZ);
    ret = hash != NULL ? 0 : 1;
    printf("%s\n", strsafe(hash));
    return ret;
}
