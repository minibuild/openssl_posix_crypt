# This makefile follows grammar syntax of 'MiniBuild' build system,
# for details see https://minibuild.github.io/minibuild/
#
# This makefile implies that OpenSSL toolkit is added into sources tree.
# OpenSSL toolkit ready to use as git-submodule may be found here:
# https://github.com/minibuild/openssl


module_type = 'executable'
module_name = 'test_openssl_posix_crypt_static'
win_console = 1

include_dir_list = [
  '${@project_root}/openssl/include',
  '../..',
]

src_search_dir_list = ['../../test']

lib_list = [
  '${@project_root}/openssl/build/crypto_static',
  '${@project_root}/zlib',
  '../static',
]

build_list = ['main.c']

prebuilt_lib_list_windows = ['crypt32','ws2_32', 'advapi32', 'user32']
prebuilt_lib_list_linux = ['dl', 'pthread']
