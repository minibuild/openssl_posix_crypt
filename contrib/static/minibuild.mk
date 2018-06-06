# This makefile follows grammar syntax of 'MiniBuild' build system,
# for details see https://minibuild.github.io/minibuild/
#
# This makefile implies that OpenSSL toolkit is added into sources tree.
# OpenSSL toolkit ready to use as git-submodule may be found here:
# https://github.com/minibuild/openssl


module_type = 'lib-static'
module_name = 'openssl_posix_crypt_static'

include_dir_list = [
  '${@project_root}/openssl/include',
  '../..',
]

src_search_dir_list = ['../..']

build_list = ['openssl_posix_crypt.c']
