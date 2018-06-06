# This makefile follows grammar syntax of 'MiniBuild' build system,
# for details see https://minibuild.github.io/minibuild/
#
# Quick build how-to:
#
#   1. Install python module 'minibuild':
#      $ python -m pip install minibuild
#
#   2. Launch build from this directory:
#      $ python -m minibuild
#
#   3. Executable ready for test is here:
#         On Linux:
#             build/exe/gcc-linux-x86_64/release/test_openssl_posix_crypt
#
#         On MacOSX:
#             build/exe/clang-macosx-x86_64/release/test_openssl_posix_crypt


#pragma build project-root='..' output='build'
#pragma os:linux toolset module=gcc alias=sys:cc
#pragma os:linux default model=sys:cc
#pragma os:macosx toolset module=clang alias=sys:cc
#pragma os:macosx default model=sys:cc


module_type = 'executable'
module_name = 'test_openssl_posix_crypt'
include_dir_list = ['..']
src_search_dir_list = ['..']
build_list = ['main.c', 'openssl_posix_crypt.c']
prebuilt_lib_list_linux = ['crypto']
prebuilt_lib_list_macosx = ['crypto']
