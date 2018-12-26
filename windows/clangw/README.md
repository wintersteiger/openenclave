clangw - clang compiler wrapper
================

This directory contains the source code for clang compiler wrapper.
The wrapper takes in a mix of msvc and gcc command line options,
transforms them and calls clang to cross-compile and generate elf
enclaves.

clangw is a workaround due to using nmake/visual studio generators
on windows which result in a mix of msvc/gcc command line options
for compiling enclaves.

clangw is similar to clang-cl. clang-cl, however, cannot be used to
cross-compile and does not support a mix of options.
