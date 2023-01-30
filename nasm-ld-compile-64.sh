#!/bin/sh

src_file=$1
src_file_no_extension=$(echo "${src_file%.*}")

if [ -f "$src_file_no_extension.o" ]; then
    rm "$src_file_no_extension.o"
fi

if [ -f $src_file_no_extension ]; then
    rm "$src_file_no_extension"
fi

nasm -f elf64 $src_file -o "$src_file_no_extension.o" || exit
ld -m elf_x86_64 "$src_file_no_extension.o" -o $src_file_no_extension || exit
