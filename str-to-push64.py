#!/usr/bin/env python3
import sys
import struct


def slice(target_str, size_of_slice):
    l = []
    for i in range(0, len(target_str), size_of_slice):
        l.append(target_str[i:i+size_of_slice])

    return l

def main():
    if len(sys.argv) != 2:
        print('Usage: {0} <string-to-encode>'.format(sys.argv[0]))
        return 1

    target_str = sys.argv[1]
    padding_size = (8 - len(target_str) % 8) % 8
    target_str = ('A' * padding_size) + target_str

    instructions = []

    for word in slice(target_str, 8):
        value = struct.unpack('<Q', word.encode())[0]
        instr = 'mov rax, {0}\n'.format(hex(value))
        instr += 'push rax'
        instructions.append(instr)

    print('xor rax, rax')
    print('push rax')
    for instr in instructions[::-1]:
        print(instr)

    print('mov rax, rsp')

    if padding_size != 0:
        print('add rax, {0}'.format(hex(padding_size)))


if __name__ == '__main__':
    ret = main()
    sys.exit(ret)
