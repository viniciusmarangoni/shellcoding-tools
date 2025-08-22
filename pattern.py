#!/usr/bin/env python3
import sys
import string


MAX_PATTERN_LENGTH = 20276


def pattern_create():
    full_pattern = ''
    for upper in string.ascii_uppercase:
        for lower in string.ascii_lowercase:
            for digit in string.digits:
                full_pattern += upper + lower + digit

    return full_pattern


def pattern_find(pattern):
    full_pattern = pattern_create()
    return full_pattern.find(pattern)


def print_usage():
    print('Usage: python3 {0} <length | pattern> [padding-length]\n'.format(sys.argv[0]))
    print('Examples:\n')
    print('\tCreate a pattern with 100 bytes')
    print('\tpython3 {0} 100\n'.format(sys.argv[0]))

    print('\tCreate a pattern with 100 bytes, prepending a padding of 3000 bytes')
    print('\tpython3 {0} 100 3000\n'.format(sys.argv[0]))

    print('\tSearch for pattern when EIP=33674332')
    print('\tpython3 {0} 0x33674332\n'.format(sys.argv[0]))

    print('\tSearch for pattern when EIP=33674332 and when you used a padding of 3000 bytes')
    print('\tpython3 {0} 0x33674332 3000\n'.format(sys.argv[0]))
    print('\n')


def main():
    if len(sys.argv) < 2:
        print_usage()
        return 1

    padding = ''
    if len(sys.argv) > 2:
        if sys.argv[2].isdigit():
            padding = 'A' * int(sys.argv[2])

        else:
            print_usage()
            return 1


    if sys.argv[1].isdigit():
        pattern_lenth = int(sys.argv[1])

        if pattern_lenth > MAX_PATTERN_LENGTH:
            print('Maximum pattern length is {0}'.format(MAX_PATTERN_LENGTH))
            return 1

        full_pattern = pattern_create()
        print(padding + full_pattern[:pattern_lenth])
    
    elif sys.argv[1].lower().startswith('0x'):
        pattern = sys.argv[1][2:]

        little_endian_pattern = bytes.fromhex(pattern)[::-1].decode()

        full_pattern = padding + pattern_create()
        index = full_pattern.find(little_endian_pattern)
        if index == -1:
            print('Pattern not found')

        else:
            print('Found after {0} bytes'.format(index))

    else:
        print_usage()
        return 1

    return 0


if __name__ == '__main__':
    ret = main()
    sys.exit(ret)
