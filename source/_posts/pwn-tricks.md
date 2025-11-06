---
title: pwn-tricks
date: 2024-07-01 17:37:24
cover: ../static/pwn_tricks/cover.png
categories:
    - CTF
tags:
    - pwn
    - trick
---
该文档主要收录一些我觉得讲的很好的一些关于pwn的trick<br />（为便于学习参与学习的大家可以在最后自增一列用于标记自己的学习进度，记录一下自己哪些是看过的了hhhhhhhhhhhhhhhhh）<br />

| tick name | url | keyboard看过了？ |
| --- | --- | --- |
| 堆漏洞挖掘中malloc_consolidate与FASTBIN_CONSOLIDATION_THRESHOLD | [https://blog.csdn.net/qq_41453285/article/details/97627411](https://blog.csdn.net/qq_41453285/article/details/97627411) | 1 |
| Glibc PWN“堆风水”应用详解 | [https://www.freebuf.com/vuls/235626.html](https://www.freebuf.com/vuls/235626.html) | 1 |
| 关于fastbin合并问题的研究 | [https://bbs.kanxue.com/thread-257742.htm](https://bbs.kanxue.com/thread-257742.htm) | 1 |
| PWN题目中malloc_consolidate()利用浅析  | [https://juejin.cn/post/6844903816031125518](https://juejin.cn/post/6844903816031125518) | 1 |
| the house of rabbit（超详细） | [https://bbs.kanxue.com/thread-280246.htm](https://bbs.kanxue.com/thread-280246.htm) | 0 |
| 堆喷射技术入门 | [https://segmentfault.com/a/1190000044165958](https://segmentfault.com/a/1190000044165958) | 1 |
| 堆喷思想在glibc pwn中的应用 | [https://xz.aliyun.com/t/7189?time__1311=n4%2BxnD0GDtKx9lDuDBqroGktkGQG8RSQmYeD&alichlgref=https%3A%2F%2Fwww.freebuf.com%2F](https://xz.aliyun.com/t/7189?time__1311=n4%2BxnD0GDtKx9lDuDBqroGktkGQG8RSQmYeD&alichlgref=https%3A%2F%2Fwww.freebuf.com%2F) | 1 |
| Heap Spray：高危漏洞的垫脚石 | [https://www.cnblogs.com/Fang3s/articles/3911561.html](https://www.cnblogs.com/Fang3s/articles/3911561.html) | 1 |
| TSCTF2019 薛定谔的堆块-HeapSpray | [https://pig-007.github.io/2021/08/18/TSCTF2019%20%E8%96%9B%E5%AE%9A%E8%B0%94%E7%9A%84%E5%A0%86%E5%9D%97-HeapSpray/#2-%E6%BC%8F%E6%B4%9E%E5%8F%91%E7%8E%B0%EF%BC%9A](https://pig-007.github.io/2021/08/18/TSCTF2019%20%E8%96%9B%E5%AE%9A%E8%B0%94%E7%9A%84%E5%A0%86%E5%9D%97-HeapSpray/#2-%E6%BC%8F%E6%B4%9E%E5%8F%91%E7%8E%B0%EF%BC%9A) | 1,考虑复现 |
| IO_FILE利用：利用_IO_2_1_stdout泄露libc | [https://blog.csdn.net/qq_41202237/article/details/113845320](https://blog.csdn.net/qq_41202237/article/details/113845320) | 1 |
| House of pig 原理详解&实战（高版本IO_FILE）--比较复杂的攻击 | [http://t.csdnimg.cn/axITU](http://t.csdnimg.cn/axITU) | 0，考虑复现 |
| Tcache Stashing Unlink Attack 原理详解 | [http://t.csdnimg.cn/vIJJP](http://t.csdnimg.cn/vIJJP) | 1 |
| Heap Exploit 2.31 | [https://github.com/StarCross-Tech/heap_exploit_2.31](https://github.com/StarCross-Tech/heap_exploit_2.31) | 0考虑复现 |
| glibc-2.31中的tcache stashing unlink与large bin attack | [http://t.csdnimg.cn/01drX](http://t.csdnimg.cn/01drX) | 1 |
| house of  banana | [https://www.anquanke.com/post/id/222948#h3-5](https://www.anquanke.com/post/id/222948#h3-5) | 0 |
| 浅入研究 tcache_perthread_struct | [https://blog.csdn.net/qq_29912475/article/details/134978851](https://blog.csdn.net/qq_29912475/article/details/134978851) | 1 |
| 通过mmap&mprotect来绕过nx | [http://t.csdnimg.cn/WgOng](http://t.csdnimg.cn/WgOng) | 1 |
| house of fmt 非栈上的fmt | [https://www.freebuf.com/vuls/284210.html](https://www.freebuf.com/vuls/284210.html) | 1 |
| [CTF]PWN--非栈上格式化字符串漏洞 | [http://t.csdnimg.cn/4sILP](http://t.csdnimg.cn/4sILP) | 1 |
| [CTF]PWN--手搓格式化字符串漏洞 | [https://blog.csdn.net/2301_79880752/article/details/136178764?spm=1001.2014.3001.5501](https://blog.csdn.net/2301_79880752/article/details/136178764?spm=1001.2014.3001.5501) | 1 |
| house of apple 1-2-3 | [https://bbs.kanxue.com/thread-273418.htm](https://bbs.kanxue.com/thread-273418.htm) | 1 |
| [house of kiwi](https://www.anquanke.com/post/id/235598) | [house of kiwi](https://www.anquanke.com/post/id/235598) | 1 |
| [house of emma](https://www.anquanke.com/post/id/260614) | [house of emma](https://www.anquanke.com/post/id/260614) | 1 |
| [house of pig](https://www.anquanke.com/post/id/242640) | [house of pig](https://www.anquanke.com/post/id/242640) | 1 |
| House of cat新型glibc中IO利用手法解析 && 第六届强网杯House of cat详解 | [https://bbs.kanxue.com/thread-273895.htm](https://bbs.kanxue.com/thread-273895.htm) | 0 |
| 堆利用详解：the house of storm | [https://bbs.kanxue.com/thread-280333.htm](https://bbs.kanxue.com/thread-280333.htm) | 0 |
| 深入理解Pwn_IO_FILE及相关赛题 | [https://bbs.kanxue.com/thread-279380.htm](https://bbs.kanxue.com/thread-279380.htm) | 1 |
| 深入理解Pwn_Heap及相关例题 | [https://bbs.kanxue.com/thread-278871.htm](https://bbs.kanxue.com/thread-278871.htm) | 1 |
| Tcache安全机制及赛题详细解析(gundam && House of Atum) | [https://bbs.kanxue.com/thread-278105.htm](https://bbs.kanxue.com/thread-278105.htm) | 0 |
| 第七届“湖湘杯” House _OF _Emma &#124; 设计思路与解析 | [https://www.anquanke.com/post/id/260614](https://www.anquanke.com/post/id/260614) | 1 |
| House OF Kiwi | [https://www.anquanke.com/post/id/235598](https://www.anquanke.com/post/id/235598) | 1 |
| 多手法联合IO利用之House of pig 学习利用 | [https://xz.aliyun.com/t/12916?time__1311=mqmhqIx%2BxkGNDQtPBKPAKY0KD%3DWDtes3C4D&alichlgref=https%3A%2F%2Fxz.aliyun.com%2Ft%2F12934%3Ftime__1311%3DmqmhqIx%252Bxfx0hxBqDTWxUE%253Dx9DAOq6rCoD%26alichlgref%3Dhttps%253A%252F%252Fcn.bing.com%252F](https://xz.aliyun.com/t/12916?time__1311=mqmhqIx%2BxkGNDQtPBKPAKY0KD%3DWDtes3C4D&alichlgref=https%3A%2F%2Fxz.aliyun.com%2Ft%2F12934%3Ftime__1311%3DmqmhqIx%252Bxfx0hxBqDTWxUE%253Dx9DAOq6rCoD%26alichlgref%3Dhttps%253A%252F%252Fcn.bing.com%252F) | 1 |
| glibc 2.31 pwn——house of pig原题分析与示例程序 | [http://t.csdnimg.cn/BiNVQ](http://t.csdnimg.cn/BiNVQ) | 1 |
| i春秋2020新春战役PWN之BFnote (修改TLS结构来bypass canary) | [http://t.csdnimg.cn/dC98r](http://t.csdnimg.cn/dC98r) | 1 |
| roarctf 2020 PWN 2a1---虚表指针加密问题 | [https://bbs.kanxue.com/thread-264469.htm](https://bbs.kanxue.com/thread-264469.htm) | 0 |
| 新版本glibc下的IO_FILE攻击 | [https://www.anquanke.com/post/id/216290](https://www.anquanke.com/post/id/216290) | 0 |
| 通过LIBC基址来爆破TLS | [https://blog.wjhwjhn.com/posts/%e9%80%9a%e8%bf%87libc%e5%9f%ba%e5%9d%80%e6%9d%a5%e7%88%86%e7%a0%b4tls/](https://blog.wjhwjhn.com/posts/%e9%80%9a%e8%bf%87libc%e5%9f%ba%e5%9d%80%e6%9d%a5%e7%88%86%e7%a0%b4tls/) | 0 |
| 从两道题目学习 exit_hook | [https://zhuanlan.zhihu.com/p/576942474](https://zhuanlan.zhihu.com/p/576942474) | 1 |
| malloc_printerr劫持 | [https://bbs.kanxue.com/thread-272471.htm#msg_header_h1_3](https://bbs.kanxue.com/thread-272471.htm#msg_header_h1_3) | 1 |
| house of husk | [https://www.anquanke.com/post/id/202387](https://www.anquanke.com/post/id/202387) | 1 |
| <br /> |  | <br /> |
| <br /> |  | <br /> |
| <br /> |  | <br /> |
| <br /> |  | <br /> |
| <br /> |  | <br /> |
| <br /> |  | <br /> |
| <br /> |  | <br /> |
| <br /> |  | <br /> |
| <br /> |  | <br /> |
| <br /> |  | <br /> |

