---
title: 在 Ghidra 通过 Wine 调试 Win32 应用
date: 2024-03-23 10:19:39
updated: 2024-03-24 21:25:30
tags: [Ghidra, Wine, Win32, 调试, 逆向]
categories: [技术]
---

Ghidra 作为一个跨平台的逆向工具，可以在 Linux 上运行，也支持 Win32 应用的反编译。如果要调试 Win32 应用，那可就麻烦了。Win32 应用可没法支持跑在 Linux 上，但可以借助 Wine 运行。

那么这篇文章将介绍 Win32 应用在 Ghidra 上调试的方法、各种问题以及解决方案。

<!-- more -->

## 在 Linux 编译一个 Win32 应用

随便写点代码吧（

```c
#include <stdio.h>
#include <string.h>

int main() {
    char buf[50];
    printf("type anything you want:\n");
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\r\n")] = 0;
    printf("you typed: %s\n", buf);
    return 0;
}
```

在这命名为 `foo.c`，使用系统包管理器提供的 mingw32 跨平台编译器进行编译，此处以 openSUSE Tumbleweed 为例。

```shell
x86_64-w64-mingw32-gcc foo.c -o foo.exe
```

验证一下编译出来的 Win32 应用是否能执行。

```shell
wine foo.exe
```

![](Screenshot_20240323_103557.webp)

## 在 Wine 上启动 GDB 服务器

通过包管理器安装用于运行在 Wine 上的 GDB，以 openSUSE Tumbleweed 为例，需要添加源 `windows:mingw:win64`，后安装 `mingw64-gdb`。

此处可借助工具 [opi (OBS Package Installer)](https://github.com/openSUSE/opi) 进行安装。

```shell
sudo opi mingw64-gdb
```

![](Screenshot_20240323_104155.webp)

安装完成后，可通过指令:

```shell
wine /usr/x86_64-w64-mingw32/sys-root/mingw/bin/gdbserver.exe :<port> <binary>
```

对目标 Win32 应用启动 GDB 服务器。

![](Screenshot_20240323_104841.webp)

## 在 Ghidra 调试器进行调试

在 Ghidra 调试器窗口左上角处的 *Debugger Targets* 窗口点击 *Create a new connection to a debugging agent*，如图所示位置:

![](Screenshot_20240323_105439.webp)

选择 *gdb via GADP*（建议，下文以 *gdb via GADP* 模式进行调试）或 *gdb*（不建议）。

![](Screenshot_20240323_105932.webp)

部分发行版所提供的 `gdb` 可能不支持多平台调试，如 Debian / Ubuntu 需要使用 `gdb-mingw-w64` 包所提供的 `i686-w64-mingw32-gdb` 及 `x86_64-w64-mingw32-gdb` 进行调试，需要修改 *GDB launch command*。

此处 openSUSE Tumbleweed 提供的 `gdb` 支持多平台调试，无需修改。

连接 GDB 成功后，在右侧工作区的窗口中会有新建的 *Interpreter* 窗口，在里面执行 GDB 指令。

![](Screenshot_20240323_110902.webp)

```gdb
file /path/to/foo.exe
target remote :<port>
```

即可完成读取可执行文件及连接在 Wine 启动的 GDB 服务器。

但是会发现在 *Interpreter* 窗口出现了报错:

> Not supported on this target.

![](Screenshot_20240323_111143.webp)

发生了什么事呢？简单来说，Ghidra 依赖于 GDB 指令 `info proc mappings` 来确定可访问的内存区域，但 GDB 并没有在 Windows 上实现这个指令。

## 解决 mappings 问题

虽然说 Windows 上没有实现这个指令，但我们可以实现一个。

在 Wine 上的一个进程是可以对应到 Linux 的一个进程的，而 Linux 的 procfs 中提供了 maps 文件，同样可以用来获取 `info proc mappings` 相关的信息。

于是此处可以借用 Ghidra 内置的 GDB Python 脚本 `remote-proc-mappings.py` 实现对指定 PID 的进程以 `info proc mappings` 格式输出对应的 maps。

脚本位置通常位于 `<Ghidra 根目录>/Ghidra/Debug/Debugger-agent-gdb/data/scripts/remote-proc-mappings.py`

此外，需要编写一个脚本用于获取进程的 PID，虽然 Ghidra 提供了脚本 `getpid-linux-i386.gdb`，但其文档写着:

```
# Note that binaries linked with non-executable stacks, such as those
# created by the `-z,noexecstack` or `/NXCOMPAT` options, should replace
# `($esp-7)` with an address that will be mapped to an executable region.
# Selection of such an address is platform- and binary-specific.
```

可见该脚本适用范围非常有限。

### 通过程序名获取

换一种思路，通过 `top` 可以查看到，所要调试的可执行文件的 *cmdline* 就是可执行文件的位置，虽然不太可靠，但可以根据这一点进行编写脚本:

```python
import contextlib
import psutil
from pathlib import Path

class GetWinePid(gdb.Command):
    def __init__(self):
        super(GetWinePid, self).__init__("get-wine-pid", gdb.COMMAND_STATUS)

    def invoke(self, arg, from_tty):
        if len(arg):
            return gdb.write("usage: get-wine-pid\n", gdb.STDERR)
        objs = gdb.objfiles()
        exe = Path(next(filter(lambda obj: obj.filename.endswith(".exe"), objs)).filename)
        for process in psutil.process_iter():
            with contextlib.suppress(psutil.Error):
                cmdline = process.cmdline()
                if not cmdline:
                    continue
                current = Path(cmdline[0].replace("\\", "/").strip())
                if current.parts[0].endswith(":"):
                    current = "/" / current.relative_to(current.parts[0])
                part_length = len(current.parts)
                if current.parts == exe.parts[-part_length:]:
                    return gdb.write(str(process.pid))

GetWinePid()
```

将其保存于 `~/ghidra/get-wine-pid.py`。

后可根据 `wine32_info_proc_mappings.gdb` 脚本编写出用于 Wine 的 `info proc mappings` 指令:

```gdb
source /usr/lib64/ghidra/Ghidra/Debug/Debugger-agent-gdb/data/scripts/remote-proc-mappings.py
source ~/ghidra/get-wine-pid.py

define info proc mappings
  python
remote_pid = gdb.execute("get-wine-pid", to_string=True).strip()
gdb.execute("remote-proc-mappings {}".format(remote_pid))
  end
end
```

将其保存于 `~/ghidra/wine.gdb`。

回到 Ghidra，在 *Interpreter* 窗口中执行指令:

```gdb
file /path/to/foo.exe
source ~/ghidra/wine.gdb
target remote :<port>
```

你能发现 Ghidra 能正常进行调试工作了，*Interpreter* 也没出现相关的报错。

![](Screenshot_20240323_114137.webp)

至此，你可以在 Ghidra 上通过 Wine 调试 Win32 应用了。

### 对 .text 头部进行 Patch

这一部分其实是后面补充更新的，根据 John Millikin 老师的文章（见后记）给出的第二个方案，通过对在 `.text` 中未使用的空区域 / 错误处理分支把下面指令 Patch 上调用 `sys_getpid` 指令执行并读取:

```asm
MOV eax, 20  ; SYS_getpid
INT 0x80
RET
```

在 Win32 应用上 `.text` **通常**是固定的 offset，此处可将 i386 的 Patch 在 `0x401020` 上（John Millikin 老师的文章中给出的数据），而 amd64 的可以 Patch 在 `0x140002000` 上（经过我自己测试出来的数据）。

因此，可针对 i386 及 amd64 可分别定义出两个指令:

```gdb
define getpid-linux-i386
  set $linux_getpid = {int (void)}0x401020
  set {unsigned char[8]}($linux_getpid) = {\
    0xB8, 0x14, 0x00, 0x00, 0x00, \
    0xCD, 0x80, \
    0xC3 \
  }
  output $linux_getpid()
  echo \n
end

define getpid-linux-amd64
  set $linux_getpid = {int (void)}0x140002000
  set {unsigned char[8]}($linux_getpid) = {\
    0xB8, 0x14, 0x00, 0x00, 0x00, \
    0xCD, 0x80, \
    0xC3 \
  }
  output $linux_getpid()
  echo \n
end
```

将其保存于 `~/ghidra/get-wine-pid.py`。

分别编辑出适用于 i386 及 amd64 的脚本:

```gdb
source ~/ghidra/getpid-linux.gdb
source /usr/lib64/ghidra/Ghidra/Debug/Debugger-agent-gdb/data/scripts/remote-proc-mappings.py

define info proc mappings
  python
remote_pid = gdb.execute("getpid-linux-i386", to_string=True).strip()
gdb.execute("remote-proc-mappings {}".format(remote_pid))
  end
end
```

将其保存于 `~/ghidra/wine-i386.gdb`。

```gdb
source ~/ghidra/getpid-linux.gdb
source /usr/lib64/ghidra/Ghidra/Debug/Debugger-agent-gdb/data/scripts/remote-proc-mappings.py

define info proc mappings
  python
remote_pid = gdb.execute("getpid-linux-amd64", to_string=True).strip()
gdb.execute("remote-proc-mappings {}".format(remote_pid))
  end
end
```

将其保存于 `~/ghidra/wine-amd64.gdb`。

参照上一种方法进行对 GDB 脚本文件的引用，根据实际架构配合使用。

## 后记

### 2024-03-23

鉴于我在 Linux 上进行 Win32 应用调试的需求，我找到了 John Millikin 老师的文章 *[Debugging Win32 binaries in Ghidra via Wine](https://john-millikin.com/debugging-win32-binaries-in-ghidra-via-wine)*。前前后后尝试了几次，还怀疑是不是发行版提供的 GDB 有问题，在 target attach 之后显示无法访问对应内存区域。直到我发现了这个脚本在 Ghidra 并入了主分支后写的文档标注才发现适用范围非常有限。

于是自己尝试写一个脚本直接通过进程的 *cmdline* 信息获取 PID 去 `remote-proc-mappings`，发现是可行的，于是写了这篇文章记录一下。

### 2024-03-24

在写完这篇文章后，我又在好奇，是不是因为 i386 和 amd64 的 `.text` 在内存 / 寄存器上区域 / 行为不同导致的原脚本无法使用。

然后我自己去手动调试了一下，发现 amd64 上 `.text` 头部在内存的区域位于 `0x140002000`，看了一下那块地方基本上都是 `NOP` 或者 Undefined Function 区域，就尝试了一下 John Millikin 老师的第二种解决方案，把他上面写的地址数据改成了 `0x140002000` 测试了一下，发现确实可行，于是更新了这篇文章。
