---
title: 西湖论剑 2024 个人题解
date: 2024-02-28 19:53:26
tags: [CTF]
categories: [技术]
---

![](Screenshot_20240228_195644.webp)

放寒假的时候被 [unknown](https://unk.org.cn/) 大佬拉去玩了！

<!-- more -->

# 西湖论剑 2024 个人题解

## Binary - MZ

通过大致阅读反编译代码，可大致得出以下理解结果。

![](Screenshot_20240203_222835.webp)

注：

1. 此处 table 的每个元素占用 4 bytes，反编译代码中的指针移动是 `1:1 byte`
2. table 中奇数位为 `int`，偶数位为 `int *`，反编译代码中的指针永远是一个 `int *`，并且指向的是 table 中的一个 `int` 元素，在每次校验完之后的 `tb_ptr` 移动操作是移动至 `cur` 在表中下一位的 `int *` 所指向的 `int` 元素。

其中这题比较特殊的一个地方是，它的表初始化代码是非连续的，大体上如下图

![](Screenshot_20240203_224729.webp)

因此通过手动编写的方案过于繁杂，需要通过调试抓取内存。

由于我此处使用的 Linux 系统，需要通过 Wine 进行调试，这里也给出相关的调试方法。

![](Screenshot_20240203_222142.webp)

通过 `winedbg` 的 `--gdb` 特性，可以使用 `gdb` 进行调试。

![](Screenshot_20240203_222707.webp)

在宿主机上，通过 `winedbg` 最后一行给出的指令连接上 `winedbg` 提供的 `gdb` 服务器。

在 `init_table` 函数中，找到相对应数据在内存中的开头的末尾地址（分别为 `0x439078` 和 `0x442cb4`）。

![](Screenshot_20240203_223023.webp)
![](Screenshot_20240203_223034.webp)

随后找到 `init_table` 函数调用的后一行指令，即 `0x434a80` 处，在此打断点，并抓取内存。

![](Screenshot_20240203_222918.webp)

![](Screenshot_20240203_223735.webp)

根据上文理解结果，编写代码（由于结果具有不确定性，因此编写了一个交互脚本进行操作）

```python
import string
import sys
from dataclasses import dataclass
from typing import Any, Generator

chars = string.ascii_letters + string.punctuation + string.digits


@dataclass(frozen=True)
class State:
    char: int
    nextpos: int


def try_next(data: list[int] | bytes, state: State | None = None) -> Generator[State, None, None]:
    offset = state.nextpos if state else 0
    for char in chars:
        try:
            code = ord(char)
            cur = data[offset + code * 2]
            if code - 5 == cur or code + 5 == cur:
                pos = data[offset + code * 2 + 1]
                yield State(code, pos)
        except Exception:
            pass


def step_forward(data: list[int] | bytes, step: int, state: State | None = None) -> list[Any]:
    assert step > 0, "step should be greater than 0"
    probable = list(try_next(data, state))
    if step == 1:
        return probable
    result: list[Any] = []
    for state in probable:
        result.append((state, step_forward(data, step - 1, state)))
    return result


def flatten_steps(steps: list[Any]) -> list[list[State]]:
    def chain_gather(
        parent: list[State], child: State | tuple[State, list[Any]]
    ) -> list[list[State]]:
        if isinstance(child, State):
            return [parent + [child]]
        chains: list[list[State]] = []
        for node in child[1]:
            chains += chain_gather(parent + [child[0]], node)
        return chains

    chains: list[list[State]] = []
    for rsteps in steps:
        chains += chain_gather([], rsteps)
    return chains


def subtract_base(data: list[int] | bytes, base: int) -> list[int]:
    return [(b - base) // 4 if i % 2 else b for i, b in enumerate(data)]


assert len(sys.argv) == 3, "too few or too many arguments."
_, file, base = sys.argv
base = int(base, base=0)

with open(file, "rb") as fp:
    mem = fp.read()

data = [int.from_bytes(mem[i : i + 4], "little", signed=False) for i in range(0, len(mem), 4)]
data = subtract_base(data, base)

history: list[State] = []

while True:
    s = bytes(state.char for state in history).decode()
    print(f"current: {s}")
    print("type index to choose the solution:")
    print("1. try next")
    print("2. step forward")
    print("3. move backward")
    try:
        index = int(input("choice: "))
    except ValueError:
        print("invalid choice.")
        continue
    match index:
        case 1:
            last = history[-1] if history else None
            probable = list(try_next(data, last))
            if not probable:
                print("no char available, try to move backward.")
                continue
            if len(probable) == 1:
                history.append(probable[0])
                continue
            print("choose the combination:")
            print(
                "\n".join(
                    f"{i}. {s}{state.char.to_bytes().decode()}"
                    for i, state in enumerate(probable, 1)
                )
            )
            try:
                choice = int(input("choice: "))
            except ValueError:
                print("invalid choice.")
                continue
            if choice < 1 or choice > len(probable):
                print("choice is out of range.")
                continue
            history.append(probable[choice - 1])
        case 2:
            last = history[-1] if history else None
            try:
                step = int(input("step: "))
            except ValueError:
                print("invalid step.")
                continue
            chains = flatten_steps(step_forward(data, step, last))
            if not chains:
                print("no result available, try to move backward.")
                continue
            if len(chains) == 1:
                history += chains[0]
                continue
            print("choose the combination:")
            for i, chain in enumerate(chains, 1):
                cur = bytes(state.char for state in chain).decode()
                print(f"{i}. {s}{cur}")
            try:
                choice = int(input("choice: "))
            except ValueError:
                print("invalid choice.")
                continue
            if choice < 1 or choice > len(chains):
                print("choice is out of range.")
                continue
            history += chains[choice - 1]
        case 3:
            history.pop()
        case _:
            print("choice is out of range.")
```

通过调用脚本，逐步尝试出最终结果（此处并未编写对 SHA-1 结果的校验）

![](Screenshot_20240203_223821.webp)

![](Screenshot_20240203_224046.webp)


## Misc - easy_rawraw

对于没有接触过内存取证的我来说，看到 raw 我只能联想到 Disk RAW Image (硬盘镜像)，也确实在 DiskGenius 的修复进行下能够修复出来部分东西，我也找到了关键的加密工具 `veracrypt` 字样。

随后也没什么思路，便去网上一找，发现这是 DASCTF 的过往出题手法，也就是内存取证，其中需要用到工具 ***volatility***，我在这里使用了其后继者 *volatility3* 进行操作。

通过 `vol -f rawraw.raw windows.pslist.PsList` 获取进程列表。

![](2cd16821-4ad5-48ab-99f5-14f5fcf0d2f4.webp)

可以看到几个关键进程：

- `VeraCrypt.exe`: 用于加密磁盘/磁盘映像
- `WinRAR.exe`: 可以推测存在并且打开了压缩包文件
- `DumpIt.exe`: 用于生成该 raw 文件

通过 `vol -f rawraw.raw windows.filescan.FileScan` 可以搜索到对应的 zip 文件。

![](17e8f461-d72b-4229-ba44-5c3d0367e4f5.webp)

再通过 `vol -f rawraw.raw windows.dumpfiles.DumpFiles --physaddr 0x3df8b650` 把文件给 dump 出来。

![](9f7fe058-9c3f-433c-9c17-1fb21a51649f.webp)

可以得到一个 *pass.webp* 文件。

![](e66dfc27-1163-42e9-ac2c-bf306626af19.webp)

对该 *pass.webp* 文件进行 *binwalk* 可得到其中隐写着 zip 文件。

![](Screenshot_20240228_192903.webp)

该 zip 文件也可以通过 `vol -f rawraw.raw windows.memmap.Memmap --pid 2088 --dump` 在 `WinRAR.exe` 进程中给 dump 出来。

该 zip 需要密码，使用 *john* 带上 *rockyou.txt* 即可 brute 出来。

![](9900c138-b438-4bcc-ac9b-c8d078dc4840.webp)

里面的 *pass.txt* 文件直接打开也没什么用处。

对 raw 文件进行 `strings rawraw.raw | grep password` 可以找到 rar 密码。

![](58fd95e4-639b-499e-8fc0-c68e7d35263f.webp)

使用刚才的 *pass.txt* 作为 veracrypt 的 keyfile 对刚刚解压出的 mysecretfile 即可挂载上磁盘映像。

![](f47f4790-7cae-4e81-8a4b-a2bbdf643b6e.webp)

可看到里面含有 *data.xlsx* 文件

![](e8f215a3-ac34-4fc7-877e-9ec334281041.webp)

打开发现需要密码，不过我到此就没想到方法来获取了（x

## Misc - easy_tables

看懂题和给出来的样例就能写出来了，直接贴代码（x

```python
from dataclasses import dataclass
from datetime import datetime, time
from hashlib import md5
from pathlib import Path
from typing import Callable, Generator, Iterable, TypeVar, cast


T = TypeVar("T")
DT = TypeVar("DT")


@dataclass
class Action:
    id: int
    name: str
    time: datetime
    statement: str


@dataclass
class User:
    id: int
    name: str
    password: str
    group: int


@dataclass
class Group:
    id: int
    name: str
    allowed_action: list[str]
    tables: list[int]


@dataclass
class Table:
    id: int
    name: str
    allowed_range: list[tuple[time, time]]

    def is_allowed(self, t: time) -> bool:
        for r in self.allowed_range:
            if r[0] <= t <= r[1]:
                return True
        return False


def extract_action_name_unchecked(statement: str) -> str:
    return statement.split()[0]


def extract_target_table_unchecked(statement: str) -> str:
    it = iter(statement.split())
    for word in it:
        if word.upper() in ["FROM", "INTO", "UPDATE"]:
            break
    return next(it)


def extract_csv_items(line: str) -> Generator[str, None, None]:
    assert "\n" not in line and "\r" not in line, "newline char is not allowed in line."
    cur = ""
    quote = False
    for c in line:
        if not quote and c == ",":
            yield cur
            cur = ""
        elif c == "\"":
            quote = not quote
        else:
            cur += c
    assert not quote, "quote has not closed."
    yield cur


def read_actionlog(data: str) -> Generator[Action, None, None]:
    for line in data.splitlines()[1:]:
        items = list(extract_csv_items(line))
        yield Action(
            int(items[0]),
            items[1],
            datetime.strptime(items[2], "%Y/%m/%d %H:%M:%S"),
            items[3],
        )


def read_groups(data: str) -> Generator[Group, None, None]:
    for line in data.splitlines()[1:]:
        items = list(extract_csv_items(line))
        yield Group(
            int(items[0]),
            items[1],
            items[2].split(","),
            list(map(int, items[3].split(","))),
        )


def read_users(data: str) -> Generator[User, None, None]:
    for line in data.splitlines()[1:]:
        items = list(extract_csv_items(line))
        yield User(
            int(items[0]),
            items[1],
            items[2],
            int(items[3]),
        )


def read_tables(data: str) -> Generator[Table, None, None]:
    for line in data.splitlines()[1:]:
        items = list(extract_csv_items(line))
        yield Table(
            int(items[0]),
            items[1],
            [
                cast(
                    tuple[time, time],
                    tuple(datetime.strptime(t, "%H:%M:%S").time() for t in r.split("~"))
                )
                for r in items[2].split(",")
            ],
        )


def first(iterable: Iterable[T], cond: Callable[[T], bool], default: DT = None) -> T | DT:
    for item in iterable:
        if cond(item):
            return item
    return default


load_from = Path("/path/to/easy_tables附件/")

with open(load_from / "users.csv") as fp:
    users = list(read_users(fp.read()))

with open(load_from / "tables.csv") as fp:
    tables = list(read_tables(fp.read()))

with open(load_from / "permissions.csv") as fp:
    groups = list(read_groups(fp.read()))

with open(load_from / "actionlog.csv") as fp:
    actions = list(read_actionlog(fp.read()))


exps = list[tuple[int, int, int, int]]()

for action in actions:
    user = first(users, lambda it: it.name == action.name)
    if not user:
        exps.append((0, 0, 0, action.id))
        continue
    action_name = extract_action_name_unchecked(action.statement)
    table_name = extract_target_table_unchecked(action.statement)
    group = first(groups, lambda it: it.id == user.group)
    table = first(tables, lambda it: it.name == table_name)
    assert group and table, "group and table is not allowed to be None."
    if (
        table.id not in group.tables or
        action_name not in group.allowed_action or
        not table.is_allowed(action.time.time())
    ):
        exps.append((user.id, group.id, table.id, action.id))

exps.sort()
result = ",".join(("_".join(map(str, exp)) for exp in exps))
print(result)
print(md5(result.encode()).hexdigest())
```
