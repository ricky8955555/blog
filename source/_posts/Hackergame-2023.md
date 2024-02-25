---
title: Hackergame 2023 总结 + 个人题解
date: 2023-11-05 15:22:07
updated: 2024-02-25 09:37:10
tags: [CTF]
categories: [其他]
---

![](hgys-bg.webp)

Hackergame 启动！Hackergame 关闭！

<!-- more -->

Hackergame 算是我第一次正经参与 CTF 比赛。本来就抱着试着玩玩的心态去参与的~~（然后没想到越玩越起劲）~~，实际上自己对计算机很多知识都是一直半解，在玩的过程中遇到了不少的困难，但是感谢现在搜索引擎以及机器学习的强大，了解到了许多未曾听闻的知识，感谢 Hackergame 让我学到了这么多东西w。

![](Screenshot_20231105_154014.webp)

但最后我拿到了 4200 分，总排名 98 / 2381 是我完全没想到的（x

# 个人题解

## 🌐 Hackergame 启动

最最最简单的一题x

我在做这题的时候压根没录音就提交上去了，然后看到了 URL 多了个 `?similarity=` 参数，然后我就瞎摸着传入个 `100`，然后就出现仿某神的界面了（

![](Screenshot_20231105_154706.webp)


## 💻 猫咪小测

搜集资料的问答题x

### 第一问

> 1. 想要借阅世界图书出版公司出版的《A Classical Introduction To Modern Number Theory 2nd ed.》，应当前往中国科学技术大学西区图书馆的哪一层？**（30 分）**

看到 **中国科学技术大学西区图书馆**，我便第一时间想到去寻找中科大的图书馆官网。通过搜索引擎也确实找到了。

接下来便是要利用官网的检索系统进行书籍检索了，但是搜索的时候不能直接复制粘贴（因为有可能图书的命名不太一样），通过检索关键词 `A Classical Introduction To Modern Number Theory` 便能检索到该书籍在中科大图书馆的分类及编号。

![](Screenshot_20231105_155823.webp)
![](Screenshot_20231105_155954.webp)
![](Screenshot_20231105_160207.webp)

可以看到下方写着该书籍馆藏于 *西区外文书库*，但显然作为校外人员的我没法知道 *西区外文书库* 在哪。

返回到主页，可以注意到导航栏 *本馆概况* 下有栏目 [*馆藏分布*](https://lib.ustc.edu.cn/%e6%9c%ac%e9%a6%86%e6%a6%82%e5%86%b5/%e9%a6%86%e8%97%8f%e5%88%86%e5%b8%83/)，在里面便能轻松找到 *西区外文书库* 的楼层为 **12** 楼。

![](Screenshot_20231105_161228.webp)
![](Screenshot_20231105_160913.webp)

于是得到第一题的答案：`12`。

### 第二问

> 2. 今年 arXiv 网站的天体物理版块上有人发表了一篇关于「可观测宇宙中的鸡的密度上限」的论文，请问论文中作者计算出的鸡密度函数的上限为 10 的多少次方每立方秒差距？**（30 分）**

~~感谢 Hackergame 让我知道了 arXiv 这个论文档案库（~~

进入 [arXiv](https://arxiv.org) 后，检索 *可观测宇宙中的鸡的密度上限* 论文，但显然不能直接搜索中文，于是我利用我贫穷的英语知识大概提炼了一下关键词 `
chicken density universe`，于是搜索到了题为 [*Nuggets of Wisdom: Determining an Upper Limit on the Number Density of Chickens in the Universe*](https://arxiv.org/abs/2303.17626) 的论文。

![](Screenshot_20231105_162357.webp)

通过查看论文的 *Abstract*（~~抽象~~ 概要）部分，可以快速地找到关键词 *upper limit* 以及对应的数量级 **1e23**。

于是得到第二题的答案：`23`。

### 第三问

> 3. 为了支持 TCP BBR 拥塞控制算法，在**编译** Linux 内核时应该配置好哪一条内核选项？（20 分）

依旧依靠搜索引擎的强大能力（因为自己对 Linux 内核编译以及 BBR 不太了解），通过关键词 `linux kernel tcp bbr congestion control` 在搜索引擎搜索，可以找到对应的指导文章。

![](Screenshot_20231105_163225.webp)
![](Screenshot_20231105_163708.webp)

不难发现对应的参数说明，但此处有两个参数，题目只需要一个，便拿出了最贴切题目 *TCP BBR 拥塞控制算法* 的 **CONFIG_TCP_CONG_BBR** 作为尝试，最终答案也的确是这个。

于是得到第三题的答案：`CONFIG_TCP_CONG_BBR`。

### 第四问

> 4. 🥒🥒🥒：「我……从没觉得写类型标注有意思过」。在一篇论文中，作者给出了能够让 Python 的类型检查器 ~~MyPY~~ mypy 陷入死循环的代码，并证明 Python 的类型检查和停机问题一样困难。请问这篇论文发表在今年的哪个学术会议上？**（20 分）**

依旧依靠搜索引擎的强大能力（

提炼关键词 `Python 类型检查 停机问题` (`python type checking halting problem`)，最终可以定位到一篇名为 [*Python type hints are Turing complete*](https://arxiv.org/abs/2208.14755) 的论文。

再以论文标题作为检索词扔进搜索引擎搜索，最终可定位到这篇论文与 *ECOOP 2023* 相关，再进一步资料搜索，可以了解到 ***ECOOP*** 全名 *European Conference on Object-Oriented Programming*，可确定这是一场学术会议。

![](Screenshot_20231105_164941.webp)
![](Screenshot_20231105_165104.webp)

于是得到第三题的答案：`ECOOP`。

## 🌐 更深更暗

~~♪ 悲しみの海に沈んだ私~~

这道题你是不能直接通过滑动网页划到底的~~（因为是个无底深渊~~，但实际上也很简单。

> 我刚刚有一瞬间好像在残骸上看到了一个 flag？

这道题只要通过审查元素/检查功能，根据题目说的，找到最底下的元素 id 为 `titan` 残骸，把它展开就能看到 flag 了。

![](Screenshot_20231105_170520.webp)

## 💻 旅行照片 3.0

~~一年一度的开盒题！（bushi~~

一开始想用 EXIF 解题的（但发现压根就没有x），然后只能一点点地从字里行间以及图片细节提取信息了（这道题应该做了两三天了x）。

### 神秘奖牌

![](travelling-01.webp)

通过 Google Lens 等识图技术，或者将奖牌四周的文字一检索可以很快地找到这是一个诺贝尔奖牌，同时也能看到获奖人为 ***M. KOSHIBA***。

![](Screenshot_20231105_171136.webp)

进一步检索可以找到获奖人全名为 *小柴昌俊（Masatoshi Koshiba）*，生前工作于 *東京大学（东京大学, The University of Tokyo）*。

> 2、在学校该展厅展示的所有同种金色奖牌的得主中，出生最晚者获奖时所在的研究所缩写是什么？

通过第二题的任务驱动，再根据 *在校园的一个展厅内，你发现了一枚神秘的金色奖牌* 可猜测这枚奖牌位于 東京大学 某个展厅内。

于是我在搜索引擎上检索 `東京大学 ノーベル賞 展示`（`东京大学 诺贝尔奖 展示`），便找到了需要的获奖者信息（甚至那个页面已经给出了出生年份了）。

![](Screenshot_20231105_173221.webp)

经过对比可以看到出生最晚者名为 *梶田隆章（Takaaki Kajita）*，从介绍中可看到其身份为 *宇宙線研究所教授*。通过检索 `東京大学宇宙線研究所`，不难找到它的简称为 ***ICRR***。

![](Screenshot_20231105_173744.webp)

于是得到第二题的答案：`ICRR`

![](travelling-02.webp)

看到第二张图片，以及文中提到 *学长（下图左一）与你分享了不少学校的趣事*，可以注意到图片中哪位是学长，以及学长挂的牌子上面赫然写着 **STATPHYS28**。

![](Screenshot_20231105_174334.webp)

通过检索可以发现这是一个国际学术活动，也能推断出学长当日是在参加该活动。

> 1、你还记得与学长见面这天是哪一天吗？（格式：yyyy-mm-dd）

进入 [*STATPHYS28* 官网](https://statphys28.org) 可以看到活动时间为 *August 7th-11th, 2023*。

![](Screenshot_20231105_175216.webp)

因此 *2023-08-07* 到 *2023-08-11* 都尝试一下就好了，最后可以发现答案为 ***2023-08-10***。

于是得到第一题的答案：`2023-08-10`

### 这是什么活动？

![](travelling-03.webp)

> 当你们走到一座博物馆前时，马路对面的喷泉和它周围的景色引起了你的注意。下午，白色的帐篷里即将举办一场大型活动，人们忙碌的身影穿梭其中，充满了期待与热情。

看到这图我立刻扔给 Google Lens 了（x

![](Screenshot_20231105_180116.webp)

大致地信息处理后，可了解到拍摄地为 *上野恩賜公園（上野恩赐公园, Ueno Park）*。

> 3、帐篷中活动招募志愿者时用于收集报名信息的在线问卷的编号（以字母 S 开头后接数字）是多少？

但在这步之后我锁定的地方错了，因为通过检索，我了解到了 *上野の森美術館（上野之森美术馆, The Ueno Royal Museum）* 位于 *上野恩賜公園*，里面也有符合对应时间段的展览 *日本の自然を描く展* 以及 *野田哲也の版画―Ⅲ～静かなるもの～*，锁定在这里面已经是有一两天的时间了，但我费尽九牛二虎之力也没法找到对应的志愿者招募信息，于是放弃锁定 *上野の森美術館*。

![](Screenshot_20231105_181410.webp)

后面就以 `上野恩賜公園 8月10日` 作为关键词进行检索，便找到了 *全国梅酒まつりin東京2023* 的活动。

![](Screenshot_20231105_181836.webp)

根据网站的链接找到了其 [官网](https://umeshu-matsuri.jp)，经过内容阅读，可以发现网页底部有志愿者招募（*ボランティアSTAFF募集*）信息链接，里面也有问题所需的问卷调查编号 **S495584522**。

![](Screenshot_20231105_182051.webp)
![](Screenshot_20231105_182308.webp)

于是得到第三题的答案：`S495584522`

> 4、学长购买自己的博物馆门票时，花费了多少日元？

其实这道题我并没有真正地做出来，因为我理解错了，我以为是参与 *全国梅酒まつりin東京2023* 活动所需要的金额。

由于尝试了上面所述金额没有以后，随便试了个 0 就过了x。

![](Screenshot_20231105_182824.webp)

这题我的解题方法并没有参考价值，所以不加赘述，建议查看 [官方题解](https://github.com/USTC-Hackergame/hackergame2023-writeups/tree/master/official/%E6%97%85%E8%A1%8C%E7%85%A7%E7%89%87%203.0)。

### 后会有期，学长！

#### 第五题

> 5、学长当天晚上需要在哪栋标志性建筑物的附近集合呢？（请用简体中文回答，四个汉字）

根据文字描述 *学长那天晚上将继续他的学术之旅，打算乘船欣赏东京的迷人夜景和闪耀的彩虹大桥（Rainbow Bridge）*，结合上面分析到学长很可能参与的 *STATPHYS28* 活动，再次进入 *STATPHYS28* 官网了解详情。

##### 错误的方向

不难发现在 *STATPHYS28* 官网的导航栏，*Events* 下有栏目 [*Social Programs and Visits*](https://statphys28.org/socialprogram.html)。

![](Screenshot_20231105_185000.webp)

但发现符合条件的只有 *Tokyo Night View Tours* 活动，所述内容并不符合题目所说的 *乘船欣赏东京的迷人夜景*。

![](Screenshot_20231105_185715.webp)

##### 转向正确的方向

在 *Events* 导航栏下转来转去，最后锁定到了栏目 [*Banquet*](https://statphys28.org/banquet.html)。

里面的时间以及交通方式恰好符合，于是我猜测应该是这项活动。

![](Screenshot_20231105_190302.webp)

也在底部的 *Meeting Point* 一栏找到了集合点 *Yasuda Auditorium*。

![](Screenshot_20231105_190406.webp)

经过简单的检索，可以了解到该地点中文名为 ***安田讲堂***。

![](Screenshot_20231105_190708.webp)

##### 总结

于是得到第五题的答案：`安田讲堂`

#### 第六题

> 6、进站时，你在 JR 上野站中央检票口外看到「ボタン＆カフリンクス」活动正在销售动物周边商品，该活动张贴的粉色背景海报上是什么动物（记作 A，两个汉字）？ 在出站处附近建筑的屋顶广告牌上，每小时都会顽皮出现的那只 3D 动物是什么品种？（记作 B，三个汉字）？（格式：A-B）

##### 第一小问

这一小问我没在搜索引擎上搜索出来什么，倒是在某 X 社交网站通过检索 `ボタン＆カフリンクス 上野駅` 找到了。

![](Screenshot_20231105_191639.webp)

于是得到第一小问的答案：`熊猫`

##### 第二小问

其实这道题我也并没有真正地做出来，因为我这也是理解错了，我以为是 *上野駅* 出口处的 3D 广告牌（实际那里没有）。

我就在搜索引擎的图片搜索功能用关键词 `上野 3D 広告` 检索，然后搜到个 **秋田犬**，扔进去竟然对了x

这题我的解题方法也同样没有参考价值，建议查看 [官方题解](https://github.com/USTC-Hackergame/hackergame2023-writeups/tree/master/official/%E6%97%85%E8%A1%8C%E7%85%A7%E7%89%87%203.0)。

于是得到第二小问的答案：`秋田犬`

##### 总结

结合上述结论，得到该题答案为：`熊猫-秋田犬`

## 🌐 赛博井字棋

在这题不难通过调试发现“下棋”的过程是通过 POST 方法实现的。

![](Screenshot_20231105_193850.webp)

思考了一番之后，突发奇想：在结束后 POST 一个机器人下的棋子并且取代之后会让我赢的点位会怎样呢？

然后给服务器 POST 了个 `{x: 0, y: 0}`，服务器就会返回个 flag 作为 `msg` 的响应。

![](Screenshot_20231105_194600.webp)

## 💻 奶奶的睡前 flag 故事

![](grandma-flag-story-screenshot.png)

注意到图片的 ***在最后*** 加粗提示，我便猜测可能在这个图片末尾的字节处应该有答案。利用 ImHex 也能看到 PNG 的 `IEND` 标识符后面确实有内容，但我没法解出来是什么东西。

然后利用 `binwalk` 工具看了一下，也没看出来什么东西。

于是过了几天再认真地看了一下题目加粗点 ***谷歌的『亲儿子』*** / ***连系统都没心思升级*** / ***截图***，于是我在搜索引擎检索了关键词 `pixel screenshot vulnerability`，也确实搜集到了本题所利用的漏洞 ***Acropalypse***。

![](Screenshot_20231105_195718.webp)

在 GitHub 上也找到了对应的工具，我这采用的是 [Acropalypse-Multi-Tool](https://github.com/frankthetank-music/Acropalypse-Multi-Tool)

经过工具的还原，可以看到本题利用该漏洞留下的 flag（原图分辨率随便选一个都行x）。

![](Screenshot_20231105_201051.webp)

## 🌐 组委会模拟器

> 本题中，你需要撤回的 "flag" 的格式为 `hack[...]`，其中**方括号**内均为小写英文字母，点击消息即可撤回。你需要在 3 秒内撤回消息，否则撤回操作将失败。在全部消息显示完成后等待几秒，如果你撤回的消息完全正确（撤回了全部需要撤回的消息，并且未将不需要撤回的消息撤回），就能获得本题**真正的 flag**。

经过阅读题目后，并且~~实地考察~~一番后，可以确定下来 `fakeqq-message__bubble` 的点击事件可以触发撤回消息操作，消息是由 id 为 `fakeqq-message__bubble` 的 `div` 元素下的 `span` 元素作显示的。

至于为什么不直接采用 POST，是因为 POST 方法会有点麻烦。

根据题目所描述的 flag 格式，可编写 RegEx 表达式 `hack\[[a-z]+\]` 进行匹配。

结合上述信息，通过定时轮询清理消息。题目要求 *3 秒内撤回消息*，但轮询操作不能过于频繁（不然你设备处理不来x），所以设定为 1s 即可。

接着可写出以下代码进行操作（当然代码可读性不强，~~能用就好~~）：

```javascript
const flagRegex = /hack\[[a-z]+\]/

function clean() {
    for (let i = 0; i < 1000; i++) {
        const bubble = document.querySelector(`#app > div > div.fakeqq-container > div:nth-child(${i + 1}) > div > div.fakeqq-message__content > div.fakeqq-message__bubble`)
        if (bubble && flagRegex.test(bubble.querySelector("span").innerText)) bubble.click()
    }
}

setInterval(clean, 1000)
```

## 💻 虫

~~谁家虫子还能叫出一张图片来啊x~~

> 你把这段声音录制了下来：这听起来像是一种通过**无线信道传输图片的方式**，如果精通此道，或许就可以接收来自国际空间站（ISS）的图片了。

通过题目提示，可以在搜索引擎用关键词 `ISS wireless image transmission` 进行检索，不难发现采用的传输方式是 ***SSTV***。

![](Screenshot_20231106_103551.webp)

接下来随便找个 SSTV 实现解题就好了x。

这里我采用的是 [colaclanth/sstv](https://github.com/colaclanth/sstv) 实现。

![](Screenshot_20231106_112551.webp)

很快就能发现解码后的图片里面就有所需要的 flag。

## 💻 JSON ⊂ YAML?

### JSON ⊄ YAML 1.1

通过信息搜集，可以大致收集到 YAML 1.1 不支持 JSON 的科学计数法特性（可参考文章 [JSON is not a YAML subset](https://john-millikin.com/json-is-not-a-yaml-subset)）。

### JSON ⊄ YAML 1.2

参考 [YAML 1.2 规范文档 (旧版)](https://yaml.org/spec/1.2-old/spec.html#id2759572) 的 *Relation to JSON* 一节。

> *JSON*'s RFC4627 requires that mappings keys merely **“SHOULD”** be unique, while *YAML* insists they **“MUST”** be.

可见，*JSON* 的 Key (键) 规范上来说是 **应该** 要唯一的（即并非为强制性要求），而 *YAML* 的 Key (键) 规范上来说是 **必须** 要唯一（即强制性要求）。

### 总结

综上，可以编写一个具有科学计数法及重复键的 JSON 出来解题。

```json
{ "foo": "shota saikou!", "foo": 1e3 }
```

## 💻 Git? Git!

> 「刚刚一不小心，把 flag 提交到本地仓库里了。」马老师回答，「还好我发现了，*撤销了这次提交*，不然就惨了……」

看到 **撤销** 二字，我第一个想到的是 **revert**，然后往 git log 一翻，也没翻到 revert 前的 commit。

然后想了一下~~自己的实际经历~~，想到了这位老师可能进行了 rebase。朝着这个想法向搜索引擎检索了 `check git rebased commit`，找到了关键的工具：`git reflog`（参考 [How to find rebase commits in git or github](https://stackoverflow.com/questions/45228378/how-to-find-rebase-commits-in-git-or-github)）。

经过一番测试后，使用 `git diff HEAD@{2}` 对比，可以发现在 `HEAD@{2}` 处便有问题所需的 flag。

![](Screenshot_20231107_213636.webp)

## 🌐 HTTP 集邮册

这题是搜了半天 [MDN 文档](https://developer.mozilla.org/zh-CN/docs/Web/HTTP) 以及瞎碰瞎撞做出来的（x

### 12 种状态码集邮！

#### [200 OK](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Status/200)

~~送分题~~

```
GET / HTTP/1.1\r\n
Host: example.com\r\n\r\n
```

#### [100 Continue](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Status/100)

```
GET / HTTP/1.1\r\n
Host: example.com\r\n
Expect: 100-continue\r\n\r\n
```

#### [206 Partial Content](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Status/206)

限定返回数据范围，达到获取 Partial Content (部分内容) 的效果。

```
GET / HTTP/1.1\r\n
Host: example.com\r\n
Range: bytes=0-10\r\n\r\n
```

#### [304 Not Modified](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Status/304)

根据 [If-None-Match](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/If-None-Match) 的 Header 介绍，在 `If-None-Match` 中的 `ETag` 值匹配的话，即为验证失败，则服务端会返回 `304` 状态码。

根据 nginx 返回的响应头 ETag 显示为 `64dbafc8-267`，则可根据语法 `If-None-Match: <etag_value>` 构造以下请求头：

```
GET / HTTP/1.1\r\n
Host: example.com\r\n
If-None-Match: "64dbafc8-267"\r\n\r\n
```

#### [400 Bad Request](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Status/400)

送分题，随便扔个不是 HTTP 请求头的东西进去就好了（

```
1145141919810\r\n\r\n
```

#### [404 Not Found](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Status/404)

也是送分题，随便扔个不存在的路径进去就好了（

```
GET /114514 HTTP/1.1\r\n
Host: example.com\r\n\r\n
```

#### [405 Method Not Allowed](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Status/405)

给它来个 POST 就好（

```
POST / HTTP/1.1\r\n
Host: example.com\r\n\r\n
```

#### [412 Precondition Failed](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Status/412)

跟上面 304 比较类似，上面是 `If-None-Match` 匹配上返回 `304`，这里是 [If-Match](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/If-Match) 没匹配上返回 `412`。

根据语法 `If-Match: <etag_value>` 可以随便个构造类似以下的请求头传上去：

```
GET / HTTP/1.1\r\n
Host: example.com\r\n
If-Match: "114514"\r\n\r\n
```

#### [414 URI Too Long](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Status/414)

给它传个超级超级长的路径就好了（

```
GET /<long_string> HTTP/1.1\r\n
Host: example.com\r\n\r\n
```

自行把 `<long_string>` 替换成一个超级超级长的字符串就好了（x

#### [416 Range Not Satisfiable](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Status/416)

根据请求头 [Range](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Range) 的描述，在传入一个不合法的范围时，就会返回 `416` 状态码。

也就是我们传入一个超过返回内容大小的范围就好了，可以构造以下请求头：

```
GET / HTTP/1.1\r\n
Host: example.com\r\n
Range: bytes=114514-\r\n\r\n
```

#### [501 Not Implemented](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Status/501)

这个得参考 Nginx 源码 [src/http/ngx_http_request.c#L1993,L2011](https://github.com/nginx/nginx/blob/a13ed7f5ed5bebdc0b9217ffafb75ab69f835a84/src/http/ngx_http_request.c#L1993,L2011)。

可见在请求头传入的 `Transfer-Encoding` 不受支持时，便会返回 `501` 状态码，即可构造一个不存在的 `Encoding` 进行请求操作即可。

```
GET / HTTP/1.1\r\n
Host: example.com\r\n
Transfer-Encoding: majik\r\n\r\n
```

#### [505 HTTP Version Not Supported](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Status/505)

传入一个不受默认值配置 Nginx 支持的 HTTP 版本就好。

```
GET / HTTP/2077\r\n
Host: example.com\r\n\r\n
```

#### 总结

其实 `501 Not Implemented` 是非预期解，取而代之的预期解是 `413 Content Too Large`，但我没想到能传入一个唬人的 `Content-Length` 就能解决的（x

### 没有状态……哈？

这个还是误打误撞试出来的，我就试了一下不传入 HTTP 版本会怎样，结果试出来了一个 HTTP/0.9 的这个~~特性~~。

可参考 [What is HTTP/0.9 request?](https://superuser.com/a/1504534) 以及 [w3.org 定义](https://www.w3.org/Protocols/HTTP/AsImplemented.html)

```
GET /\r\n\r\n
```

## 💻 Docker for Everyone

本人通过参考文章 [技术干货 | Docker 容器逃逸案例汇集](https://zhuanlan.zhihu.com/p/191373337)，猜测可能宿主 Docker 的 sock 及本体映射进去了，便进行了以下操作。

```shell
docker -H unix:///var/run/docker.sock run -it -v /:/host alpine /bin/ash  # 调用宿主机的 docker 开启新的容器，并挂在根目录至 /host，并运行 ash
cat /host`readlink -f /host/flag`  # 获取 flag
```

~~但实际上是因为用户直接处于 docker 用户组中，可以直接操作宿主的 docker。~~

## 🧮 惜字如金 2.0

这题非常简单，按照题目的指引去做就好了。

我的方法是先都以 *creat 原则* 进行，在混淆字典每一行后面全补上一个 `e`。然后根据 flag 的格式要求: `flag\{[\w\-]+\}`~~（不知道怎么表达就直接用 RegEx 表示一下）~~，如果对应的字符偏移了就去掉补上的 `e`，利用 *referer 原则* 进行修补。

修补完之后就能获得对应的 flag 了。

## 🪐 高频率星球

这道题我拿到文件后就看看能不能打开来直接操作~~（然后发现真可以）~~，虽然可以直接操作，但是还是有一堆控制字符在，于是我随便写了个 Python 脚本解题，最后手动修补一下就好了。

```python
import re

PATTERN = re.compile(r"\u001b\[\??\d*[a-zA-Z]?")
lines: list[str] = []

HINTS = [
    "\r\u001b[K \u001b[KESC\b\b\bESC\u001b[K[\b[\u001b[K6\b6\u001b[K~\b~\r\u001b[K",
    "\r\u001b[K \u001b[KESC\b\b\bESC\u001b[K[\b[\u001b[K6\b6",
    "\r\u001b[K \u001b[KESC\b\b\bESC\u001b[K[\b[",
    "\u001b[K6\b6\u001b[K~\b~\r\u001b[K",
    "\u001b[K~\b~\r\u001b[K",
]  # 各种用来显示给人看不是给解释器看的东西

with open("asciinema_restore.rec") as fp:
    data = map(eval, fp.readlines()[1:])  # 跳过第一行信息
for item in data:
    line: str = item[2]  # 去除前面不必要的信息
    for hint in HINTS:
        line = line.replace(hint, "")  # 去除提示信息
    line = PATTERN.sub("", (
        line
        .replace(":\u001b[K", "")
        .replace("\b", "")
    ))  # 去除各种控制符
    if not line:
        continue  # 去除空行
    lines.append(line)  # 丢到待输出列表
with open("result.txt", "w") as fp:
    fp.writelines(lines)
```

~~（随便写的就不要奢求什么啦（x）~~

## 🪐 流式星球

这道题通过代码是可以发现处理的视频是经过 `cv2` 和 `numpy` 处理，以类似于 RAW 且不压缩地输出到新文件，但是数据最后部分数据（可能是 [0, 100] 范围内的任意一个数）被直接裁切掉了，但由于数据是 RAW 形式存储的，即使后面被裁切了，也不影响前面的内容解析。

其中视频的长宽是无法知道的，只能慢慢去试。另外由于数据裁切，需要对最后被裁切的不完整数据进行处理。以下是我写的 Python 脚本。

```python
import numpy as np
import cv2

arr = np.fromfile("video.bin", dtype=(np.uint8, np.uint8))
frame = 110
height = 759
width = 427
arr = arr[:(frame * height * width * 3)]
arr = arr.reshape((frame, height, width, 3), order="C")
for i in range(frame):
    cv2.imshow("video", arr[i])
    cv2.waitKey(100)
```

## 🪐 低带宽星球

### 小试牛刀

> 压缩至 2KiB (2048 字节) 及以下，获得 flag1

什么？图片压缩？还得看我 VP9 / AV1 压缩！直接上 WebP 压缩

```shell
ffmpeg -i image.png -lossless 1 image.webp
```

压缩出来 170B，完事！

### 极致压缩

这题没解出来x

> 压缩至 50 字节及以下，获得 flag2

看到这个，我还在尝试 VP9 / AV1 压缩加上各种优化参数，但始终无法实现 50 bytes 以下（甚至还幻想转换成 SVG，但实际更大了）

实际上过程中还搜索到了 JPEG XL 这个东西，但是脑子里想着 JPEG 是什么古老的东西，肯定不是他（然后看官方题解后：草！）

## 💻 Komm, süsser Flagge

### 我的 POST

首先看到第一条规则

```shell
-A myTCP-1 -p tcp -m string --algo bm --string "POST" -j REJECT --reject-with tcp-reset
```

可以看到是通过匹配**包**里是否存在 `POST` 来过滤包。

所以重点在于让 POST 这串东西强制分包传输，虽然说想过通过降低 MTU 和 MSS 来控制分包，但发现毫无成果。

然后我在猜想能不能直接通过 `socket.send` 分开两次发来实现分包，然后实践了一下确实可以。

```python
import socket
import time

addr, port = input("input the host (addr:port): ").split(":")
token = input("input your token: ")
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((addr, int(port)))
client.send(b"P")
time.sleep(1)
client.send(b"OST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: " + str(len(token)).encode() + b"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" + token.encode() + b"\r\n\r\n")
print(client.recv(4096))
```

### 我的 P

是非预期解啦，我拿第一题的代码拿到了。

具体原因可以看 [官方题解说明](https://github.com/USTC-Hackergame/hackergame2023-writeups/tree/master/official/Komm%2C%20s%C3%BCsser%20Flagge#%E9%9D%9E%E9%A2%84%E6%9C%9F%E8%A7%A3)。

### 我的 GET

没解出来。

## 👨‍💻 为什么要打开 /flag 😡

### LD_PRELOAD

第一题 *LD_PRELOAD* 这名字已经提示了这题通过 `LD_PRELOAD` 进行干扰程序运行，即可以通过静态链接或者直接上 Assembly 绕过干扰。

#### Assembly

感谢 [Reading files the hard way - Part 2 (x86 asm, linux kernel)](https://fasterthanli.me/series/reading-files-the-hard-way/part-2)，代码参考了该文章。

```nasm
global _start

section .data
    path:   db  "/flag", 0


section .text
_start:
    mov     rax, 2      ; "open"
    mov     rdi, path   ;
    xor     rsi, rsi    ; O_RDONLY
    syscall

    push    rax         ; push file descriptor onto stack
    sub     rsp, 64     ; reserve 64 bytes of memory

    xor     rax, rax    ; "read"
    mov     rdi, [rsp+64]   ; file descriptor
    mov     rsi, rsp    ; address of buffer
    mov     rdx, 64     ; size of buffer
    syscall

    mov     rdx, rax    ; number of bytes
    mov     rax, 1      ; "write"
    mov     rdi, 1      ; file descriptor (stdout)
    mov     rsi, rsp    ; address of buffer
    syscall

    mov     rax, 60     ; "exit"
    xor     rdi, rdi    ; return code 0
    syscall
```

#### 静态链接

下面是随便写的代码。

```c
#include <stdio.h>

int main() {
    FILE *fp = fopen("/flag", "r");
    char buffer[64];
    fread(buffer, 64, 1, fp);
    printf("%s", buffer);
}
```

下面是编译命令。

```shell
gcc -static ld_preload.c -o ld_preload
```

### 都是 seccomp 的错

挖，是 Rust！但没在意那条注释（虽然说看到了也不会解x）

## 👨‍💻 异星歧途

特意下了 Mindustry（在游戏里解题，蛮新颖的x）

一开始我还以为真的是搁那随便试试就能试出来了，然后弄了半天没弄出什么来，直到后面发现了叫 **微型处理器** 和 **逻辑处理器** 的东西，打开发现一堆逻辑（x）

不过最后一个确实得一个个试，试出来把整体通了就好了。

### 第一个区域

第一个可以推出来以下逻辑：

从左到右，匹配上了 `0 1 0 1 1 0 1 0` 的一个，则整体为 *disabled* 状态，反之为 *enabled* 状态。

用代码表示就是：

```python
enabled = not any(switch == target for switch, target in zip(switches, [0, 1, 0, 1, 1, 0, 1, 0]))
```

可以得出开关需要设置为 `1 0 1 0 0 1 0 1`。

### 第二个区域

第二个可以推出来以下逻辑：

```python
number += sw1 << 7
number += sw2 << 6
number += sw3 << 5
number += sw4 << 4
number += sw5 << 3
number += sw6 << 2
number += sw7 << 1
number += sw8
en = number in [i ** 2 for i in range(16)]
enabled = sw1 and sw6 and en
```

可以发现令 `number` 结果符合 `[0, 1, 4, 9, 16, 25, 36, 49, 64, 81, 100, 121, 144, 169, 196, 225]` 其中任意一个结果且 sw1 和 sw6 处于启动状态都能使其启动。

可以通过尝试组合，得出开关需要设置为 `1 1 0 0 0 1 0 0`（此时 number 结果为 `2^7 + 2^6 + 2^2 = 196`）。

### 第三个区域

此处逻辑十分简单：

```python
converyor1.enabled = switch1.enabled
gate1.enabled = switch2.enabled
reactor1.enabled = not switch3.enabled
reactor2.enabled = not switch3.enabled
conduit1.enabled = switch4.enabled
conduit2.enabled = switch4.enabled
mixer1.enabled = switch5.enabled
extractor1.enabled = switch7.enabled
meltdown2.enabled = switch7.enabled

if switch8.enabled != switch9.enabled:
    mixer1.enabled = False
    conduit2.enabled = True
    reactor1.enabled = True
    reactor2.enabled = True
    conveyor2.enabled = True
    sleep(5)
```

经过**尝试**可以得到开关需要设置为 `1 0 0 0 1 1 1 0`。

### 第四个区域

基于**尝试**可以得到开关需要设置为 `0 1 1 1 0 1 1 1`。

# 后记

咕咕咕了三个月，终于把它更完了！
