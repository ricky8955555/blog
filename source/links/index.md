---
title: 友情链接
---

这里可以通往 Ricky 朋友们的秘密基地捏~

<!-- more -->

<style>
    .container {
        display: block;
        margin: 2rem 1rem 2rem 1rem;
    }

    .container::after {
        content: " ";
        display: block;
        clear: both;
    }

    .card {
        display: flex;
        width: 45%;
        height: 5rem;
        border-radius: 4px;
        transition-duration: 0.3s;
        padding: 0.5rem 0 0.5rem 0;
    }

    .card:nth-child(odd) {
        float: left;
    }
    .card:nth-child(even) {
        float: right;
    }

    .card:hover {
        transform: scale(1.1);
        box-shadow: 0 3px 6px rgba(0, 0, 0, 0.2);
    }

    .card > .card-avatar {
        float: left;
        height: 60%;
        margin: 0.25rem 0 0 1rem;
    }

    .card > .card-info {
        float: right;
        margin-left: 1rem;
        width: 100%;
        overflow: hidden;
    }

    .card > .card-info > .card-title {
        font-weight: bold;
    }

    .card > .card-info > .card-descr {
        font-size: 1rem;
        white-space: nowrap;
        overflow: hidden;
    }

    @media only screen and (max-width: 768px) {
        .card {
            width: 100%;
        }
    }
</style>

<div class="container">
<div class="card">
    <img class="card-avatar" src="https://avatars.githubusercontent.com/u/31303371">
    <div class="card-info">
        <div class="card-title">
            <a href="https://huajitech.net">HuajiTech</a>
        </div>
        <div class="card-descr">We do anything.</div>
    </div>
</div>

<div class="card">
    <img class="card-avatar" src="https://coldin.top/avatar.png">
    <div class="card-info">
        <div class="card-title">
            <a href="https://coldin.top">酷丁的主页</a>
        </div>
        <div class="card-descr">一个羞涩的小朋友的自我介绍页面</div>
    </div>
</div>

<div class="card">
    <img class="card-avatar" src="https://xtaolink.cn/img/avatar.jpg">
    <div class="card-info">
        <div class="card-title">
            <a href="https://my.xtaolink.cn">深海小涛</a>
        </div>
        <div class="card-descr">又一个垃圾技术博客</div>
    </div>
</div>

<div class="card">
    <img class="card-avatar" src="https://cos.zyglq.cn/static/web-logo.jpg">
    <div class="card-info">
        <div class="card-title">
            <a href="https://www.zyglq.cn">资源管理器博客</a>
        </div>
        <div class="card-descr">心中有光，对立重伤</div>
    </div>
</div>

<div class="card">
    <img class="card-avatar" src="https://s1.ax1x.com/2023/07/24/pCOmxrd.png">
    <div class="card-info">
        <div class="card-title">
            <a href="https://kkkrza.link">卡平南路</a>
        </div>
        <div class="card-descr">至少我不再寂寞，你眼神能再闪烁</div>
    </div>
</div>
</div>

> 想要跟我交换友链的可以通过 [关于我](https://rkmiao.eu.org/) 的任何一种联系方式找我哦，当然也可以直接发起 PR 添加，下面是格式示例w

```
名称: Ricky8955555's Blog
简介: Ricky 的各种日常捏
链接: https://blog.rkmiao.eu.org
图片: https://blog.rkmiao.eu.org/images/profile.webp
```