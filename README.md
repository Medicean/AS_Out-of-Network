# AntSword Out-of-Network

> AntSword 检测目标访问外网情况插件

快速探测目标出外网情况

* HTTP(TCP)
* DNS
* UDP

## 演示

点击开始按纽后，输出如下:

```
[*][HTTP] Try to send HTTP request
[+][HTTP][Success][http://220.181.38.148]
[*][UDP] Try to send UDP request
[+][UDP][Success][8.8.8.8:53]
[*][DNS] Try to resolve qq.com with system nameserver
[+][DNS][Success][qq.com]
	qq.com: 61.129.7.47
	qq.com: 123.151.137.18
	qq.com: 183.3.226.35

```


## 安装

### 商店安装

进入 AntSword 插件中心，选择 Out-of-Network，点击安装

### 手动安装

1. 获取源代码

	```
	git clone https://github.com/Medicean/as_Out-of-Network.git
	```
	
	或者
	
	点击 [这里](https://github.com/Medicean/as_Out-of-Network/archive/master.zip) 下载源代码，并解压。

2. 拷贝源代码至插件目录

    将插件目录拷贝至 `antSword/antData/plugins/` 目录下即安装成功

## 相关链接

* [AntSword 文档](http://doc.u0u.us)
* [dhtmlx 文档](http://docs.dhtmlx.com/)
