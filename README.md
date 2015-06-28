# Menu

- 赛风3 Linux版 [CHS]
- Psiphon3-for-Linux [ENG]


# 赛风3 Linux版 [CHS]
这个repo实际上是[Psiphon3](https://bitbucket.org/psiphon/psiphon-circumvention-system) `SOCKS Proxy` repo的一小部分，这部分是python脚本，可以在Linux上面运行。但是只是`SOCKS Proxy`。

所以我又添加了DeleGate repo用来支持Linux上的`HTTP Proxy`。

**总之这是一个完全免费的用来在Linux下面翻墙的工具，因为现在fqrouter2已经被谷歌封杀不少了，Android SDK更新都用不了fqrouter2了，很忧伤啊有木有！！**

## 首先编译OpenSSH

官方说需要编译他们改过的OpenSSH 5.9p1源码，用来支持混淆：

    cd openssh-5.9p1/
    ./configure
    make
然后把目录下`ssh`这个可执行文件从`openssh-5.9p1/`复制到`pyclient/`。

## 赛风3 使用方法

### 更新socks服务器列表

执行如下代码：

    cd pyclient
    python update.py

### 开启SOCKS代理

执行如下命令，可以看到软件有提示信息`Your SOCKS proxy is now running at 127.0.0.1:1080`：

    python psi_client.py

**P.S.** 命令执行可能会提示缺少包，缺少啥就谷歌啥。比如我就遇到了问题，搜一下需要执行如下指令`sudo apt-get install python-socksipy`。

### 在需要的软件里面设置SOCKS代理（以Android Studio为例）

Do these steps:

    打开 "Config"
    搜索 "proxy"
    选选择代理模式 "SOCKS"
    填写 "Address" and "Port"
    点击 "OK" or "Apply"

## 需要HTTP代理吗?

你需要这个工具： [`DeleGate`](http://delegate.hpcc.jp/)，他可以把SOCKS代理转化为HTTP代理。执行如下命令：

    cd delegate9.9.13
    make

**注意：** `make`这一步需要你填写email地址，不知道为什么……

`make`完成后，可执行的`delegated`文件就在`delegate9.9.13/src`目录里了，所以：

    cd src

接下来，可以自定义HTTP代理的相关信息。比如，使用"8080"作为HTTP端口，而且我们已经有了`赛风3`的SOCKS代理地址`127.0.0.1:1080`：（用`localhostL1080`是一样的）

    ./delegated -P8080 SERVER=http SOCKS=127.0.0.1:1080

之后你将会看到`<DeleGate/9.9.13> [32257] -P8080 READY`。这个用来作为HTTP的端口就在127.0.0.1上生效了！**尽情享受吧！！！**

### 如何停止HTTP代理？

看上面列出来的这个字符串`[32257]`，这是一个进程号，所以:

    kill 32257

完事！

但是我还是要补一句标准关闭方法（8080是刚刚开启的端口）：

    delegated -P8080 -Fkill

关于赛风3的官方资讯：
https://groups.google.com/forum/#!searchin/psiphon3-developers/python$20/psiphon3-developers/cb8CW7Y98nI/BRx7-cIQ7C8J

# Psiphon3-for-Linux [ENG]
Part of [Psiphon3](https://bitbucket.org/psiphon/psiphon-circumvention-system) `SOCKS Proxy` repo, for Linux operating system.

With DeleGate repo to achieve `HTTP Proxy` on Linux.

**TOTALLY FREE & STABLE & SAFE FOR 翻墙 =。= 额……总之这是一个用来在Linux下面翻墙的工具，大陆用户必备，因为现在fqrouter2已经被谷歌封杀不少了，Android SDK更新都用不了fqrouter2了，很忧伤啊有木有！！**

## Make openssh first

You will need to build OpenSSH 5.9p1 that supports obfuscation:

    cd openssh-5.9p1/
    ./configure
    make

and copy ssh binary from `openssh-5.9p1/` to `pyclient/`

## Phiphon3 Usage

### Update server list first

Run these commands:

    cd pyclient
    python update.py

### Run SOCKS Proxy

Run these commands, and you will see `Your SOCKS proxy is now running at 127.0.0.1:1080`:

    python psi_client.py

**P.S.** You may need to install some python packages, the commands are just in Google. e.g. I was in need of this `sudo apt-get install python-socksipy`.

### Set SOCKS Proxy configuration in apps (Android Studio for example)

Do these steps:

    Open "Config"
    Search "proxy"
    Select "SOCKS"
    Fill "Address" and "Port"
    Press "OK" or "Apply"

## Need HTTP Proxy?

You should use a tool named [`DeleGate`](http://delegate.hpcc.jp/), which convert SOCKS Proxy to HTTP Proxy. Run these commands:

    cd delegate9.9.13
    make

**Note:** `make` step need to input an email address.

Then, after `make` finished, the executable `delegated` located in `delegate9.9.13/src`, so:

    cd src

Next, set out port for HTTP Proxy. For example, choose "8080" for HTTP Proxy, and we've got the Phiphon3 SOCKS Proxy "127.0.0.1:1080": (use `localhostL1080` does the same effort)

    ./delegated -P8080 SERVER=http SOCKS=127.0.0.1:1080

You will see `<DeleGate/9.9.13> [32257] -P8080 READY`. This port for HTTP Proxy is available! **Enjoy it!!!**

### How to stop?

See the string `[32257]` above? just run:

    kill 32257

That's done!

But I still show the standard way to close port (8080 is the port we assigned above):

    delegated -P8080 -Fkill

For more details visit related Google Group discussion at
https://groups.google.com/forum/#!searchin/psiphon3-developers/python$20/psiphon3-developers/cb8CW7Y98nI/BRx7-cIQ7C8J
