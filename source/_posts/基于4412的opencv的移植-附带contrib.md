---
title: 基于4412的opencv的移植(附带contrib)
tags:
  - 嵌入式
  - 软件移植
typora-root-url: ./
abbrlink: 42ae8816
date: 2020-02-20 19:55:33
index_img: https://rmt.dogedoge.com/fetch/~/source/unsplash/photo-1593754760685-5853c829bb64
---

和缺少资料的开发板斗智斗勇的过程之其一

<!-- more -->

#### 平台

1. UP-Tech 4412
2. Kubuntu 18.04LTS 64位

#### 使用的工具

1. 2013版的交叉编译工具(arm-2013.05-24-arm-none-linux-gnueabi)
2. opencv_3.4.9
3. opencv_contrib_3.4.9
4. cmake-gui

#### 起因

1. 放假之前用的虚拟机被我删除了，里面的文件都没了。
2. 开发板的文件系统被我折腾坏了
3. 需要重新移植opencv

#### 过程：

##### 1. 下载所需软件以及源代码

​		首先下载好我们需要使用到的各个文件，他们的下载链接如下所示：

```
arm-2013.05-24-arm-none-linux-gnueabi		链接：http://pan.baidu.com/s/1i3gNttF
opencv_3.4.9	链接：https://github.com/opencv/opencv/archive/3.4.9.tar.gz
opencv_contrib_3.4.9 链接：https://github.com/opencv/opencv_contrib/archive/3.4.9.tar.gz
```

至于cmake-gui的话，如果你使用的是ububtu，直接在终端输入`sudo apt install cmake-gui`即可。

将交叉编译器解压好，这里我的是`/home/gukki/baidunetdiskdownload/arm-2013.05/`

将下载并解压好的两份源代码放在同一个目录。

##### 2. 使用cmake-gui进行交叉编译

​		打开cmake，如下图所示：（只截取了上半部分）

![image-20200220202805847](/../img/image-20200220202805847.png)

​		第一行是要求你输入你的opencv的源代码的绝对路径，在这里我的路径是`/home/gukki/OpenCv/Source_Code/opencv-3.4.9`，第二行要求你填写配置好的源代码的保存路径。在这里，我的是`/home/gukki/OpenCv/Process_Code`。

​		填写完毕之后点击`Configure`，cmake要求你选择编译工具，由于我们是交叉编译，我们选择最后一项。点击下一步之后如下图所示：

![image-20200220203339941](/../img/image-20200220203339941.png)

​		其中`Operating System`顾名思义，操作系统，我们的开发板上用的是Linux，就写上吧。

`C`要求你指定好交叉编译器的C编译器，也就是arm-gcc的所在地。

`C++`同理，也是要求你填上arm-g++的所在地，而`Target Root`填写上你交叉编译器的目录。

​		填写完成之后点击完成。

​		配置完成之后应该会是一片红色，并且左下角的文本显示区域有一句`Configuring done`。

我们对我们的需求进行对opencv的裁剪：

> 在搜索栏区域输入JPEG,勾选上`BUILD_JPEG`  
>
> 输入PNG,勾选上`BULID_PNG`
>
> 输入nonfree，勾选上
>
> 输入gtk，取消勾选，因为我们用不上图形界面
>
> 输入zlib，勾选上
>
> 输入extra，在`Value`一栏上点击右边的三个点，定位好你的`opencv_contrib`的`moudules`文件夹。
>
> 输入prefix，输入你想安装到的文件夹路径。等会`make install`时会安装到这里。    

​		配置完成之后点击`Configure`，此时你应该要下载一些有关附加模块的一些文件，可能需要很久，等不及的就不去配置extra。下载完成之后，可以再次对额外模块进行裁剪，根据你的需求来定。裁剪完成之后，再次点击`Configure`，应该不会出现红色了。

点击`Generate`生成工程文件。  

##### 3.编译文件

​		进入你的配置好的源代码的文件夹，在此处打开终端，输入`make`开始编译，根据自身虚拟机配置情况，可在后面加上`-j 线程数`这个参数，我给虚拟机分配了8个核心，所以我编译速度比较快，只用了5分钟左右。如果你什么都没加，预计时间可能是半小时到一小时左右。中间可能有些警告，无须理会。只要没停下来就好。

![image-20200220210124846](/../img/image-20200220210124846.png)

可以看到处理器是被吃满的。  

​		编译完成后输入`make install`，可能需要你加个`sudo`什么的....

​		安装完成之后可以去设定的`prefix`文件夹去看看。应该长这样：

![image-20200220210712344](/../img/image-20200220210712344.png)

​		其中`lib`里面是我们编译好的库文件，使用`file`命令查看类型：

![image-20200220210841342](/../img/image-20200220210841342.png)

​		成功了大半了！

##### 4. 移植到开发板上

​		将`lib`文件夹里面的所有文件全部传到开发板的`/lib`，目录下面，使用`nfs`速度会快很多。

​		由于我们使用了较新版本的`arm_gcc`编译工具链，我们还需要把交叉编译工具链里面的`libstdc++.so,libstdc++.so.6,libstdc++6.0.17`一起复制过去并覆盖。他们位于`arm-2013.05/arm-none-linux-gnueabi/libc/usr/lib/`这个地方。

##### 5. 虚拟机编译设置

​		为了让虚拟机知道opecv的头文件和库文件的位置，我们需要借助一个叫做`pkg-config` 的软件， 安装也是可以用`apt`来安装的。我们找到opencv库文件夹里面的pkgconfig文件夹，打开你的shell的配置文件，我使用的是`zsh`所以打开`.zshrc`加入以下的两句话句话：

```
PKG_CONFIG_PATH=/home/gukki/OpenCv/_Install/lib/pkgconfig/:$PKG_CONFIG_PATH
export PKG_CONFIG_PATH
```

​		自行替换你的pkgconfig文件夹位置。

​		使用`source`命令让更改生效，输入`pkg-config --cflags --libs opencv`，应该会出现一大坨东西，如下所示：

![image-20200220212101215](/../img/image-20200220212101215.png)

##### 6. 测试与简化

​		写一个非常简单的程序，来测试下吧：

```c++
#include<opencv2/opencv.hpp>
using namespace cv;
int main()
{
  Mat m;
  return 0;
}
```

​		保存为`T.cpp`，使用如下命令进行编译：

```shell
arm-none-linux-gnueabi-g++ `pkg-config --cflags --libs opencv` T.cpp -lpthread -lrt -ldl 
```

​		应该只有一个警告，不需要理会。

​		生成的`a.out`文件拷贝到开发板，给予权限。运行之后应该什么效果都没有，也没有任何报错。那就是行了。你可以试试更加复杂的程序了。但是不能有任何跟界面有关的函数出现比如`imshow`，`waitkey`等等，否则会报错。（因为我裁剪掉了）你也可以自行尝试如何让他们使用，有更好的想法可以告诉我！

​		每次编译都要打那么长的代码，有没有方法可以简化？

​		可以使用`alias`命令来进行简化，我的就是：

```shell
alias armcv="arm-none-linux-gnueabi-g++ `pkg-config --cflags --libs opencv` -lpthread -ldl -lrt"
```

​		同样的，写到你自己的shell的配置文件里面。

​		完-

​		