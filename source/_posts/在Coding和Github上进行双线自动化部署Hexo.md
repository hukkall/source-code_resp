---
title: 在Coding和Github上进行双线自动化部署Hexo
abbrlink: 52f9e600
date: 2020-02-21 21:27:07
tags:
	- Hexo
	- 没有用的知识
	- 自动化部署
typora-root-url: ./
---

### 起因

​		我前几天开始搭建这个博客，由于之前搭建过很多次，所以没有出现什么意外就搭建完了。但是当我把博客地址给其他人的时候，他们有的反应打得开，有的反应打不开。经过一番谷歌之后我发现原因可能是gitpage的服务器在国外，会出现加载失败的问题。与此同时我又了解到国内也有提供类似静态页面托管服务的厂家，我就想把博客也一并部署到国内的服务器上。我选择了可免费绑定域名的Coding（需要实名认证）。  

​		我这种经常宿舍实验室两头跑的人有在不同电脑上写博客的需求，而我又不想每次都要拷个源代码，于是便萌生了将博客源代码上传到github去的想法。但是这样一来每次写完代码都要做git三连和hexo三连，很是麻烦。一番搜索之后发现Appveyor可以实现自动化部署hexo，只需要推送到远程仓库，Appveyor就可以帮我自动部署了。

​		但是对于coding的话，我用Appveyor就找不到什么好方法了。我们可以利用github自带的Ci来进行Coding的静态页面的自动化部署。当然你也可以不用Appveyor，直接利用github的Ci进行部署也是可以的。

### 要求

		- 一个域名
		- 一个github账户
		- 一个coding账户（需要实名认证）

### 过程

#### 1. 新建仓库

​		我们先新建一个公开的源码仓库，用于保存博客源代码。

#### 2. 去Appveyor注册

​		[注册网址](https://ci.appveyor.com/signup)，选择**FREE-for open-source projects** ,并选择使用github账户登录。

![image-20200223213407364](/../img/image-20200223213407364.png)

#### 3. 新建并加密一个Access_Token

​		[申请地址](https://github.com/settings/tokens/new)，这是用来申请一个Token，Appveyor就是利用这个来访问你的Github仓库的，我把权限全部给了。在最上面的Note一栏里面填入这个Token的名字，随意。

​				![image-20200223213834567](/../img/image-20200223213834567.png)

​		然后点击最下面的Generate token。复制好他给出的Token，它只会出现一次，如果你忘记了的话，只能删掉重新生成一个了。

![image-20200223213922721](/../img/image-20200223213922721.png)

​		因为这个仓库是公开的，而且这个Token是要放在这个仓库里面的，为了安全，我们需要对它进行加密。来到[Appveyor提供的加密页面](https://ci.appveyor.com/tools/encrypt)，输入刚才新建的Token，点击Encypt，即可生成加密后的Token。

#### 4. 新建Appveyor的配置文件

​		在博客源代码目录中新建一个`appveyor.yml`，你可以根据官方文档自行填写，也可仿照我的：

```yaml
clone_depth: 5

environment:
  access_token:
    secure: 填写你的加密后的Token

install:
  - node --version
  - npm --version
  - npm install
  - npm install hexo-cli -g

build_script:
  - hexo generate

artifacts:
  - path: public

on_success:
  - git config --global credential.helper store
  - ps: Add-Content "$env:USERPROFILE\.git-credentials" "https://$($env:access_token):x-oauth-basic@github.com`n"
  - git config --global user.email "%GIT_USER_EMAIL%"
  - git config --global user.name "%GIT_USER_NAME%"
  - git clone --depth 5 -q --branch=%TARGET_BRANCH% %STATIC_SITE_REPO% %TEMP%\static-site
  - cd %TEMP%\static-site
  - del * /f /q
  - for /d %%p IN (*) do rmdir "%%p" /s /q
  - SETLOCAL EnableDelayedExpansion & robocopy "%APPVEYOR_BUILD_FOLDER%\public" "%TEMP%\static-site" /e & IF !ERRORLEVEL! EQU 1 (exit 0) ELSE (IF !ERRORLEVEL! EQU 3 (exit 0) ELSE (exit 1))
  - git add -A
  - if "%APPVEYOR_REPO_BRANCH%"=="master" if not defined APPVEYOR_PULL_REQUEST_NUMBER (git diff --quiet --exit-code --cached || git commit -m "Update Static Site" && git push origin %TARGET_BRANCH% && appveyor AddMessage "Static Site Updated")

```

​		其中`GIT_USER_EMAIL`,`GIT_USER_NAME`,`TARGET_BRANCH`,`STATIC_SITE_REPO`，他们分别是git的用邮箱、用户名、待部署仓库的目标分支，待部署的目标仓库（你的静态页面的github地址）。这几个都是要我们去Appveyor里面设置的环境变量。

#### 5. Appveyor的配置

​		回到Appveyor，点击New Project

![image-20200223214015897](/../img/image-20200223214015897.png)

​		选择github里面你的博客源代码目录，点击右侧的Add，在新页面选择setting

![image-20200223214102188](/../img/image-20200223214102188.png)

​		选择Environment，添加第四点所说的的环境变量

​		![image-20200223215652016](/../img/image-20200223215652016.png)

​		点击Save保存好配置。

​		之后，你只要把你的博客源代码推送到远程仓库之后，Appveyor会自动检测到你的推送并进行自动化部署。类似这样：

​		![image-20200223220116830](/../img/image-20200223220116830.png)

​			并且可以再你的源代码仓库里面查看是否部署成功：

![image-20200223220259404](/../img/image-20200223220259404.png)	

​				

#### 6. 对Coding进行自动部署

​		来到Coding的[官网](https://coding.net/)，点击个人版登录，新建一个DevOps项目，建议项目名称跟你的用户名一致。在右侧的“构建与部署”处选择静态网站，选择立即发布静态网站，网站名称随意。

​		然后进入到个人设置，点击访问令牌

![image-20200223221358546](/../img/image-20200223221358546.png)

​		这个类似于github的Access_Token,在这里我也是把权限全给了。

​		创建完成后记住令牌和令牌用户名。回到github的博客源代码仓库，选择上方的Actions，这个也就是github的Ci，选择**Set up a workflow yourself** 

![image-20200223221848554](/../img/image-20200223221848554.png)

​		在出现的编辑窗口里面，用下面的文本替换掉里面的内容（知乎上的一个大佬的配置）

```yaml
name: 自动部署 Hexo

on:
  push:
    branches:
      - master

jobs:
  build:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: [10.x]

    steps:
      - name: 开始运行
        uses: actions/checkout@v1

      - name: 设置 Node.js ${{ matrix.node-version }}
        uses: actions/setup-node@v1
        with:
          node-version: ${{ matrix.node-version }}

      - name: 安装 Hexo CI
        run: |
          export TZ='Asia/Shanghai'
          npm install hexo-cli -g
      - name: 缓存
        uses: actions/cache@v1
        id: cache-dependencies
        with:
          path: node_modules
          key: ${{runner.OS}}-${{hashFiles('**/package-lock.json')}}

      - name: 安装插件
        if: steps.cache-dependencies.outputs.cache-hit != 'true'
        run: |
          npm install
      - name: 部署博客
        run: |
          hexo clean && hexo g
          cd ./public
          git init
          git config user.name "${{secrets.GIT_NAME}}"
          git config user.email "${{secrets.GIT_EMAIL}}"
          git add .
          git commit -m "Update"
          git push --force --quiet "https://${{secrets.CD_TOKEN}}@${{secrets.CD_REF}}" master:master
```

​		其中，以`secrets.`开头的四个变量是需要我们去设置的环境变量。 点击右边的Start commit保存。

​		我们进入源码仓库的环境变量设置，其位置如下：

​		![image-20200223222546211](/../img/image-20200223222546211.png)

​		这四个变量的意思分别如下表所示：

|   变量    |              意思               |
| :-------: | :-----------------------------: |
| GIT_NAME  |           git的用户名           |
| GIT_EMAIL |            git的邮箱            |
|  CD_REF   |   coding的静态页面的仓库地址    |
| CD_TOKEN  | coding的令牌用户名:coding的令牌 |

其中CD_REF在你的Coding的右上方可以看到，改成ssh之后@后面的就是CD_REF了。

![image-20200223223844299](/../img/image-20200223223844299.png)

以后我们每次写完文章，直接git三连就可以自动化部署到两个静态页面托管仓库了。

#### 7. 域名绑定

​		我们可以对域名的dns解析记录进行修改，实现国内用户访问的是coding上的页面，国外用户访问github上的页面。

​		一图流：

​		![image-20200223225143011](/../img/image-20200223225143011.png)

​			如果你的coding站点无法申请到证书，请暂停下境外的解析。

​		-完