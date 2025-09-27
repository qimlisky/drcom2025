#### 2025年哆点pc客户端的认证脚本  

### 前言  
这是我自己研究编译，AI负责写程序的，我自己感觉代码还有问题，但是能用。目前有python，c，go语言版本的  
## 教程   
1.自行学习其他老项目的抓包教程（来自drcoms/drcom-generic）  
1-1 使用 wireshark 在官方客户端登录前开始截包，做一次完整的截包动作然后登出，保存为 wireshark截包文件, 比如 dr.pcapng (扩展名为pcapng)
1-2 进入http://drcoms.github.io/drcom-generic/  
选择5.2.x Version D备用  
2.将认证服务器ip，mac地址等替换到文件（忘记用ai添加这个参数了，同学校的不用自己编译，c语言和go语言不用添加账号密码)  
<img width="1309" height="446" alt="Snipaste_2025-09-27_22-00-46" src="https://github.com/user-attachments/assets/2d394d8a-4d92-4183-a77b-6c3264459bcb" />  
c语言的不一样，例如mac地址为112233445566  
则修改为#define MAC_ADDR {0x11, 0x22, 0x33, 0x44, 0x55, 0x66}  
go语音自行学习修改找规律   
### 3.编译(go语言，c不会)   
##### 3-1-1 ARM64 版本 (64位 ARM 设备)  
安装依赖  
```BASH
sudo apt update  
sudo apt install build-essential git gcc-arm-linux-gnueabi gcc-aarch64-linux-gnu -y
```
3-1-2 编译
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
go build -o drcom-client-arm64 -ldflags="-s -w" dr.go
```
####  3-2-1ARMv7 版本 (32位 ARM 设备)
```BASH
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 \
go build -o drcom-client-armv7 -ldflags="-s -w" dr.go
```
#### 3-3-1 x86_64 版本 (64位 Linux)
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
go build -o drcom-client-x86 -ldflags="-s -w" dr.go
```
##### 3-4-1  MIPS 版本 (32位大端序)  
安装 MIPS 工具链
```bash
sudo apt install gcc-mips-linux-gnu -y
```
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=mips \
go build -o drcom-client-mips -ldflags="-s -w" dr.go
```
#### 3-5-1 MIPSEL 版本
```BASH
CGO_ENABLED=0 GOOS=linux GOARCH=mipsle \
go build -o drcom-client-mipsel -ldflags="-s -w" dr.go
```
上传的编译文件是适用某学校的，其他学校自行编译

4.运行 ./文件名 -u username -p password -i 你认证前获取的ip或者你抓包得到的hostip （选填-v，开启log输出）
## 特别指出禁止任何个人或者公司将此项目的代码投入商业使用，由此造成的后果和法律责任均与本人无关。
