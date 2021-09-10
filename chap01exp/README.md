# 网络安全课程第一次实验 实验报告

## 实验目的

- 掌握 VirtualBox 虚拟机的安装与使用；
- 掌握 VirtualBox 的虚拟网络类型和按需配置；
- 掌握 VirtualBox 的虚拟硬盘多重加载；

## 实验环境

- VirtualBox虚拟机
- 攻击者主机（Attacker）：Kali Rolling 2109.2
- 网关（Gateway, GW）：Debian Buster
- 靶机（Victim）：From Sqli to shell / xp-sp3 / Kali

## 实验要求
[√] 虚拟硬盘配置成多重加载

[√] 搭建满足如下拓扑图所示的虚拟机网络拓扑；
![](https://c4pr1c3.gitee.io/cuc-ns/chap0x01/attach/chap0x01/media/vb-exp-layout.png)

完成以下网络连通性测试：

[√] 靶机可以直接访问攻击者主机

[√] 攻击者主机无法直接访问靶机

[√] 网关可以直接访问攻击者主机和靶机

[√] 靶机的所有对外上下行流量必须经过网关

[√] 所有节点均可以访问互联网

## 实验流程

创建六台虚拟机，其中有两台采用Windows xp系统，两台使用Debian 10 系统，两台使用Kali系统。

其中，一台Kali系统的虚拟机将扮演攻击者的角色，一台Debian系统的虚拟机将作为网关。一个Windows系统与一个Kali系统的虚拟机在一个局域网下作为Alpha组的受害者，一个Windows系统与一个Kali系统的虚拟机在另一个局域网下作为Bravo组的受害者

## 实现

### attacker网络设置

在virtualbox中为攻击者设置一张网卡，模式为NAT网络，在此之前，需要在virtualbox的全局设定中添加NAT网络
![添加NAT网络设置-1](./img/添加NAT网络设置-1.png)
![添加NAT网络设置-2](./img/添加NAT网络设置-2.png)

设定完成后，将attacker的网卡设置为NAT网络
![attacker设置网络](./img/attacker设置网络.png)

### victim网络设置

处在同一局域网下的victim使用同一块“内部网络”网卡，Alpha使用intnet#1，Bravo使用intnet#2

![Alpha内部网卡1](./img/Alpha内部网卡1.png)
![Alpha内部网卡1](./img/Alpha内部网卡2.png)
![Bravo内部网卡1](./img/Bravo内部网卡1.png)
![Bravo内部网卡2](./img/Bravo内部网卡2.png)

### 网关网络设置

网关需要设定四块网卡，第一块网卡使用Nat模式，第二块使用Host-Only模式，第三与第四块使用内部网络模式

![网关](./img/网关网络设置.png)

## 网络连通性测试

### 外网连通性
__各结点均可以访问外网__

attacker外网连通性测试：

![Attacker外网连通性](./img/attacker连通外网测试.png)

Debian victim外网连通性测试：

![victim外网连通性](./img/Debian连通外网测试.png)

Windows外网连通性测试：

![victim外网连通性](./img/Window外网连通性测试.png)

网关外网连通性测试：

![网关外网连通性](./img/网关连通外网测试.png)

### victim可以连通attacker，但attacker不能连通victim

victim可以连通attacker：

Alpha组：

![v-a](./img/Windows连通攻击者测试.png)

Bravo组：

![v-a](./img/Debian连通attacker测试.png)

attacker不能连通victim：

Alpha组：

![a-v](./img/attacker访问victim1测试.png)

Bravo组：

![a-v](./img/attacker访问victim2测试.png)

### 网关连通性测试

网关访问attacker：

![gateway](./img/网关连通Attacker测试.png)

网关访问Alpha：

![gateway](./img/GtoAlpha.png)

网关访问Bravo：

![gateway](./img/GtoBravo.png)

### 不同局域网之间的主机不能连通

Alpha不能访问Bravo：

![A-B](./img/Alpha连通Bravo测试.png)

Bravo不能访问Alpha：

![B-A](./img/Bravo连通Alpha测试.png)

### Alpha与Bravo的流量都是经过Gateway

![Gatewayoff](./img/Gatewayoff.png)

## 实验中出现的问题

1. 测试网关与Windows系统的连通性时，需要关闭Windows防火墙，不然无法ping通

2. 同一局域网下的victim的网卡设置需要名称一致

3.通过Nat网络模式可以使attacker与其他主机处于独立的网络空间

## 各主机网络配置

主机 | IP地址
--|--
Alpha-Windows | 172.16.111.141
Alpha-Kali | 172.16.111.111
Bravo-Windows | 172.16.222.124
Bravo-Debian | 172.16.222.106
Attacker | 10.0.2.15
Gateway | 192.168.56.113