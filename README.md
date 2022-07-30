# verify-the-pitfalls

mainly with ECDSA
·Leaking k leads to leaking of d
·Reusing k leads to leaking of d
···

# 项目说明

**1.小组成员**：周睿泽。git账户名称：RuizeZhou

**2,所作项目名称：**

本项目名称为：Project: verify the above pitfalls with proof-of-concept code

简介：实现并证明ppt上的pitfalls，编程语言为python。

mainly with ECDSA

·Leaking k leads to leaking of d

·Reusing k leads to leaking of d

···


完成人：周睿泽

**3.清单：**

完成的项目：

√Project: implement the naïve birthday attack of reduced SM3 

√Project: implement the Rho method of reduced SM3

√Project: implement length extension attack for SM3, SHA256, etc.

√Project: do your best to optimize SM3 implementation (software)

√Project: Impl Merkle Tree following RFC6962

√Project: report on the application of this deduce technique in Ethereum with ECDSA

√Project: Implement sm2 with RFC6979

√Project: verify the above pitfalls with proof-of-concept code

√Project: Implement a PGP scheme with SM2

未完成的项目：

Project: Try to Implement this scheme

Project: Implement the above ECMH scheme

Project: implement sm2 2P sign with real network communication

Project: implement sm2 2P decrypt with real network communication

Project: PoC impl of the scheme, or do implement analysis by Google

Project: forge a signature to pretend that you are Satoshi

Project: send a tx on Bitcoin testnet, and parse the tx data down to every bit, better write script yourself

Project: forge a signature to pretend that you are Satoshi

Project: research report on MPT

Project: Find a key with hash value “sdu_cst_20220610” under a message composed of your name followed by your student ID. For example, “San Zhan 202000460001”.

有问题的项目及问题：\


**4.本项目具体内容：** 具体内容如下

# verify-the-pitfalls



Project: verify the above pitfalls with proof-of-concept code

### A.具体的项目代码说明

本项目代码需要同文件夹下的utils包和ecdsa包，以提供椭圆曲线上的计算等函数。由于涉及到对k的泄露或复用，在此k的生成从函数中移出，作为全局变量使用。

本项目内的内容主要基于数学公式推导，完成如下：

1.当泄露k，造成私钥的泄露：

根据公式即可以推断私钥d：

```
def leaking_k(message,r,s):
    e = hash(message)
    d = utils.mod_inverse(r,N)*(k*s-e) %N
    print("Leaking k leads to leaking of d ,private key:d=",d)
    return d
```

2.重新使用相同的k导致私钥的泄露：

```
def reuseing_k(m1,m2):
    signature1=sign(pri_key1,m1)
    r1=signature1[0]
    s1=signature1[1]
    signature2=sign(pri_key1,m2)
    r2=signature2[0]
    s2=signature2[1]
    print('true d:',pri_key1)
    e1=hash(m1)
    e2=hash(m2)
    d2=(s1*e2-s2*e1)*utils.mod_inverse((s2*r1-s1*r2)%N,N)%N
    print('Reusing k leads to leaking of d,d2=',d2)
```

3.两个不同的用户，使用相同的k，导致泄露各自的密钥：

```
def reusing_k_by_2(m1,m2):
    r,s1=sign(pri_key1,m1)
    r,s2=sign(pri_key2,m2)
    e1=hash(m1)
    e2=hash(m2)
    d2=(s2 * e1 - s1 * e2 + s2 * r * pri_key1) *utils.mod_inverse(s1 * r, N) % N
    print('用户2的实际私钥：',pri_key2)
    print('用户1计算出用户2的私钥：',d2)

    d1=(s1 * e2 - s2 * e1 + s1 * r * pri_key2) *utils.mod_inverse(s2 * r, N) % N
    print('用户2的实际私钥：',pri_key1)
    print('用户1计算出用户2的私钥：',d1)
```

4.(r,s)和(r,-s)都是有效签名：

```
def Malleability():
    signature=sign(pri_key1,message1)
    print('sigmature:',signature)
    r=signature[0]
    s=signature[1]
    verify(message1,r,s,pub_key1)
    verify(message1,r,-s%N,pub_key1)
```

6.如果验证不检查m，可以伪造签名：

```
def forge(m1):
    r,s1=sign(pri_key1,m1)
    ran1=random.randint(1,N)
    ran2=random.randint(1,N)
 			   	newpoint=utils.elliptic_add(utils.elliptic_multiply(ran1,G),utils.elliptic_multiply(ran2,pub_key1))
    r_1=newpoint[0]
    e_1=r_1*ran1*utils.mod_inverse(ran2,N)%N
    s_1=r_1*utils.mod_inverse(ran2,N)%N

    if verify_no_m(e_1,r_1,s_1,pub_key1)==1:
        print('伪造成功')    
```

这里的验证函数并不要求输入消息。具体函数内容见代码

7.Schnorr算法中如果使用与ECDSA相同的私钥和k，那么会泄露该Schnorr方案中的私钥

```
def same_dk_withECDSA(pri_key,m):
    R,e2,s2=schnorr(pri_key,m)
    r1,s1=sign(pri_key,m)
    e1=hash(m)
    s1=(e1+r1*pri_key)*utils.mod_inverse((s2-e2*pri_key)%N,N)%N
    d_new=(s1*s2-e1)*utils.mod_inverse(s1*e2+r1,N)%N
    print('true d:',pri_key)
    print('Same d and k with ECDSA, leads to leaking of d:',d_new)
    if pri_key==d_new:
        print('succ')
        return 1
    else:
        print('false')
        return 0
```

### B.运行指导(跑不起来的不算成功)

​	在main主函数中取消注释需要运行查看的pitfall代码即可：

![1659170667409](https://cdn.jsdelivr.net/gh/RuizeZhou/images/1659170667409.png)





### C.代码运行全过程截图(无截图无说明的代码不给分)

依次运行结果如下：

1.前几行显示k及公私钥对信息，最后输出函数推测私钥结果，与前面的私钥信息相等。![1659170697324](https://cdn.jsdelivr.net/gh/RuizeZhou/images/1659170697324.png)

2.前几行显示k及公私钥对信息，最后输出函数推测私钥结果，与前面的私钥信息相等。![1659170711723](https://cdn.jsdelivr.net/gh/RuizeZhou/images/1659170711723.png)

3.前几行显示k及两个用户各自的公私钥对信息，最后输出函数推测私钥结果，与前面的私钥信息相等。

![1659170735333](https://cdn.jsdelivr.net/gh/RuizeZhou/images/1659170735333.png)

4.前几行显示k及两个用户各自的公私钥对信息，最后验证签名是否满足verify

![1659170764052](https://cdn.jsdelivr.net/gh/RuizeZhou/images/1659170764052.png)

6.前几行显示k及两个用户各自的公私钥对信息，最后验证如果使用不验证m的Verify函数能否通过验证，显示成立。

![1659170808453](https://cdn.jsdelivr.net/gh/RuizeZhou/images/1659170808453.png)

7.前几行显示k及两个用户各自的公私钥对信息，最后将Schnorr的真实私钥和推测的私钥进行对比，显示一致。

![1659170826717](https://cdn.jsdelivr.net/gh/RuizeZhou/images/1659170826717.png)



### D.每个人的具体贡献说明及贡献排序(复制的代码需要标出引用)

​	本人负责全部。

