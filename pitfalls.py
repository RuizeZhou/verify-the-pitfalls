#coding:utf-8
#verify the above pitfalls with proof-of-concept code
from utils import N,P,G
import ecdsa
import utils
import secrets
from ecdsa import generate_key
import random

k = secrets.randbelow(P)#0~P的随机数
# k=19032327043088631316439290381930709354608949219184001686906494989587616666744
print('k=',k)
''''''''''''
def sign(private_key, message):#私钥签名
    e = hash(message)#哈希
    # k=12581384025608555250890351613719061476129424215689402246915303910451212003013
    random_point = utils.elliptic_multiply(k, G)#P点=k*G
    r = random_point[0] % N
    s = utils.mod_inverse(k, N) * (e + r*private_key) %N#用私钥进行签名

    return (r, s)#以元组形式存在的签名

'''验证'''
def verify(m,r,s,pub_key):
    e=hash(m)
    s_1=utils.mod_inverse(s,N)%N

    a=utils.elliptic_multiply(e*s_1%N,G)
    b=utils.elliptic_multiply(r*s_1 %N,pub_key)
    recovered_point=utils.elliptic_add(a,b)

    r_new=recovered_point[0]
    # print(r)
    # print(r_new)
    if r_new==r:
        print("verify succ")
        return 1
    else:
        print("verify fail")
        return 0

'''verification does not check m'''
def verify_no_m(e,r,s,pub_key):
    s_1=utils.mod_inverse(s,N)%N

    a=utils.elliptic_multiply(e*s_1%N,G)
    b=utils.elliptic_multiply(r*s_1 %N,pub_key)
    recovered_point=utils.elliptic_add(a,b)

    r_new=recovered_point[0]
    # print(r)
    # print(r_new)
    if r_new==r:
        print("verify succ")
        return 1
    else:
        print("verify fail")
        return 0






''' Leaking k leads to leaking of d'''
def leaking_k(message,r,s):
    e = hash(message)
    d = utils.mod_inverse(r,N)*(k*s-e) %N
    print("Leaking k leads to leaking of d ,private key:d=",d)
    return d





''' Reusing k leads to leaking of d'''
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


'''Two users, using k leads to leaking of d, that is they can deduce each other’s d'''
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






'''Malleability, e.g. (r,s) and (r,-s)are both valid signatures, lead to blockchain network split'''
def Malleability():
    signature=sign(pri_key1,message1)
    print('sigmature:',signature)
    r=signature[0]
    s=signature[1]
    verify(message1,r,s,pub_key1)
    verify(message1,r,-s%N,pub_key1)


'''Ambiguity of DER encode could lead to blockchain network split'''






'''One can forge signature if the verification does not check m'''
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



'''Same d and k with ECDSA, leads to leaking of d'''
'''Schnorr:'''
def schnorr(pri_key,message):
    R=utils.elliptic_multiply(k,G)
    tem=str(R[0])+str(message)
    e=hash(tem)
    s=(k+e*pri_key)%N
    return R,e,s

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








if __name__=='__main__':
    message1 = "hello,world!"
    message2 ="abandon"

    keys1=generate_key()
    # print('keys:',keys)
    # keys=(16416302799941546994684581689615732774280299348770021550884396273987385006872, (50663178404966299982871470853531608409398292258634454823862857216237319864346, 33790061684382316738947273482981693896472019888899392102580549305789342175879))

    pri_key1=keys1[0]
    pub_key1=keys1[1]
    # print('pri:',pri_key)
    # print('pub:',pub_key)



    '''1.泄露k：'''
    # signature=sign(pri_key1,message1)
    # r=signature[0]
    # s=signature[1]
    # leaking_k(message1,r,s)

    '''2.重复使用k'''
    # reuseing_k(message1,message2)


    '''3.不同用户使用相同的k'''
    keys2=generate_key()
    pri_key2=keys2[0]
    pub_key2=keys2[1]
    # reusing_k_by_2(message1,message2)


    '''4.(r,s),(r,-s)'''
    # Malleability()


    '''6.伪造'''
    # forge(message1)


    '''7.和ECDSA相同的d,k。导致泄露d（私钥）'''
    same_dk_withECDSA(pri_key1,message1)




