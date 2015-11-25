//********************************************************************
//---文  件 名  ead_aes.h
//---版权所有  (c)南京天微智能科技有限公司
//---创建日期  2015.11
//---作      者  王江坤
//---版  本 号  v2.0
//---功能简述  AES加密算法头文件
//---重要说明  本类中计算密钥长度16字节(128位)， 加密圈数10的用例
//             AES还有其他密钥长度及加密圈数，没有全部做出来
//             本方法的加密公有函数 QEncryption 中，使用了末尾随机填充(纯属自创)，有兴趣的可参考官方的填充方法,随机补位相同明文每次加密结果都不一样
//			   AES的加密模式公有5种，区别在于明文的处理方式不同，加密方法都一样，本类中使用的是电码本模式(ECB)
//********************************************************************


//------------------  发现问题请反馈邮箱 marswjk@163.com ，大家共同进步   -----------------------------

//                          知识没有产权，可是代码有，你懂的 ^_^



#ifndef ALGORITHM_EAD_AES_H
#define ALGORITHM_EAD_AES_H

#include "qglobal.h"


class Ead_Aes
{
public:
    Ead_Aes(unsigned char* key);
    QString QEncryption(QString input); //对QString类型加密
    QString QDecrypt(QString input);   //对QString解密

private:
    void BlockCipher(unsigned char* block);   //对每块16字节明文进行加密
    void BlockRestore(unsigned char* block);  //对每块加密的16字节密文进行还原
    unsigned char FFmul(unsigned char a, unsigned char b);  //有限域GF(28)上的乘法
    void AddRoundKey(unsigned char state[4][4], unsigned char k[4][4]); //轮密钥加
    void SubStituteBytes(unsigned char state[4][4]); //字节替换
    void ShiftRows(unsigned char state[4][4]);   //行移位
    void MixColumns(unsigned char state[4][4]);  //列混淆
    void RevSubStituteBytes(unsigned char state[4][4]); //解密字节替换
    void RevShiftRows(unsigned char state[4][4]);   //解密行移位
    void RevMixColumns(unsigned char state[4][4]);  //解密列混淆
    void KeyExpansion(unsigned char* key, unsigned char w[][4][4]);    //密钥扩展

private:
    unsigned char m_chSbox[256];    //加密S盒
    unsigned char m_chInvSbox[256]; //解密S盒
    unsigned char m_chW[11][4][4]; //密钥扩展
};

#endif //ALGORITHM_EAD_AES_H
