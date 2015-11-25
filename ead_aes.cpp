//********************************************************************
//---文  件 名  ead_aes.cpp
//---版权所有  (c)南京天微智能科技有限公司
//---创建日期  2015.11
//---作      者  王江坤
//---版  本 号  v2.0
//---功能简述  AES加密算法定义文件
//---重要说明  本类中计算密钥长度16字节(128位)， 加密圈数10的用例
//             AES还有其他密钥长度及加密圈数，没有全部做出来
//             本方法的加密公有函数 QEncryption 中，使用了末尾随机填充(纯属自创)，有兴趣的可参考官方的填充方法，随机补位相同明文每次加密结果都不一样
//			   AES的加密模式公有5种，区别在于明文的处理方式不同，加密方法都一样，本类中使用的是电码本模式(ECB)
//********************************************************************


//------------------  发现问题请反馈邮箱 marswjk@163.com ，大家共同进步   -----------------------------

//                          知识没有产权，可是代码有，你懂的 ^_^



#include <QElapsedTimer>
#include <QTime>
#include "ead_aes.h"

//******************************************************************************
//---函 数 名 称   Ead_Aes(unsigned char* key)
//---功      能   构造函数，传入原始密钥
//---输      入   key:原始密钥
//---输      出
//---日      期   2015.11.15
//---作      者   王江坤
//---重 要 说 明   初始化加密及解密S盒，并扩展出10轮密钥
//******************************************************************************
Ead_Aes::Ead_Aes(unsigned char* key)
{    
    //初始化加密S盒
    unsigned char sBox[256] =
    { /* 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  /*0*/
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  /*1*/
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  /*2*/
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  /*3*/
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  /*4*/
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  /*5*/
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  /*6*/
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  /*7*/
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  /*8*/
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  /*9*/
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  /*a*/
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  /*b*/
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  /*c*/
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  /*d*/
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  /*e*/
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16   /*f*/
    };
    //初始化解密S盒
    unsigned char invsBox[256] =
    { /*  0    1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,  /*0*/
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,  /*1*/
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,  /*2*/
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,  /*3*/
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,  /*4*/
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,  /*5*/
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,  /*6*/
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,  /*7*/
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,  /*8*/
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,  /*9*/
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,  /*a*/
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,  /*b*/
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,  /*c*/
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,  /*d*/
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,  /*e*/
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d  /*f*/
    };
    memcpy_s(m_chSbox, 256, sBox, 256);
    memcpy_s(m_chInvSbox, 256, invsBox, 256);
    KeyExpansion(key, m_chW);
}

//******************************************************************************
//---函 数 名 称   QString QEncryption(QString plaintext)
//---功      能   对QString类型加密
//---输      入   plaintext:需要加密的QString
//---输      出   加密后的QString
//---日      期   2015.11.18
//---作      者   王江坤
//---重 要 说 明   对字符串进行随机补充、分割，字符串末两位表示为补充的字符串长度
//******************************************************************************
QString Ead_Aes::QEncryption(QString input)
{
    QString res = "";
    QString plaintext = input;
    //用于随机补位的字符串，长度77
    QString strFiller = "acE.d0Ve1H:g2hiWx*kln3&opPqr#Mst@5Ku(4yQ)zA6^BCmDF%7GIJ8L_9Nw,ObR+STjU=fXY-vZ";
    int length = plaintext.length();
    //空字符串，返回空值
    if (length == 0)
    {
        return res;
    }
    int fillLen = 0;    //需要填充的长度
    int diff = length % 16; //16位分块后余下的长度
    //余位长度不足，无法写入末两位，则增加一个块
    if (diff == 0)
    {
        fillLen = 16;
    }
    if (diff == 15)
    {
        fillLen = 17;
    }
    //余位长度足够
    if (diff >0 && diff <=14)
    {
        fillLen = 16 - diff;
    }
    //对字符串随机补位
    for (int i=0; i<fillLen-2; i++)
    {
        qsrand(QTime::currentTime().msec() + QTime::currentTime().second()* 1000);
        int asc = qrand() % 77;
        plaintext.append(strFiller.mid(asc, 1));
        QElapsedTimer t;
        t.start();
        while(t.elapsed()<13);
    }
    //在末两位写入填充长度
    QString lastTwo = QString::number(fillLen);
    if (lastTwo.length() < 2)
    {
        lastTwo.prepend("0");
    }
    plaintext.append(lastTwo);
    //逐块加密
    for (int i=0; i<plaintext.length(); i+=16)
    {
        //将16字符转换为unsigned char数组
        QByteArray mingw = plaintext.mid(i, 16).toLocal8Bit();
        const char* c_str = mingw.data();
        unsigned char chming[17];
        //memcpy_s(chming, 16, c_str, 16);
        for (int k=0; k<16; k++)
        {
            chming[k] = c_str[k] + 128;
        }
        BlockCipher(chming);
		//BlockRestore(chming);
        //将16位密文转换为16组16字节字符串，共计32位
        for (int j=0; j<16; j++)
        {
            QString qc = QString::number(chming[j], 16);
            if (qc.length() < 2)
            {
                qc.prepend("0");
            }
            res.append(qc);
        }
    }
    return res;

}

//******************************************************************************
//---函 数 名 称   QString QDecrypt(QString ciphertext)
//---功      能   对QString类型解密
//---输      入   plaintext:需要加密的QString
//---输      出   加密后的QString
//---日      期   2015.11.18
//---作      者   王江坤
//---重 要 说 明   对密文进行分割、解密、去掉随机位
//******************************************************************************
QString Ead_Aes::QDecrypt(QString input)
{
    QString res = "";
    int length = input.length();
    //密文位数有问题，返回空值
    if (length % 32 != 0)
    {
        return res;
    }
    //密文按32位分块取出进行解密
    bool ok = true;
    for (int i=0; i<length; i+=32)
    {
        unsigned char chMiw[17];
        for (int j=0; j<32; j+=2)
        {
            int k = input.mid(i + j, 2).toInt(&ok, 16);
            chMiw[j / 2] = k;
        }
        BlockRestore(chMiw);
        //将解密后的明文转换为字符串
        char ch[17];
        for (int j=0; j<16; j++)
        {
            ch[j] = chMiw[j] - 128;
        }
        ch[16] = '\0';
		QString cht = QString(ch);
		cht.remove(16, 1);
		res.append(cht);
    }
    //移除随机补位
    int addlength = res.right(2).toInt();
    length = res.length();
    res.remove(length - addlength, addlength);
    return res;
}

//******************************************************************************
//---函 数 名 称   void BlockCipher(unsigned char* block)
//---功      能   对每块16字节明文进行加密
//---输      入   block:16字节明文
//---输      出
//---日      期   2015.11.17
//---作      者   王江坤
//---重 要 说 明   对已经分割好的标准16字节明文进行加密,0-15位分割图如下
//                              0   4   8   12
//                              1   5   9   13
//                              2   6   10  14
//                              3   7   11  15
//******************************************************************************
void Ead_Aes::BlockCipher(unsigned char* block)
{
    unsigned char state[4][4];//存储转变为矩阵的16字符(128字节)明文
    //将明文转换为C++二维数组
    int r = 0;//数组行
    int c = 0;//数组列
    for (r=0; r<4; r++)
    {
        for (c=0; c<4; c++)
        {
            state[r][c] = block[c * 4 + r];
        }
    }
    //进入10圈加密前，先进行一次轮密钥加变换
    AddRoundKey(state, m_chW[0]);
    for (int i=1; i<=9; i++)
    {
        SubStituteBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, m_chW[i]);
    }
    //10圈加密后，再分别进行一次字节替换、行移位、轮密钥加
    SubStituteBytes(state);
    ShiftRows(state);
    AddRoundKey(state, m_chW[10]);
    //返还加密后的16字符
    for (r=0; r<4; r++)
    {
        for (c=0; c<4; c++)
        {
            block[c * 4 + r] = state[r][c];
        }
    }
}

//******************************************************************************
//---函 数 名 称   void BlockRestore(unsigned char* block)
//---功      能   对每块加密的16字节密文进行还原
//---输      入   block:需要还原的密码块
//---输      出
//---日      期   2015.11.17
//---作      者   王江坤
//---重 要 说 明
//******************************************************************************
void Ead_Aes::BlockRestore(unsigned char* block)
{
    unsigned char state[4][4];
    //将密文块存入数组
    for(int r=0; r<4; r++)
    {
        for(int c=0; c<4 ;c++)
        {
            state[r][c] = block[c * 4 + r];
        }
    }
    AddRoundKey(state, m_chW[10]);
    for(int i=9; i>0; i--)
    {
        RevShiftRows(state);
        RevSubStituteBytes(state);
        AddRoundKey(state, m_chW[i]);
        RevMixColumns(state);
    }
    RevShiftRows(state);
    RevSubStituteBytes(state);
    AddRoundKey(state, m_chW[0]);

    for(int r=0; r<4; r++)
    {
        for(int c=0; c<4 ;c++)
        {
            block[c * 4 + r] = state[r][c];
        }
    }
}

//******************************************************************************
//---函 数 名 称   unsigned char FFmul(unsigned char a, unsigned char b)
//---功      能   有限域GF(2^8)上的乘法
//---输      入   a:乘法因子  b:明文
//---输      出
//---日      期   2015.11.17
//---作      者   王江坤
//---重 要 说 明   标准算法应该是循环8次（b与a的每一位相乘，结果相加），但这里只用到最低2位
//               解密时用到的逆列混淆也只用了低4位，所以在这里高4位的运算是多余的，只计算低4位
//******************************************************************************
unsigned char Ead_Aes::FFmul(unsigned char a, unsigned char b)
{
    unsigned char bw[4];
    unsigned char res = 0;
    int i;
    bw[0] = b;
    for(i=1; i<4; i++)
    {
      bw[i] = bw[i - 1] << 1;
      if(bw[i - 1] & 0x80)
      {
          bw[i] ^= 0x1b;
      }
    }
    for(i=0; i<4; i++)
    {
      if((a >> i) & 0x01)
      {
          res ^= bw[i];
      }
    }
    return res;
}

//******************************************************************************
//---函 数 名 称   void AddRoundKey(unsigned char state[4][4], unsigned char k[4][4])
//---功      能   轮密钥加变换
//---输      入   state:需要变换的明文    k:当前轮的轮密钥
//---输      出
//---日      期   2015.11.16
//---作      者   王江坤
//---重 要 说 明   将轮密钥与明文的同行同列进行异或运算
//******************************************************************************
void Ead_Aes::AddRoundKey(unsigned char state[4][4], unsigned char k[4][4])
{
    for (int c=0; c<4; c++)
    {
        for (int r=0; r<4; r++)
        {
            state[r][c] ^= k[r][c];
        }
    }
}

//******************************************************************************
//---函 数 名 称   void SubStituteBytes(unsigned char state[4][4])
//---功      能   字节替换
//---输      入   state:需要替换的明文
//---输      出
//---日      期   2015.11.16
//---作      者   王江坤
//---重 要 说 明   用加密S盒中的数据代替明文中的数据  例如明文中有数据0x3e，则用加密S盒中第3行，第e列的数据代替
//******************************************************************************
void Ead_Aes::SubStituteBytes(unsigned char state[4][4])
{
    for (int c=0; c<4; c++)
    {
        for (int r=0; r<4; r++)
        {
            state[r][c] = m_chSbox[state[r][c]];
        }
    }
}

//******************************************************************************
//---函 数 名 称   void ShiftRows(unsigned char state[4][4])
//---功      能   行移位
//---输      入   state:需要移位的明文
//---输      出
//---日      期   2015.11.16
//---作      者   王江坤
//---重 要 说 明   明文第0行不动，第1行向左移1位，第2行向左移2位，第3行向左移3位
//******************************************************************************
void Ead_Aes::ShiftRows(unsigned char state[4][4])
{
    unsigned char temp[4];
    for(int r=1; r<4; r++)
    {
        for(int c=0; c<4; c++)
        {
            temp[c] = state[r][(c + r) % 4];
        }
        for(int c=0; c<4; c++)
        {
            state[r][c] = temp[c];
        }
    }

}

//******************************************************************************
//---函 数 名 称   void MixColumns(unsigned char state[4][4])
//---功      能   列混淆
//---输      入   state:明文
//---输      出
//---日      期   2015.11.17
//---作      者   王江坤
//---重 要 说 明   列混淆即是用一个常矩阵乘以第二步变换后的矩阵，以达到矩阵中每一个元素都是该元素原所在列所有元素的加权和
//                                  0x02 0x03 0x01 0x01
//                                  0x01 0x02 0x03 0x01
//                                  0x01 0x01 0x02 0x03
//                                  0x03 0x01 0x01 0x02
//******************************************************************************
void Ead_Aes::MixColumns(unsigned char state[4][4])
{
    unsigned char temp[4];
    for(int c=0; c<4; c++)
    {
        for(int r=0; r<4; r++)
        {
            temp[r] = state[r][c];
        }
        for(int r=0; r<4; r++)
        {
            state[r][c] = FFmul(0x02, temp[r])
                        ^ FFmul(0x03, temp[(r + 1) % 4])
                        ^ FFmul(0x01, temp[(r + 2) % 4])
                        ^ FFmul(0x01, temp[(r + 3) % 4]);
        }
    }
}

//******************************************************************************
//---函 数 名 称   void RevSubStituteBytes(unsigned char state[4][4])
//---功      能   解密字节替换
//---输      入   state:需要替换的明文
//---输      出
//---日      期   2015.11.17
//---作      者   王江坤
//---重 要 说 明   解密过程的字节替换,使用解密S盒进行替换
//******************************************************************************
void Ead_Aes::RevSubStituteBytes(unsigned char state[4][4])
{
    for (int c=0; c<4; c++)
    {
        for (int r=0; r<4; r++)
        {
            state[r][c] = m_chInvSbox[state[r][c]];
        }
    }
}

//******************************************************************************
//---函 数 名 称   void RevShiftRows(unsigned char state[4][4])
//---功      能   解密行移位
//---输      入   state:需要移位的明文
//---输      出
//---日      期   2015.11.16
//---作      者   王江坤
//---重 要 说 明   明文第0行不动，第1行向右移1位，第2行向右移2位，第3行向右移3位
//******************************************************************************
void Ead_Aes::RevShiftRows(unsigned char state[4][4])
{
    unsigned char temp[4];
    for(int r=1; r<4; r++)
    {
        for(int c=0; c<4; c++)
        {
            temp[c] = state[r][(c - r + 4) % 4];
        }
        for(int c=0; c<4; c++)
        {
            state[r][c] = temp[c];
        }
    }
}

//******************************************************************************
//---函 数 名 称   void MixColumns(unsigned char state[4][4])
//---功      能   解密列混淆
//---输      入   state:明文
//---输      出
//---日      期   2015.11.17
//---作      者   王江坤
//---重 要 说 明   列混淆即是用一个常矩阵乘以第二步变换后的矩阵，以达到矩阵中每一个元素都是该元素原所在列所有元素的加权和
//                                  0x0e 0x0b 0x0d 0x09
//                                  0x09 0x0e 0x0b 0x0d
//                                  0x0d 0x09 0x0e 0x0b
//                                  0x0b 0x0d 0x09 0x0e
//******************************************************************************
void Ead_Aes::RevMixColumns(unsigned char state[4][4])
{
    unsigned char temp[4];
    for(int c=0; c<4; c++)
    {
        for(int r=0; r<4; r++)
        {
            temp[r] = state[r][c];
        }
        for(int r=0; r<4; r++)
        {
            state[r][c] = FFmul(0x0e, temp[r])
                        ^ FFmul(0x0b, temp[(r + 1) % 4])
                        ^ FFmul(0x0d, temp[(r + 2) % 4])
                        ^ FFmul(0x09, temp[(r + 3) % 4]);
        }
    }
}

//******************************************************************************
//---函 数 名 称   void KeyExpansion(unsigned char* key, unsigned char w[][4][4])
//---功      能   密钥扩展
//---输      入   key:原始密钥字符串地址指针   w[][4][4]:扩展后的密钥
//---输      出
//---日      期   2015.11.15
//---作      者   王江坤
//---重 要 说 明   将输入的密钥kye扩展为11组128位密钥组，其中0组为原密钥(限定原密钥为16字符，即128位)
//******************************************************************************
void Ead_Aes::KeyExpansion(unsigned char* key, unsigned char w[][4][4])
{
    unsigned char rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
    //扩展密钥第0组为原密钥
    int r = 0;
    int c = 0;
    int m = 0;
    for (r=0; r<4; r++)
    {
        for (c=0; c<4; c++)
        {
            w[0][r][c] = key[r + c * 4];
        }
    }
    //扩展密钥第1组到第10组
    for (int i=1; i<=10; i++)
    {
        //对第i轮密钥的4列分别进行扩展
        for(int j=0; j<4; j++)
        {
            unsigned char temp[4];  //存储临时列
            //临时列，当前轮第一列，取上一轮最后一列的数据，2到4列取当前轮前一列数据
            for (m=0; m<4; m++)
            {
                temp[m] = j ? w[i][m][j - 1] : w[i - 1][m][3];
            }
            //第一列数据左移一位，并与S盒交换
            if (j == 0)
            {
                //数据左移一位
                unsigned char t = temp[0];
                for (m=0; m<3; m++)
                {
                    temp[m] = temp[m + 1];
                }
                temp[3] = t;
                //与S盒交换
                for (m=0; m<4; m++)
                {
                    temp[m] = m_chSbox[temp[m]];
                }
                //第一列第一个数据与rcon数组异或
                temp[0] ^= rcon[i - 1];
            }
            //当前轮与上一轮同列异或
            for (m=0; m<4; m++)
            {
                w[i][m][j] = w[i-1][m][j] ^ temp[m];
            }
        }
    }
}
