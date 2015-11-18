//********************************************************************
//---��  �� ��  ead_aes.cpp
//---��Ȩ����  (c)�Ͼ���΢���ܿƼ����޹�˾
//---��������  2015.11
//---��      ��  ������
//---��  �� ��  v2.0
//---���ܼ���  AES�����㷨�����ļ�
//---��Ҫ˵��
//********************************************************************

#include <QElapsedTimer>
#include <QTime>
#include "ead_aes.h"

//******************************************************************************
//---�� �� �� ��   Ead_Aes(unsigned char* key)
//---��      ��   ���캯��������ԭʼ��Կ
//---��      ��   key:ԭʼ��Կ
//---��      ��
//---��      ��   2015.11.15
//---��      ��   ������
//---�� Ҫ ˵ ��   ��ʼ�����ܼ�����S�У�����չ��10����Կ
//******************************************************************************
Ead_Aes::Ead_Aes(unsigned char* key)
{    
    //��ʼ������S��
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
    //��ʼ������S��
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
//---�� �� �� ��   QString QEncryption(QString plaintext)
//---��      ��   ��QString���ͼ���
//---��      ��   plaintext:��Ҫ���ܵ�QString
//---��      ��   ���ܺ��QString
//---��      ��   2015.11.18
//---��      ��   ������
//---�� Ҫ ˵ ��   ���ַ�������������䡢�ָ�ַ���ĩ��λ��ʾΪ������ַ�������
//******************************************************************************
QString Ead_Aes::QEncryption(QString input)
{
    QString res = "";
    QString plaintext = input;
    //���������λ���ַ���������77
    QString strFiller = "acE.d0Ve1H:g2hiWx*kln3&opPqr#Mst@5Ku(4yQ)zA6^BCmDF%7GIJ8L_9Nw,ObR+STjU=fXY-vZ";
    int length = plaintext.length();
    //���ַ��������ؿ�ֵ
    if (length == 0)
    {
        return res;
    }
    int fillLen = 0;    //��Ҫ���ĳ���
    int diff = length % 16; //16λ�ֿ�����µĳ���
    //��λ���Ȳ��㣬�޷�д��ĩ��λ��������һ����
    if (diff == 0)
    {
        fillLen = 16;
    }
    if (diff == 15)
    {
        fillLen = 17;
    }
    //��λ�����㹻
    if (diff >0 && diff <=14)
    {
        fillLen = 16 - diff;
    }
    //���ַ��������λ
    for (int i=0; i<fillLen-2; i++)
    {
        qsrand(QTime::currentTime().msec() + QTime::currentTime().second()* 1000);
        int asc = qrand() % 77;
        plaintext.append(strFiller.mid(asc, 1));
        QElapsedTimer t;
        t.start();
        while(t.elapsed()<13);
    }
    //��ĩ��λд����䳤��
    QString lastTwo = QString::number(fillLen);
    if (lastTwo.length() < 2)
    {
        lastTwo.prepend("0");
    }
    plaintext.append(lastTwo);
    //������
    for (int i=0; i<plaintext.length(); i+=16)
    {
        //��16�ַ�ת��Ϊunsigned char����
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
        //��16λ����ת��Ϊ16��16�ֽ��ַ���������32λ
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
//---�� �� �� ��   QString QDecrypt(QString ciphertext)
//---��      ��   ��QString���ͽ���
//---��      ��   plaintext:��Ҫ���ܵ�QString
//---��      ��   ���ܺ��QString
//---��      ��   2015.11.18
//---��      ��   ������
//---�� Ҫ ˵ ��   �����Ľ��зָ���ܡ�ȥ�����λ
//******************************************************************************
QString Ead_Aes::QDecrypt(QString input)
{
    QString res = "";
    int length = input.length();
    //����λ�������⣬���ؿ�ֵ
    if (length % 32 != 0)
    {
        return res;
    }
    //���İ�32λ�ֿ�ȡ�����н���
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
        //�����ܺ������ת��Ϊ�ַ���
        char* ch = new char[17];
        for (int j=0; j<16; j++)
        {
            ch[j] = chMiw[j] - 128;
        }
        ch[17] = '\0';
		QString cht = QString(ch);
		cht.remove(16, 1);
		res.append(cht);
        delete ch;
    }
    //�Ƴ������λ
    int addlength = res.right(2).toInt();
    length = res.length();
    res.remove(length - addlength, addlength);
    return res;
}

//******************************************************************************
//---�� �� �� ��   void BlockCipher(unsigned char* block)
//---��      ��   ��ÿ��16�ֽ����Ľ��м���
//---��      ��   block:16�ֽ�����
//---��      ��
//---��      ��   2015.11.17
//---��      ��   ������
//---�� Ҫ ˵ ��   ���Ѿ��ָ�õı�׼16�ֽ����Ľ��м���,0-15λ�ָ�ͼ����
//                              0   4   8   12
//                              1   5   9   13
//                              2   6   10  14
//                              3   7   11  15
//******************************************************************************
void Ead_Aes::BlockCipher(unsigned char* block)
{
    unsigned char state[4][4];//�洢ת��Ϊ�����16�ַ�(128�ֽ�)����
    //������ת��ΪC++��ά����
    int r = 0;//������
    int c = 0;//������
    for (r=0; r<4; r++)
    {
        for (c=0; c<4; c++)
        {
            state[r][c] = block[c * 4 + r];
        }
    }
    //����10Ȧ����ǰ���Ƚ���һ������Կ�ӱ任
    AddRoundKey(state, m_chW[0]);
    for (int i=1; i<=9; i++)
    {
        SubStituteBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, m_chW[i]);
    }
    //10Ȧ���ܺ��ٷֱ����һ���ֽ��滻������λ������Կ��
    SubStituteBytes(state);
    ShiftRows(state);
    AddRoundKey(state, m_chW[10]);
    //�������ܺ��16�ַ�
    for (r=0; r<4; r++)
    {
        for (c=0; c<4; c++)
        {
            block[c * 4 + r] = state[r][c];
        }
    }
}

//******************************************************************************
//---�� �� �� ��   void BlockRestore(unsigned char* block)
//---��      ��   ��ÿ����ܵ�16�ֽ����Ľ��л�ԭ
//---��      ��   block:��Ҫ��ԭ�������
//---��      ��
//---��      ��   2015.11.17
//---��      ��   ������
//---�� Ҫ ˵ ��
//******************************************************************************
void Ead_Aes::BlockRestore(unsigned char* block)
{
    unsigned char state[4][4];
    //�����Ŀ��������
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
//---�� �� �� ��   unsigned char FFmul(unsigned char a, unsigned char b)
//---��      ��   ������GF(2^8)�ϵĳ˷�
//---��      ��   a:�˷�����  b:����
//---��      ��
//---��      ��   2015.11.17
//---��      ��   ������
//---�� Ҫ ˵ ��   ��׼�㷨Ӧ����ѭ��8�Σ�b��a��ÿһλ��ˣ������ӣ���������ֻ�õ����2λ
//               ����ʱ�õ������л���Ҳֻ���˵�4λ�������������4λ�������Ƕ���ģ�ֻ�����4λ
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
//---�� �� �� ��   void AddRoundKey(unsigned char state[4][4], unsigned char k[4][4])
//---��      ��   ����Կ�ӱ任
//---��      ��   state:��Ҫ�任������    k:��ǰ�ֵ�����Կ
//---��      ��
//---��      ��   2015.11.16
//---��      ��   ������
//---�� Ҫ ˵ ��   ������Կ�����ĵ�ͬ��ͬ�н����������
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
//---�� �� �� ��   void SubStituteBytes(unsigned char state[4][4])
//---��      ��   �ֽ��滻
//---��      ��   state:��Ҫ�滻������
//---��      ��
//---��      ��   2015.11.16
//---��      ��   ������
//---�� Ҫ ˵ ��   �ü���S���е����ݴ��������е�����  ����������������0x3e�����ü���S���е�3�У���e�е����ݴ���
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
//---�� �� �� ��   void ShiftRows(unsigned char state[4][4])
//---��      ��   ����λ
//---��      ��   state:��Ҫ��λ������
//---��      ��
//---��      ��   2015.11.16
//---��      ��   ������
//---�� Ҫ ˵ ��   ���ĵ�0�в�������1��������1λ����2��������2λ����3��������3λ
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
//---�� �� �� ��   void MixColumns(unsigned char state[4][4])
//---��      ��   �л���
//---��      ��   state:����
//---��      ��
//---��      ��   2015.11.17
//---��      ��   ������
//---�� Ҫ ˵ ��   �л���������һ����������Եڶ����任��ľ����Դﵽ������ÿһ��Ԫ�ض��Ǹ�Ԫ��ԭ����������Ԫ�صļ�Ȩ��
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
//---�� �� �� ��   void RevSubStituteBytes(unsigned char state[4][4])
//---��      ��   �����ֽ��滻
//---��      ��   state:��Ҫ�滻������
//---��      ��
//---��      ��   2015.11.17
//---��      ��   ������
//---�� Ҫ ˵ ��   ���ܹ��̵��ֽ��滻,ʹ�ý���S�н����滻
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
//---�� �� �� ��   void RevShiftRows(unsigned char state[4][4])
//---��      ��   ��������λ
//---��      ��   state:��Ҫ��λ������
//---��      ��
//---��      ��   2015.11.16
//---��      ��   ������
//---�� Ҫ ˵ ��   ���ĵ�0�в�������1��������1λ����2��������2λ����3��������3λ
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
//---�� �� �� ��   void MixColumns(unsigned char state[4][4])
//---��      ��   �����л���
//---��      ��   state:����
//---��      ��
//---��      ��   2015.11.17
//---��      ��   ������
//---�� Ҫ ˵ ��   �л���������һ����������Եڶ����任��ľ����Դﵽ������ÿһ��Ԫ�ض��Ǹ�Ԫ��ԭ����������Ԫ�صļ�Ȩ��
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
//---�� �� �� ��   void KeyExpansion(unsigned char* key, unsigned char w[][4][4])
//---��      ��   ��Կ��չ
//---��      ��   key:ԭʼ��Կ�ַ�����ַָ��   w[][4][4]:��չ�����Կ
//---��      ��
//---��      ��   2015.11.15
//---��      ��   ������
//---�� Ҫ ˵ ��   ���������Կkye��չΪ11��128λ��Կ�飬����0��Ϊԭ��Կ(�޶�ԭ��ԿΪ16�ַ�����128λ)
//******************************************************************************
void Ead_Aes::KeyExpansion(unsigned char* key, unsigned char w[][4][4])
{
    unsigned char rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
    //��չ��Կ��0��Ϊԭ��Կ
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
    //��չ��Կ��1�鵽��10��
    for (int i=1; i<=10; i++)
    {
        //�Ե�i����Կ��4�зֱ������չ
        for(int j=0; j<4; j++)
        {
            unsigned char temp[4];  //�洢��ʱ��
            //��ʱ�У���ǰ�ֵ�һ�У�ȡ��һ�����һ�е����ݣ�2��4��ȡ��ǰ��ǰһ������
            for (m=0; m<4; m++)
            {
                temp[m] = j ? w[i][m][j - 1] : w[i - 1][m][3];
            }
            //��һ����������һλ������S�н���
            if (j == 0)
            {
                //��������һλ
                unsigned char t = temp[0];
                for (m=0; m<3; m++)
                {
                    temp[m] = temp[m + 1];
                }
                temp[3] = t;
                //��S�н���
                for (m=0; m<4; m++)
                {
                    temp[m] = m_chSbox[temp[m]];
                }
                //��һ�е�һ��������rcon�������
                temp[0] ^= rcon[i - 1];
            }
            //��ǰ������һ��ͬ�����
            for (m=0; m<4; m++)
            {
                w[i][m][j] = w[i-1][m][j] ^ temp[m];
            }
        }
    }
}
