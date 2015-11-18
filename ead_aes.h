//********************************************************************
//---��  �� ��  ead_aes.h
//---��Ȩ����  (c)�Ͼ���΢���ܿƼ����޹�˾
//---��������  2015.11
//---��      ��  ������
//---��  �� ��  v2.0
//---���ܼ���  AES�����㷨ͷ�ļ�
//---��Ҫ˵��  �����м�����Կ����16�ֽڣ� ����Ȧ��10������
//********************************************************************

#ifndef ALGORITHM_EAD_AES_H
#define ALGORITHM_EAD_AES_H

#include "qglobal.h"


class Ead_Aes
{
public:
    Ead_Aes(unsigned char* key);
    QString QEncryption(QString input); //��QString���ͼ���
    QString QDecrypt(QString input);   //��QString����

private:
    void BlockCipher(unsigned char* block);   //��ÿ��16�ֽ����Ľ��м���
    void BlockRestore(unsigned char* block);  //��ÿ����ܵ�16�ֽ����Ľ��л�ԭ
    unsigned char FFmul(unsigned char a, unsigned char b);  //������GF(28)�ϵĳ˷�
    void AddRoundKey(unsigned char state[4][4], unsigned char k[4][4]); //����Կ��
    void SubStituteBytes(unsigned char state[4][4]); //�ֽ��滻
    void ShiftRows(unsigned char state[4][4]);   //����λ
    void MixColumns(unsigned char state[4][4]);  //�л���
    void RevSubStituteBytes(unsigned char state[4][4]); //�����ֽ��滻
    void RevShiftRows(unsigned char state[4][4]);   //��������λ
    void RevMixColumns(unsigned char state[4][4]);  //�����л���
    void KeyExpansion(unsigned char* key, unsigned char w[][4][4]);    //��Կ��չ

private:
    unsigned char m_chSbox[256];    //����S��
    unsigned char m_chInvSbox[256]; //����S��
    unsigned char m_chW[11][4][4]; //��Կ��չ
};

#endif //ALGORITHM_EAD_AES_H
