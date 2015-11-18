#include <QApplication>
#include <QDebug>
#include "ead_aes.h"

int main(int argc, char* argv[])
{
    QApplication a(argc, argv);
    unsigned char key[16] =
    {
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08,
        0x09, 0x00, 0x01, 0x02,
        0x03, 0x04, 0x05, 0x06
    };
    Ead_Aes aes(key);
    QString ke = "dfsfasdjuiko5696385f";
	aes.QDecrypt(aes.QEncryption(ke));
    return a.exec();
}
