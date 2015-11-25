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
    QString mingw = "dfsfasdjuiko5696385f";
	QString aft = aes.QDecrypt(aes.QEncryption(mingw));


    return a.exec();
}
