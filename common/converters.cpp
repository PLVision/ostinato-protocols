#include "converters.h"

QString macToHexStr(QString mac)
{
    QString hexstr = mac.remove(':');
    return hexstr;
}

QString hexStrToMac(QString hexdata)
{
    QString mac;
    for (int i = 0; i < hexdata.length(); i += 2)
    {
        mac.append(QString(hexdata[i]) + QString(hexdata[i + 1])).append(":");
    }
    mac.remove(mac.length() - 1, 1);
    return mac;
}

QString hexStrInsertSpaces(QString hexdata)
{
    QString out;
    for (int i = 0; i < hexdata.length(); i += 2)
    {
        out.append(QString(hexdata[i]) + QString(hexdata[i + 1])).append(" ");
    }
    out.remove(out.length() - 1, 1);
    return out;
}

QString ipv4ToHexStr(QString ipv4)
{
    bool isOk;
    QString hexstr;
    foreach (QString iByte, ipv4.split(".")) {
        int octet = iByte.toUInt(&isOk, BASE_DEC);
        if (octet > 255)
            octet = 0;
        hexstr.append(QString("%1").arg(octet, 2,
                                        BASE_HEX, QChar('0')));
    }
    return hexstr;
}

QString hexStrToIpv4(QString hexdata)
{
    bool isOk;
    QString ipv4;
    for (int i = 0; i < hexdata.length(); i += 2)
    {
        int num = ((QString)hexdata[i] + (QString)hexdata[i + 1]
                   ).toUInt(&isOk, BASE_HEX);
        ipv4.append(QString::number(num)).append(".");
    }
    ipv4.remove(ipv4.length() - 1, 1);
    return ipv4;
}

QString ipV6ToHexStr(QString ipv6Str)
{
    Q_IPV6ADDR addr = QHostAddress(ipv6Str).toIPv6Address();
    QString hexstr;

    for (int i = 0; i< OCTETS_IN_IPV6; i++) {
        quint8 octet = addr[i];
        hexstr.append(QString("%1").arg(octet, 2, BASE_HEX, QChar('0')));
    }
    return hexstr;
}

QString hexStrToIpv6(QString hexstr)
{
    hexstr.remove(":");
    QString ipv6;

    for (int i = 0; i< hexstr.length(); i += 4) {
        ipv6.append(hexstr[i]).append(hexstr[i + 1])
                .append(hexstr[i + 2]).append(hexstr[i + 3]).append(":");
    }
    ipv6.remove(ipv6.length() - 1, 1);
    return ipv6;
}

QByteArray hexStrToByteArray(QString hexstring)
{
    bool isOk;
    QByteArray array;
    for (int i = 0; i < hexstring.length(); i += 2)
    {
        char num = ((QString)hexstring[i] + (QString)hexstring[i + 1]
                    ).toUInt(&isOk, BASE_HEX);
        array.append(num);
    }
    return array;
}

QString byteArrayToHexStr(QByteArray byteArray)
{
    QString hexStr(byteArray);

    return hexStr;
}

QString uDecStrToHexStr(QString decstring)
{
    bool isOk;
    QString res = QString::number(decstring.toULongLong(&isOk, BASE_DEC),
                                  BASE_HEX);
    if (isOk)
        return res;
    else
        return "0";
}

QString hexStrToUDecStr(QString hexstring)
{
    bool isOk;
    QString res = QString::number(hexstring.toULongLong(&isOk, BASE_HEX),
                                  BASE_DEC);
    if (isOk)
        return res;
    else
        return "0";
}

QString bitStrToHexStr(QString bitstring)
{
    bool isOk;
    // 0x80 insert in the left position to prevent
    // clipping of the first zero bits
    bitstring.insert(0, "10000000");
    QString res = QString::number(bitstring.toULongLong(&isOk, BASE_BIN),
                                  BASE_HEX);
    res.remove(0, 2); //remove first byte
    return res;
}

QString hexStrToBitStr(QString hexstr)
{
    bool isOk;
    hexstr.insert(0, "80");
    // 0x80 insert in the left position to prevent
    // clipping of the first zero bits
    QString res = QString::number(hexstr.toULongLong(&isOk, BASE_HEX),
                                  BASE_BIN);
    res.remove(0, 8); //remove first byte
    return res;
}


QString allignToSizeHex(QString hexString, tlv_fields_struct_t field)
{
    int min = field.getMin(UnitOctet) * 2;
    int max = field.getMax(UnitOctet) * 2;
    int prev_size = hexString.length();
    QString res = hexString;
    if (prev_size < min)
    {
        res = QString("%1%2").arg(QString().fill('0', min*2),
                                  hexString).right(min);
        return res;
    }
    if (prev_size == min)
        return res;
    if (prev_size > min)
    {
        if (prev_size < max)
            return res;
        if (prev_size == max)
        return res;
        if (prev_size > max)
        return res.left(max);
    }
    return res;
}

QString allignToSizeBin(QString binString, tlv_fields_struct_t field)
{
    int min = field.getMin(UnitBit);
    int max = field.getMax(UnitBit);
    int prev_size = binString.length();
    QString res = binString;
    if (prev_size < min)
    {
        res = QString("%1%2").arg(QString().fill('0', min),
                                  binString).right(min);
        return res;
    }
    if (prev_size == min)
        return res;
    if (prev_size > min)
    {
        if (prev_size < max)
        return res;
        if (prev_size == max)
        return res;
        if (prev_size > max)
        return res.right(max);
    }
    return res;
}

QString oidToHexStr(QString oid)
{
    bool isOk;
    QStringList split = oid.split('.');
    QList<int> retVal;
    QList<int> tmpVal;

    for (int a = 0, b = 0, i = 0; i < split.count(); i++)
    {
        if (i == 0)
            a = split[0].toInt(&isOk, BASE_DEC);
        else if (i == 1)
            retVal.push_back(40 * a + split[1].toInt(&isOk, BASE_DEC));
        else
        {
            b = split[i].toInt(&isOk, BASE_DEC);
            if (b < 0x80)
                retVal.push_back(b);
            else //if number has more than one byte
            {
                tmpVal.push_front(b % 0x80);
                while (b > 0x80)
                {
                    b /= 0x80;
                    tmpVal.push_front(0x80 + ( b % 0x80));
                }
            }
        }
        while (!tmpVal.empty())
        {
            retVal.push_back(tmpVal.front());
            tmpVal.pop_front();
        }
    }

    QString temp = "";
    for (int i = 0; i < retVal.count(); i++)
        temp.append(QString("%1").arg(retVal[i], 2, BASE_HEX, QChar('0')));

    return temp.toUpper();
}

QString hexStrToAlphaNumeric(QString hexStr)
{
    QByteArray ba = hexStrToByteArray(hexStr);
    QString oid = ba.right(ba.length() - ba.lastIndexOf(char(0)) - 1);
    return oid;
}

QString reverseSrting(QString inString)
{
    QString reverse = inString;
    if (!inString.isEmpty())
    {
        reverse.reserve(inString.size());
        for(int i = 0, j = inString.length() - 1; j >= 0; i++, j--)
            reverse[j] = inString[i];
    }
    return reverse;
}

QString hexStrToOid(QString hexString)
{
    if (hexString.isEmpty())
        return "";

    QByteArray oid(hexStrToByteArray(hexString));

    QString sb = "";
    // Pick apart the OID
    char x = (char)(oid[0] / 40);
    char y = (char)(oid[0] % 40);
    if (x > 2)
    {
        // Handle special case for large y if x = 2
        y += (int)((x - 2) * 40);
        x = 2;
    }
    sb.append(QString::number((int)x, BASE_DEC));
    sb.append(".");
    sb.append(QString::number((int)y, BASE_DEC));
    long val = 0;
    for (x = 1; x < oid.length(); x++)
    {
        val = ((val << 7) | ((char)(oid[x] & 0x7F)));
        if (!((oid[x] & 0x80) == 0x80))
        {
            sb.append(".");
            sb.append(QString::number(val));
            val = 0;
        }
    }
    return sb;
}

QString hexStrToSpecificFormat(QString hexString, FieldType type)
{
    switch(type)
    {
        case THexInput:
            return hexStrInsertSpaces(hexString);
        case TMacAddress:
            return hexStrToMac(hexString);
        case TIpv4Address:
            return hexStrToIpv4(hexString);
        case TIpv6Address:
            return hexStrToIpv6(hexString);
        case TAlphaNumeric:
            return hexStrToAlphaNumeric(hexString);
        case TOID:
            return hexStrToOid(hexString);
        case TTime:
        case TLength:
        case TDecInput:
            return hexStrToUDecStr(hexString);
        case THexDump:
            return hexStrInsertSpaces(hexString);
        default:
            return hexString;
    }
}
