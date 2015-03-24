/*
Copyright (C) 2014 Marchuk S.

This file is part of "Ostinato"

This is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>

This module is developed by PLVision <developers@plvision.eu> company
*/
#include <QHostAddress>
#include "tlvmanager.h"

#define OCTETS_IN_IPV6 16

QString macToHexStr(QString mac);
QString hexStrToMac(QString hexdata);
QString hexStrInsertSpaces(QString hexdata);
QString ipv4ToHexStr(QString ipv4);
QString hexStrToIpv4(QString hexdata);
QString ipV6ToHexStr(QString ipv6Str);
QString hexStrToIpv6(QString hexstr);
QByteArray hexStrToByteArray(QString hexstring);
QString byteArrayToHexStr(QByteArray byteArray);
QString uDecStrToHexStr(QString decstr);
QString hexStrToUDecStr(QString hexstring);
QString bitStrToHexStr(QString bitstring);
QString reverseSrting(QString inString);
QString hexStrToBitStr(QString hexstr);
QString allignToSizeHex(QString hexString, tlv_fields_struct_t field);
QString allignToSizeBin(QString binString, tlv_fields_struct_t field);
QString oidToHexStr(QString oid);
QString hexStrToAlphaNumeric(QString hexStr);
QString hexStrToOid(QString hexStr);
QString hexStrToSpecificFormat(QString hexString, FieldType type);
