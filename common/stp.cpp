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

This module is developed by PLVision  <developers@plvision.eu>
*/

#include "stp.h"
#include <QRegExp>

#define uintToMacStr(num)    \
    QString("%1").arg(num, 6 * 2, BASE_HEX, QChar('0')) \
    .replace(QRegExp("([0-9a-fA-F]{2}\\B)"), "\\1:").toUpper()
#define ONE_BIT(pos) ((unsigned int)(1 << (pos)))
#define BITS(bit) (bit)
#define BYTES(byte) (byte)
#define BYTES_TO_BITS(byte) (byte * 8)

#define STP_LLC 0x424203

StpProtocol::StpProtocol(StreamBase *stream, AbstractProtocol *parent)
    : AbstractProtocol(stream, parent)
{
}

StpProtocol::~StpProtocol()
{
}

AbstractProtocol* StpProtocol::createInstance(StreamBase *stream,
                                              AbstractProtocol *parent)
{
    return new StpProtocol(stream, parent);
}

quint32 StpProtocol::protocolNumber() const
{
    return OstProto::Protocol::kStpFieldNumber;
}

void StpProtocol::protoDataCopyInto(OstProto::Protocol &protocol) const
{
    protocol.MutableExtension(OstProto::stp)->CopyFrom(data);
    protocol.mutable_protocol_id()->set_id(protocolNumber());
}

void StpProtocol::protoDataCopyFrom(const OstProto::Protocol &protocol)
{
    if (protocol.protocol_id().id() == protocolNumber() &&
        protocol.HasExtension(OstProto::stp))
        data.MergeFrom(protocol.GetExtension(OstProto::stp));
}

QString StpProtocol::name() const
{
    return QString("Spanning Tree Protocol");
}

QString StpProtocol::shortName() const
{
    return QString("STP");
}

AbstractProtocol::ProtocolIdType StpProtocol::protocolIdType() const
{
    return ProtocolIdLlc;
}

quint32 StpProtocol::protocolId(ProtocolIdType type) const
{
    switch(type)
    {
        case ProtocolIdLlc:
            return STP_LLC;
        default:
            break;
    }

    return AbstractProtocol::protocolId(type);
}

int StpProtocol::fieldCount() const
{
    return stp_fieldCount;
}

int StpProtocol::frameFieldCount() const
{
    return AbstractProtocol::frameFieldCount();
}

AbstractProtocol::FieldFlags StpProtocol::fieldFlags(int index) const
{
    AbstractProtocol::FieldFlags flags;

    flags = AbstractProtocol::fieldFlags(index);

    switch (index)
    {
        case stp_protocol_identifier:
        case stp_version_identifier:
        case stp_bpdu_type:
        case stp_flags:
        case stp_root_identifier:
        case stp_root_path_cost:
        case stp_bridge_identifier:
        case stp_port_identifier:
        case stp_message_age:
        case stp_max_age:
        case stp_hello_time:
        case stp_forward_delay:
            break;
        default:
            qFatal("%s: unimplemented case %d in switch", __PRETTY_FUNCTION__,
                   index);
            break;
    }
    return flags;
}

QVariant StpProtocol::fieldData(int index, FieldAttrib attrib,
                                int streamIndex) const
{
    QString str[] = {"Topology Change", "Topology Change Acknowledgment"};

    switch (index)
    {
        case stp_protocol_identifier:
        {
            switch (attrib)
            {
                case FieldName:
                    return QString("Protocol Identifier");
                case FieldValue:
                    return QString("%1").arg(data.protocol_identifier());
                case FieldTextValue:
                    return QString("0x%1").arg(data.protocol_identifier(),
                                               4, BASE_HEX, QChar('0'));
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(BYTES(2));
                    qToBigEndian((quint16)data.protocol_identifier(),
                                 (uchar*)fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return BYTES_TO_BITS(2);
                default:
                    break;
            }
            break;
        }
        case stp_version_identifier:
        {
            switch (attrib)
            {
                case FieldName:
                    return QString("Version Identifier");
                case FieldValue:
                    return data.protocol_version_identifier();
                case FieldTextValue:
                    return QString("%1").arg(
                                data.protocol_version_identifier());
                case FieldFrameValue:
                    return QByteArray(1,
                                      (char)data.protocol_version_identifier());
                case FieldBitSize:
                    return BYTES_TO_BITS(1);
                default:
                    break;
            }
            break;
        }
        case stp_bpdu_type:
        {
            switch (attrib)
            {
                case FieldName:
                    return QString("BPDU Type");
                case FieldValue:
                    return QString("%1").arg(data.bpdu_type());
                case FieldTextValue:
                    return QString("0x%1").arg(data.bpdu_type(),
                                               2, BASE_HEX, QChar('0'));
                case FieldFrameValue:
                    return QByteArray(1, (char)data.bpdu_type());
                case FieldBitSize:
                    return BYTES_TO_BITS(1);
                default:
                    break;
            }
            break;
        }
        case stp_flags:
        {
            switch (attrib)
            {
                case FieldName:
                    return QString("BPDU Flags");
                case FieldValue:
                    return data.flags();
                case FieldTextValue:
                {
                    QString str_temp = "(";
                    if((data.flags() & ONE_BIT(0))) str_temp += str[0] + ", ";
                    if((data.flags() & ONE_BIT(7))) str_temp += str[1] + ", ";
                    str_temp += ")";
                    str_temp.replace(", )", ")");
                    return str_temp;
                }
                case FieldFrameValue:
                    return QByteArray(1, (char)data.flags());
                case FieldBitSize:
                    return BYTES_TO_BITS(1);
                default:
                    break;
            }
            break;
        }
        case stp_root_identifier:
        {
            switch (attrib)
            {
                case FieldName:
                    return QString("Root Identifier "
                                   "(Bridge Priority, MAC Address)");
                case FieldValue:
                    return QString("%1").arg(data.root_id(), 16,
                                             BASE_HEX, QChar('0'));
                case FieldTextValue:
                {
                    // Root ID contain two value:
                    // Root ID Priority(first 2 bytes)
                    // and Root ID MAC (last 6 bytes). (IEEE802.1D-2008)
                    quint16 priority = (data.root_id() & 0xFFFF000000000000
                                        ) >> (BYTES_TO_BITS(6));
                    quint64 mac = data.root_id() & 0x0000FFFFFFFFFFFF;
                    return QString("%1 / %3").arg(QString::number(priority),
                                                  uintToMacStr(mac));
                }
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(BYTES(8));
                    qToBigEndian((quint64)data.root_id(), (uchar*)fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return BYTES_TO_BITS(8);
                default:
                    break;
            }
            break;
        }
        case stp_root_path_cost:
        {
            switch (attrib)
            {
                case FieldName:
                    return QString("Root Path Cost");
                case FieldValue:
                    return data.root_path_cost();
                case FieldTextValue:
                    return QString("%1").arg(data.root_path_cost());
                case FieldFrameValue:
                    {
                        QByteArray fv;
                        fv.resize(BYTES(4));
                        qToBigEndian(data.root_path_cost(), (uchar*)fv.data());
                        return fv;
                    }
                case FieldBitSize:
                    return BYTES_TO_BITS(4);
                default:
                    break;
            }
            break;
        }
        case stp_bridge_identifier:
        {
            switch (attrib)
            {
                case FieldName:
                    return QString("Bridge Identifier "
                                   "(Bridge Priority, MAC Address)");
                case FieldValue:
                    return QString("%1").arg(data.bridge_id(), 16,
                                             BASE_HEX, QChar('0'));
                case FieldTextValue:
                {
                    // Bridge ID contain two value:
                    // Bridge ID Priority(first 2 bytes)
                    // and Bridge ID MAC (last 6 bytes). (IEEE802.1D-2008)
                    quint16 priority = (data.bridge_id() & 0xFFFF000000000000
                                        ) >> (BYTES_TO_BITS(6));
                    quint64 mac = data.bridge_id() & 0x0000FFFFFFFFFFFF;
                    return QString("%1 / %3").arg(QString::number(priority),
                                                  uintToMacStr(mac));
                }
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(BYTES(8));
                    qToBigEndian((quint64)data.bridge_id(), (uchar*)fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return BYTES_TO_BITS(8);
                default:
                    break;
            }
            break;
        }
        case stp_port_identifier:
        {
            switch (attrib)
            {
                case FieldName:
                    return QString("Port Identifier");
                case FieldValue:
                    return QString("%1").arg(data.port_id(), 4,
                                             BASE_HEX, QChar('0'));
                case FieldTextValue:
                    return QString("0x%1").arg(data.port_id(), 4,
                                               BASE_HEX, QChar('0'));
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(BYTES(2));
                    qToBigEndian((quint16)data.port_id(), (uchar*)fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return BYTES_TO_BITS(2);
                default:
                    break;
            }
            break;
        }
        case stp_message_age:
        {
            switch (attrib)
            {
                case FieldName:
                    return QString("Message Age");
                case FieldValue:
                    return data.message_age();
                case FieldTextValue:
                    return QString("%1").arg(data.message_age());
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(BYTES(2));
                    qToBigEndian((quint16)(data.message_age()),
                                 (uchar*)fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return BYTES_TO_BITS(2);
                default:
                    break;
            }
            break;
        }
        case stp_max_age:
        {
            switch (attrib)
            {
                case FieldName:
                    return QString("Max Age");
                case FieldValue:
                    return data.max_age();
                case FieldTextValue:
                    return QString("%1").arg(data.max_age());
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(BYTES(2));
                    qToBigEndian((quint16)data.max_age(), (uchar*)fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return BYTES_TO_BITS(2);
                default:
                    break;
            }
            break;
        }
        case stp_hello_time:
        {
            switch (attrib)
            {
                case FieldName:
                    return QString("Hello Time");
                case FieldValue:
                    return data.hello_time();
                case FieldTextValue:
                    return QString("%1").arg(data.hello_time());
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(BYTES(2));
                    qToBigEndian((quint16)data.hello_time(), (uchar*)fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return BYTES_TO_BITS(2);
                default:
                    break;
            }
            break;
        }
        case stp_forward_delay:
        {
            switch (attrib)
            {
                case FieldName:
                    return QString("Forward Delay");
                case FieldValue:
                    return data.forward_delay();
                case FieldTextValue:
                    return QString("%1").arg(data.forward_delay());
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(BYTES(2));
                    qToBigEndian((quint16)data.forward_delay(),
                                 (uchar*)fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return BYTES_TO_BITS(2);
                default:
                    break;
            }
            break;
        }
        default:
            break;
    }
    return AbstractProtocol::fieldData(index, attrib, streamIndex);
}

bool StpProtocol::setFieldData(int index, const QVariant &value,
        FieldAttrib attrib)
{
    bool isOk = false;

    if (attrib != FieldValue)
        return isOk;

    switch (index)
    {
        case stp_protocol_identifier:
        {
            quint16 proto_id = value.toString().toUShort(&isOk);
            if (isOk)
                data.set_protocol_identifier(proto_id);
            break;
        }
        case stp_version_identifier:
        {
            quint8 version_id = value.toUInt(&isOk);
            data.set_protocol_version_identifier(version_id);
            break;
        }
        case stp_bpdu_type:
        {
            quint8 bpdu = value.toString().toUShort(&isOk);
            data.set_bpdu_type(bpdu);
            break;
        }
        case stp_flags:
        {
            quint8 flags = value.toUInt(&isOk);
            if (isOk)
                data.set_flags(flags);
            break;
        }
        case stp_root_identifier:
        {
            quint64 root_id = value.toString().toULongLong(&isOk, BASE_HEX);
            if (isOk)
                data.set_root_id(root_id);
            break;
        }
        case stp_root_path_cost:
        {
            quint32 path_cost = value.toUInt(&isOk);
            data.set_root_path_cost(path_cost);
            break;
        }
        case stp_bridge_identifier:
        {
            quint64 bridge_id = value.toString().toULongLong(&isOk, BASE_HEX);
            if (isOk)
                data.set_bridge_id(bridge_id);
            break;
        }
        case stp_port_identifier:
        {
            quint32 port_id = value.toString().toUInt(&isOk, BASE_HEX);
            if (isOk)
                data.set_port_id(port_id);
            break;
        }
        case stp_message_age:
        {
            quint32 message_age = value.toUInt(&isOk);
            if (isOk)
                data.set_message_age(message_age);
            break;
        }
        case stp_max_age:
        {
            quint32 max_age = value.toUInt(&isOk);
            if (isOk)
                data.set_max_age(max_age);
            break;
        }
        case stp_hello_time:
        {
            quint32 hello_time = value.toUInt(&isOk);
            if (isOk)
                data.set_hello_time(hello_time);
            break;
        }
        case stp_forward_delay:
        {
            quint32 forward_delay = value.toUInt(&isOk);
            if (isOk)
                data.set_forward_delay(forward_delay);
            break;
        }
        default:
            break;
    }
    return isOk;
}
