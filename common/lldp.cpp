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

#include "lldp.h"
#include "converters.h"

#define LLDP_ETHERTYPE 0x88CC
#define TLV_HEAD_ELEMENTS_COUNT 4

LldpProtocol::LldpProtocol(StreamBase *stream, AbstractProtocol *parent)
    : AbstractProtocol(stream, parent)
{
}

LldpProtocol::~LldpProtocol()
{
}

AbstractProtocol* LldpProtocol::createInstance(StreamBase *stream,
                                               AbstractProtocol *parent)
{
    return new LldpProtocol(stream, parent);
}

quint32 LldpProtocol::protocolNumber() const
{
    return OstProto::Protocol::kLldpFieldNumber;
}

void LldpProtocol::protoDataCopyInto(OstProto::Protocol &protocol) const
{
    protocol.MutableExtension(OstProto::lldp)->CopyFrom(data);
    protocol.mutable_protocol_id()->set_id(protocolNumber());
}

void LldpProtocol::protoDataCopyFrom(const OstProto::Protocol &protocol)
{
    if (protocol.protocol_id().id() == protocolNumber() &&
            protocol.HasExtension(OstProto::lldp))
        data.MergeFrom(protocol.GetExtension(OstProto::lldp));
}

QString LldpProtocol::name() const
{
    return QString("Link Layer Discovery Protocol");
}

QString LldpProtocol::shortName() const
{
    return QString("LLDP");
}

AbstractProtocol::ProtocolIdType LldpProtocol::protocolIdType() const
{
    return ProtocolIdEth;
}

quint32 LldpProtocol::protocolId(ProtocolIdType type) const
{
    switch(type)
    {
        case ProtocolIdEth: return LLDP_ETHERTYPE;
        default:break;
    }

    return AbstractProtocol::protocolId(type);
}

int LldpProtocol::fieldCount() const
{
    return data.tlvdata_size();
}

int LldpProtocol::frameFieldCount() const
{
    return fieldCount();
}

AbstractProtocol::FieldFlags LldpProtocol::fieldFlags(int index) const
{
    AbstractProtocol::FieldFlags flags;

    flags = AbstractProtocol::fieldFlags(index);
    return flags;
}

QVariant LldpProtocol::fieldData(int index,
                                 FieldAttrib attrib,
                                 int streamIndex) const
{
    bool isOk = false;

    if (index >= data.tlvdata_size())
        return AbstractProtocol::fieldData(index, attrib, streamIndex);

    QVector<int> fields_count;
    int tlv_count = data.tlvdata_size();
    for (int i = 0; i < tlv_count; i++)
    {
        fields_count.append(data.tlvdata(i).content_size() + 2);
        //two fields is a: TLVType and TLVLen
    }

    QString qsFieldValue;
    QStringList fields_values;
    for (int i = 0; i < data.tlvdata(index).content_size(); i++)
    {
        qsFieldValue.append(QString(";%1").arg(
                                QString::fromStdString(
                                    data.tlvdata(index).content(i))));
        fields_values.append(QString::fromStdString(
                                 data.tlvdata(index).content(i)));
    }
    QByteArray baFrameValue;
    baFrameValue.resize(2); // len of TLVType and TLVLen
    int head = data.tlvdata(index).length() +
            (data.tlvdata(index).tlvtype() << BITS(9));
    qToBigEndian((quint16)head, (uchar*)baFrameValue.data());

    QString ByteString = qsFieldValue;
    ByteString.remove(";");
    for (int i = 0 ; i < ByteString.size() ; i += 2)
        baFrameValue.append(
                    ((QString)ByteString[i] + (QString)ByteString[i + 1]
                     ).toUInt(&isOk, BASE_HEX));

    switch((int)attrib)
    {
        case FieldName:
            return QString("TLV");
        case FieldValue:
        {
            OstProto::Lldp_Tlv data_tlv = data.tlvdata(index);
            qsFieldValue.insert(0,
                                QString("%1;%2;%3;%4").arg(
                                QString::number(data_tlv.tlvtype()),
                                QString::number(data_tlv.length()),
                                QString::number(data_tlv.inside_id()),
                                QString::number(data_tlv.is_override_length()))
                               );
            return qsFieldValue;
        }
        case FieldTextValue:
        {
            tlv_struct current_tlv = tlvmanager::getTlvById(
                        data.tlvdata(index).inside_id());
            tlv_fields_struct_t current_field;
            QString fields;
            FieldType field_type;
            for (int i = 0; i < current_tlv.fields_count; i++)
            {
                current_field = current_tlv.field[i];
                field_type = current_field.type;
                QString value = fields_values[i];
                convert_type_switch_start:
                if (field_type < 10)
                    value = hexStrToSpecificFormat(value, field_type);
                else
                {
                    switch(field_type)
                    {
                        case TEnum:
                        {
                            enum_struct current_enum;
                            current_enum = tlvmanager::getEnumByName(
                                        current_field.arguments["enum"]);
                            int item = current_enum.getItemByValue(value);
                            value = hexStrToUDecStr(value);
                            if (item != -1)
                                value.append(" - " +
                                             current_enum.items[item].name);
                            break;
                        }
                        case TItemlist:
                        {
                            enum_struct current_enum;
                            current_enum = tlvmanager::getEnumByName(
                                        current_field.arguments["enum"]);
                            QString bin_string = hexStrToBitStr(value);
                            bin_string = reverseSrting(bin_string);
                            value.clear();
                            for(int i = 0; i < current_enum.items.count(); i++)
                                value.append("\n            " +
                                             current_enum.items[i].name + " " +
                                             bin_string[i] + "");
                            break;
                        }
                        case TBitfields:
                        {
                            QString bin_string = hexStrToBitStr(value);
                            QVector<tlv_fields_struct_t>
                                    subfields = current_field.subfield;
                            value.clear();
                            for (int j = 0; j < subfields.count(); j++)
                            {
                                value.append("\n            " +
                                             subfields[j].name + ": " +
                                             "0b" + bin_string.left(
                                                 subfields[j].getMin(UnitBit)));
                                bin_string.remove(0,
                                                  subfields[j].getMin(UnitBit));
                            }
                            break;
                        }
                        case TDepend:
                        {
                            int dependfield = current_field.
                                    arguments["dependences"].toInt(
                                        &isOk, BASE_DEC);
                            int dependFieldIndex =
                                    current_tlv.getFieldIndexById(
                                        dependfield);
                            if (!fields_values[dependFieldIndex].isEmpty())
                            {
                                QString item_enum_value =
                                        fields_values[dependFieldIndex];
                                QString enum_name =
                                        current_tlv.field[dependFieldIndex].
                                        arguments["enum"];
                                enum_struct_t current_enum =
                                        tlvmanager::getEnumByName(enum_name);
                                int item_enum_index =
                                        current_enum.getItemByValue(
                                            item_enum_value);
                                if (item_enum_index == -1)
                                    field_type = THexInput;
                                else
                                {
                                    QString type =
                                            current_enum.items[item_enum_index]
                                                        .dependentfieldtype;
                                    FieldType itype= strToFieldType(type);
                                    field_type = itype;
                                }
                                goto convert_type_switch_start;
                            }
                        }
                        case TReserved:
                        default:
                            break;
                    }
                }
                if (field_type == TItemlist or field_type == TBitfields)
                    fields.append(current_tlv.field[i].name + " : " +
                                  "(0x" + fields_values[i] + ")" +
                                  value +
                                  "\n        ");
                else
                    fields.append(current_tlv.field[i].name + " : " +
                                  // field name
                              value + " (" + //field value
                                  "0x" + fields_values[i].toLower() + ")" +
                                  // value in HEX
                              "\n        ");
            }

            return QString(current_tlv.name +
                           "\n      TLV Type: %1"
                           "\n      TLV Length: %2"
                           "\n        %3").arg(
                                QString::number(data.tlvdata(index).tlvtype()),
                                QString::number(data.tlvdata(index).length()),
                                fields
                            ).trimmed();
        }
        case FieldFrameValue:
            return baFrameValue;
    }

    return AbstractProtocol::fieldData(index, attrib, streamIndex);
}

bool LldpProtocol::setFieldData(int index,
                                const QVariant &value,
                                FieldAttrib /*attrib*/)
{
    QStringList tlv_str_list = value.toString().split(";");
    if (index == -1)
    {
        data.Clear();
        return true;
    }
    if (index == 0)
        data.Clear();

    OstProto::Lldp::Tlv* tlv_item = data.add_tlvdata();
    tlv_item->set_tlvtype(tlv_str_list[0].toInt());
    tlv_item->set_length(tlv_str_list[1].toInt());
    tlv_item->set_inside_id(tlv_str_list[2].toInt());
    tlv_item->set_is_override_length(tlv_str_list[3].toInt());
    for (int i = TLV_HEAD_ELEMENTS_COUNT; i < tlv_str_list.count(); i++)
    {
        tlv_item->add_content();
        QVariant qv(tlv_str_list[i]);
        QByteArray fields = qv.toByteArray();
        if (fields.size() != 0)
            tlv_item->set_content(i - TLV_HEAD_ELEMENTS_COUNT,
                                  fields.constData(), fields.size());
    }
    bool isOk = true;
    return isOk;
}

int LldpProtocol::protocolFrameSize(int /*streamIndex*/) const
{
    int size = 2; // size of TlvType and TlvLen
    for (int i = 0; i < data.tlvdata_size(); i++)
        for (int j = 0; j < data.tlvdata(i).content_size(); j++)
        {
            size += (data.tlvdata(i).content(j).size() / 2);
        }
    return size;
}


