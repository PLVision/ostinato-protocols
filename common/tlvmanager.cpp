#include "tlvmanager.h"

#include <QFile>

QFile* tlvmanager::OpenXMLFile()
{
#ifdef Q_OS_LINUX
    QFile *file = new QFile("/usr/local/share/ostinato/tlv_base.xml");
#endif
#ifdef Q_OS_FREEBSD
    QFile *file = new QFile("/usr/local/share/ostinato/tlv_base.xml");
#endif
#ifdef Q_WS_WIN
    QFile *file = new QFile("tlv_base.xml");
#endif
#ifdef Q_WS_MACX
    QFile *file = new QFile("/usr/local/share/ostinato/tlv_base.xml");
#endif

    if (file->exists())
    {
        if (file->open(QIODevice::ReadOnly))
            return file;
        else
            qErrnoWarning("tlvmanager::ERROR: Can`t open XML file");
    }
    else
        qErrnoWarning("tlvmanager::ERROR: XML file not found");

    return NULL;
}

bool tlvmanager::CloseXMLFile(QFile* file)
{
    if (file->isOpen())
    {
        file->close();
        return true;
    }
    else
        return false;
}

QString tlvmanager::readStringAttribute(QString attribute_name,
                                        QXmlStreamReader &xml,
                                        QString defaultValue)
{
    QXmlStreamAttributes attributes = xml.attributes();
    bool isOk;

    QStringRef value = attributes.value(attribute_name);

    if (!value.isNull())
        return value.toString();
    else
        isOk = false;
    if (!isOk)
        qErrnoWarning(QString("tlvmanager::ERROR: can`t pharse string "
                              "attribute '%1' in token '%2'").
                      arg(attribute_name, xml.tokenString()).toAscii());
    return defaultValue;
}

int tlvmanager::readIntAttribute(QString attribute_name,
                                 QXmlStreamReader &xml,
                                 int defaultValue)
{
    QXmlStreamAttributes attributes = xml.attributes();
    bool isOk;

    QStringRef value = attributes.value(attribute_name);
    if (!value.isNull())
    {
        int res = value.toString().toInt(&isOk, BASE_DEC);
        if (isOk)
            return res;
    }
    else
        isOk = false;
    if (!isOk)
        qErrnoWarning(QString("tlvmanager::ERROR: can`t pharse int "
                              "attribute '%1' in token '%2'").
                      arg(attribute_name, xml.tokenString()).toAscii());
    return defaultValue;
}

field_type_t tlvmanager::readType(QXmlStreamReader &xml)
{
    field_type_t field_type_item = field_type_t();

    field_type_item.id = readIntAttribute("id", xml);
    field_type_item.name = readStringAttribute("name", xml);
    field_type_item.additional_arguments +=
            readStringAttribute("additional_arguments", xml).split(",");

    return field_type_item;
}

FieldType strToFieldType(QString type)
{
    type = type.toLower();
    if (type == "macaddress")
        return TMacAddress;
    else if (type == "ipv4address")
        return TIpv4Address;
    else if (type == "ipv6address")
        return TIpv6Address;
    else if (type == "alpha-numeric")
        return TAlphaNumeric;
    else if (type == "oid")
        return TOID;
    else if (type == "hexinput")
        return THexInput;
    else if (type == "decinput")
        return TDecInput;
    else if (type == "hexdump")
        return THexDump;
    else if (type == "enum")
        return TEnum;
    else if (type == "itemlist")
        return TItemlist;
    else if (type == "time")
        return TTime;
    else if (type == "length")
        return TLength;
    else if (type == "depend")
        return TDepend;
    else if (type == "reserved")
        return TReserved;
    else if (type == "bitfields")
        return TBitfields;
    else if (type == "bininput")
        return TBinInput;
    else
    {
        qErrnoWarning(QString("StrToFieldTypeConverter::WARNING: type "
                              "attribute '%1' is not recognize").arg(type)
                                                                .toAscii());
        return THexInput;
    }
}

QString fieldTypeToString(FieldType type)
{
    switch (type)
    {
        case TMacAddress:
            return "macaddress";
        case TIpv4Address:
            return "ipv4address";
        case TIpv6Address:
            return "ipv6address";
        case TAlphaNumeric:
            return "alpha-numeric";
        case TOID:
            return "oid";
        case THexInput:
            return "hexinput";
        case TDecInput:
            return "decinput";
        case THexDump:
            return "hexdump";
        case TEnum:
            return "enum";
        case TItemlist:
            return "itemlist";
        case TTime:
            return "time";
        case TLength:
            return "length";
        case TDepend:
            return "depend";
        case TReserved:
            return "reserved";
        case TBitfields:
            return "bitfields";
        case TBinInput:
            return "bininput";
        default:
            qErrnoWarning(QString("StrToFieldTypeConverter::WARNING: type "
                                  "attribute '%1' is not recognize").arg(type)
                                                                    .toAscii());
            return "";
    }
}

tlv_struct tlvmanager::readTLV(QXmlStreamReader &xml)
{
    tlv_struct tlv_item = tlv_struct();

    tlv_item.id = readIntAttribute("id", xml);
    tlv_item.tlvtype = readIntAttribute("tlvtype", xml);
    tlv_item.name = readStringAttribute("name", xml);
    tlv_item.length = readIntAttribute("length", xml);

    return tlv_item;
}



tlv_fields_struct_t tlvmanager::readTlvFields(QXmlStreamReader &xml)
{
    tlv_fields_struct_t tlv_field_item = tlv_fields_struct_t();
    QXmlStreamAttributes attributes = xml.attributes();
    bool isOk = false;

    tlv_field_item.id = readIntAttribute("id", xml);
    tlv_field_item.name = readStringAttribute("name", xml);

    if (!attributes.value("lenunit").isNull())
    {
        QString lenunit = readStringAttribute("lenunit", xml);
        if (lenunit == "bit")
            tlv_field_item.units = UnitBit;
        else
            tlv_field_item.units = UnitOctet;
    }
    else
        tlv_field_item.units = UnitOctet;

    QStringList length = readStringAttribute("length", xml).split("-");
    tlv_field_item.length.min = length.first().toInt(&isOk, BASE_DEC);
    tlv_field_item.length.max = length.last().toInt(&isOk, BASE_DEC);

    QString type = readStringAttribute("type", xml);
    tlv_field_item.type = strToFieldType(type);

    tlv_field_item.dafault_value = readStringAttribute("defaultvalue", xml);
    tlv_field_item.dafault_value.replace("0x","");
    // fix for "0x*****"-like defaultvalues

    if (isTypeExist(type)) // read additional arguments according the field type
        foreach (QString argument, fieldType[type].additional_arguments)
        {
            if (!argument.isEmpty())
                tlv_field_item.arguments.insert(argument,
                                                readStringAttribute(argument,
                                                                    xml));
        }

    if (type == "depend") //read all attributes of field;
        for (int i = 0; i < attributes.count(); i++)
            tlv_field_item.arguments.insert(attributes[i].name().toString(),
                                            readStringAttribute(attributes[i]
                                                .name().toString(), xml));

    return tlv_field_item;
}

enum_struct tlvmanager::readEnum(QXmlStreamReader &xml)
{
    enum_struct enum_local = enum_struct();

    enum_local.name = readStringAttribute("name", xml);
    enum_local.type = readStringAttribute("type", xml);

    return enum_local;
}

enum_item_struct_t tlvmanager::readEnumItem(QXmlStreamReader &xml,
                                            QString enumType)
{
    enum_item_struct_t enum_item = enum_item_struct_t();

    enum_item.id = readIntAttribute("id", xml);
    enum_item.name = readStringAttribute("name", xml);
    if (enumType == "typelist")
        enum_item.dependentfieldtype = readStringAttribute("dependentfieldtype",
                                                           xml);

    enum_item.value = readStringAttribute("value", xml,
                                          QString::number(enum_item.id,
                                                          BASE_HEX));
    return enum_item;
}

tlv_struct tlvmanager::findDependencies(tlv_struct tlv)
{
    for (int i = 0; i < tlv.fields_count; i++)
    {
        bool isOk;
        if (tlv.field[i].arguments.contains("dependences") and
                tlv.field[i].type == TLength)
        {
            QStringList dependFields = tlv.field[i].arguments["dependences"]
                                                   .split(",");
            foreach (QString iDepend, dependFields)
            {
                int index = iDepend.toInt(&isOk);
                if (isOk)
                {
                    tlv.field[index].arguments.insert("dependlength",
                                                  QString::number(i));
                }
            }
        }
        if (tlv.field[i].type == TEnum)
        {
            QString enum_name = tlv.field[i].arguments["enum"];
            if (enums_base[enum_name].type != "typelist")
                continue;
            foreach (tlv_fields_struct_t iField, tlv.field)
            {
                if (iField.arguments.contains("dependences"))
                {
                    QString strDepend = iField.arguments["dependences"];
                    strDepend.toInt(&isOk);
                    if (isOk)
                    {
                        tlv.field[i].arguments.insert("dependfield",
                                                      strDepend);
                    }
                }
            }
        }
    }
    return tlv;
}

bool tlvmanager::readDataFromFile()
{
    if (OpenXMLFile())
    {
        bool isOk = true;
        isOk = this->readTypesFromFile();
        isOk = this->readEnumsFromFile();
        isOk = this->readTlvListFromFile();
        return isOk;
    }
    return false;
}

bool tlvmanager::readTlvListFromFile()
{
    bool isOk = true;
    if (!isFieldTypeFill_)
        qErrnoWarning("tlvmanager::WARNING: Field Types DB is Empty.");

    QFile* file = OpenXMLFile();
    tlv_struct tlv_item = tlv_struct();
    tlv_fields_struct_t tlv_fields_item = tlv_fields_struct_t();
    tlv_fields_struct_t tlv_subfields_item = tlv_fields_struct_t();
    tlv_base_.clear();
    QXmlStreamReader xml(file);

    while (!xml.atEnd() && !xml.hasError())
    {
        QXmlStreamReader::TokenType token = xml.readNext();
        if (token == QXmlStreamReader::Invalid)
        {
            qErrnoWarning("tlvmanager::ERROR: Find invalid element in XML."
                          " (readTlvListFromFile)");
            isOk = false;
        }
        if (token == QXmlStreamReader::StartDocument)
            continue;
        if (token == QXmlStreamReader::StartElement)
        {
            if (xml.name() == "tlv_list")
                continue;
            if (xml.name() == "tlv")
            {
                tlv_item = readTLV(xml);
            }
            if (xml.name() == "field")
            {
                tlv_fields_item = readTlvFields(xml);
            }
            if (xml.name() == "subfield")
            {
                tlv_subfields_item = readTlvFields(xml);
            }
        }
        if (token == QXmlStreamReader::EndElement)
        {
            if (xml.name() == "tlv")
            {
                tlv_item.fields_count = tlv_item.field.count();
                tlv_item = findDependencies(tlv_item);
                tlv_base_.insert(tlv_item.name, tlv_item);
                tlv_item.clear();
            }
            if (xml.name() == "field")
            {
                tlv_item.field.push_back(tlv_fields_item);
                tlv_fields_item.clear();
            }
            if (xml.name() == "subfield")
            {
                tlv_fields_item.subfield.push_back(tlv_subfields_item);
                tlv_subfields_item.clear();
            }
        }
    }
    CloseXMLFile(file);

    return isOk;
}

bool tlvmanager::readTypesFromFile()
{
    bool isOk = true;
    QFile* file = OpenXMLFile();
    field_type_t field_type_item = field_type_t();
    fieldType.clear();
    isFieldTypeFill_ = false;
    QXmlStreamReader xml(file);

    while (!xml.atEnd() && !xml.hasError())
    {
        QXmlStreamReader::TokenType token = xml.readNext();
        if (token == QXmlStreamReader::Invalid)
        {
            qErrnoWarning("tlvmanager::ERROR: Find invalid element in XML."
                          " (readTypesFromFile)");
            isOk = false;
        }
        if (token == QXmlStreamReader::StartDocument)
            continue;
        if (token == QXmlStreamReader::StartElement)
        {
            if (xml.name() == "types")
                continue;
            if (xml.name() == "type")
            {
                field_type_item = readType(xml);
            }
        }
        if (token == QXmlStreamReader::EndElement)
        {
            if (xml.name() == "type")
            {
                fieldType.insert(field_type_item.name, field_type_item);
            }
            if (xml.name() == "types")
            {
                isFieldTypeFill_ = true;
            }
        }
    }
    CloseXMLFile(file);

    return isOk;
}

bool tlvmanager::readEnumsFromFile()
{
    bool isOk = true;
    QFile* file = OpenXMLFile();
    enum_struct enum_local = enum_struct();
    enum_item_struct_t enum_item = enum_item_struct_t();
    tlv_base_.clear();
    QXmlStreamReader xml(file);

    while (!xml.atEnd() && !xml.hasError())
    {
        QXmlStreamReader::TokenType token = xml.readNext();
        if (token == QXmlStreamReader::Invalid)
        {
            qErrnoWarning("tlvmanager::ERROR: Find invalid element in XML."
                          " (readEnumsFromFile)");
            isOk = false;
        }
        if (token == QXmlStreamReader::StartDocument)
            continue;
        if (token == QXmlStreamReader::StartElement)
        {
            if (xml.name() == "enums")
                continue;
            if (xml.name() == "enum")
            {
                enum_local = readEnum(xml);
            }
            if (xml.name() == "item")
            {
                enum_item = readEnumItem(xml, enum_local.type);
            }
        }
        if (token == QXmlStreamReader::EndElement)
        {
            if (xml.name() == "enum")
            {
                enums_base.insert(enum_local.name, enum_local);
                enum_local.clear();
            }
            if (xml.name() == "item")
            {
                enum_local.items.push_back(enum_item);
                enum_item.clear();
            }
        }
    }
CloseXMLFile(file);

return isOk;
}



