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
#ifndef _TLVMANAGER_H
#define _TLVMANAGER_H

#include <QString>
#include <QStringList>
#include <QHash>
#include <QVector>
#include <QXmlStreamReader>
#include <QFile>
#include <math.h>

#define BASE_BIN (2)
#define BASE_OCT (8)
#define BASE_DEC (10)
#define BASE_HEX (16)
#define BITS(n) (n)

enum FieldType{
    THexInput = 0, //Simple types
    TMacAddress,
    TIpv4Address,
    TIpv6Address,
    TAlphaNumeric,
    TOID,
    TTime,
    TLength,
    TDecInput,
    THexDump,
    TEnum = 10, //Complex types (need tlv_base for converts)
    TItemlist,
    TBitfields,
    TBinInput,
    TDepend,
    TReserved
};

enum LenunitType{
    UnitOctet = 0,
    UnitBit
};

struct field_type_struct{ //Struct of field type
    int id;
    QString name;
    QStringList additional_arguments;

    field_type_struct()
    {
        id = -1;
        name = "";
        additional_arguments = QStringList();
    }
};

struct enum_struct{ //Struct of enum (enum, itemlist)
    QString name;
    QString type; //Type of enum (checkboxlist, valuelist, typelist)

    struct enum_item_type{
        int id;
        QString name; //Visible name
        QString dependentfieldtype; // Type for depend field
        QString value; // Value that is written in the frame

        enum_item_type()
        {
            id = 0;
            name = "";
            dependentfieldtype = "";
            value = "";
        }

        void clear()
        {
            id = 0;
            name.clear();
            dependentfieldtype.clear();
            value.clear();
        }
    };
    QVector<enum_item_type> items;

    enum_struct()
    {
        name = "";
        type = "";
    }

    int getItemByValue(QString value) // Return index of field with equal value
    {
        bool isOk;
        foreach(enum_item_type iter, items)
        {
            if (iter.value.toInt(&isOk, BASE_HEX) == value.toInt(&isOk,
                                                                 BASE_HEX))
                return iter.id;
        }
        return -1;
    }

    void clear()
    {
        name.clear();
        type.clear();
    }
};

struct tlv_struct{
    int id;
    int tlvtype;
    int length;
    int fields_count;
    QString name;

    struct tlv_fields_struct{ // Struct of one field of TLV without value
        int id;
        QString name;
        struct length_minMax{
            int min;
            int max;
        } length;
        FieldType type;
        QHash<QString, QString> arguments;
        QString dafault_value;
        LenunitType units;
        QVector<tlv_fields_struct> subfield;

        tlv_fields_struct()
        {
            id = -1;
            name = "";
            length.min = 0;
            length.max = 0;
            type = THexInput;
            arguments = QHash<QString, QString>();
            dafault_value = "";
            units = UnitOctet;
            subfield = QVector<tlv_fields_struct>();
        }

        void clear()
        {
            id = -1;
            name = "";
            length.min = 0;
            length.max = 0;
            type = THexInput;
            arguments.clear();
            dafault_value.clear();
            units = UnitOctet;
            subfield.clear();
        }

        tlv_fields_struct& operator= (const tlv_fields_struct& a)
        {
            id = a.id;
            name = a.name;
            length.min = a.length.min;
            length.max = a.length.max;
            type = a.type;
            arguments = a.arguments;
            dafault_value = a.dafault_value;
            units = a.units;
            subfield = a.subfield;
            return *this;
        }

        int getMin(LenunitType return_units = UnitOctet)
        // Return min length of field
        {
            if (return_units == UnitOctet)
            {
                if (units == UnitBit)
                    return (int)ceil(length.min / BITS(8.0));
                if (units == UnitOctet)
                    return length.min;
            }
            else if (return_units == UnitBit)
            {
                if (units == UnitBit)
                    return length.min;
                if (units == UnitOctet)
                    return (int)(length.min * BITS(8));
            }
            return 0;
        }

        int getMax(LenunitType return_units = UnitOctet)
        // Return max length of field
        {
            if (return_units == UnitOctet)
            {
                if (units == UnitBit)
                    return (int)ceil(length.max / BITS(8.0));
                if (units == UnitOctet)
                    return length.max;
            }
            else if (return_units == UnitBit)
            {
                if (units == UnitBit)
                    return length.max;
                if (units == UnitOctet)
                    return (int)(length.max * BITS(8));
            }
            return 0;
        }

        QStringList getSubfieldsNameList()
        // For type == bitfields return list with names of subfields
        {
            QStringList res;
            foreach (tlv_fields_struct field_item, subfield)
            {
                res.append(field_item.name);
            }
            return res;
        }
    };
    QVector<tlv_fields_struct> field;

    tlv_struct()
    {
        id = -1;
        tlvtype = -1;
        length = -1;
        fields_count = 0;
        name = "";
        field = QVector<tlv_fields_struct>();
    }

    void clear()
    {
        id = -1;
        tlvtype = -1;
        length = -1;
        fields_count = 0;
        name.clear();
        field.clear();
    }

    tlv_struct& operator= (const tlv_struct& a)
    {
        id = a.id;
        tlvtype = a.tlvtype;
        length = a.length;
        fields_count = a.fields_count;
        name = a.name;
        field = a.field;
        return *this;
    }

    QStringList getFieldsDefaultValuesList()
    // Return list with default values for TLV
    {
        QStringList res;
        foreach (tlv_fields_struct field_item, field)
        {
            res.append(field_item.dafault_value);
        }
        return res;
    }

    QStringList getFieldsNameList()
    // Return list with fields names for TLV
    {
        QStringList res;
        foreach (tlv_fields_struct field_item, field)
        {
            res.append(field_item.name);
        }
        return res;
    }

    int getFieldIndexById(int id)
    // Get index of field in the TLV. Index may not equal to ID.
    // Addressing is carried out by ID
    {
            for (int i = 0; i < field.count(); i++)
                if (field[i].id == id)
                    return i;
        return -1;
    }
};

typedef QHash<QString, tlv_struct> tlvHash_t;
typedef enum_struct enum_struct_t;
typedef enum_struct::enum_item_type enum_item_struct_t;
typedef field_type_struct field_type_t;
typedef tlv_struct::tlv_fields_struct tlv_fields_struct_t;

FieldType strToFieldType(QString type);
QString fieldTypeToString(FieldType type);

class tlvmanager // Class singleton
{
public:
    static tlvmanager& getInstance()
    {
        static tlvmanager instance;
        return instance;
    }

    bool readDataFromFile(); // Read TLVList, Types and Enums from file
    bool readTlvListFromFile(); // Read only TLV list from file
    bool readTypesFromFile(); // Read only Types from file
    bool readEnumsFromFile(); // Read only Enums from file

    tlv_struct readTLV(QXmlStreamReader &xml);
    tlv_fields_struct_t readTlvFields(QXmlStreamReader &xml);
    field_type_t readType(QXmlStreamReader &xml);
    enum_item_struct_t readEnumItem(QXmlStreamReader &xml, QString enumType);
    enum_struct readEnum(QXmlStreamReader &xml);
    tlv_struct findDependencies(tlv_struct tlv);

    static tlvHash_t getTlvBase() //Return base with TLVs
    {
        tlvmanager& s = tlvmanager::getInstance();
        return s.tlv_base_;
    }

    static bool isTypeExist(QString name)
    {
        tlvmanager& s = tlvmanager::getInstance();
        return s.fieldType.contains(name);
    }
    static bool isTlvExist(QString name)
    {
        tlvmanager& s = tlvmanager::getInstance();
        return s.tlv_base_.contains(name);
    }
    static tlv_struct getTlvByName(QString name)
    // Return TLV struct with default values. Addressing is carried out by name
    {
        tlvmanager& s = tlvmanager::getInstance();
        if (isTlvExist(name))
            return s.tlv_base_[name];
        return s.tlv_base_["custom"];
    }

    static tlv_struct getTlvById(int id)
    // Return TLV struct with default values. Addressing is carried out by ID
    {
        tlvmanager& s = tlvmanager::getInstance();
        QString tlv_name = "Custom";
        foreach(QString item, s.tlv_base_.keys())
            if (s.tlv_base_[item].id == id)
                tlv_name = item;
        return s.tlv_base_[tlv_name];
    }

    static tlv_struct getTlvByTlvType(int tlv_type)
    // Return TLV struct with default values.
    // Addressing is carried out by TlvType
    {
        tlvmanager& s = tlvmanager::getInstance();
        QString tlv_name = "Custom";
        foreach(QString item, s.tlv_base_.keys())
            if (s.tlv_base_[item].tlvtype == tlv_type)
                tlv_name = item;
        return s.tlv_base_[tlv_name];
    }

    QHash<QString, field_type_t> fieldType; // Base of types
    QHash<QString, enum_struct_t> enums_base; // Base of Enums

    static enum_struct_t getEnumByName(QString enum_name)
    // Return TLV struct with default values.
    // Addressing is carried out by TlvType
    {
        tlvmanager& s = tlvmanager::getInstance();
        return s.enums_base[enum_name];
    }
private:
    tlvmanager(){} //Disable use the constructor bacause it is a singleton class
    tlvmanager(const tlvmanager&);
    tlvmanager& operator=(const tlvmanager&);
    QFile* OpenXMLFile();
    bool CloseXMLFile(QFile* file);

    // Read integer attribute from xmlfile
    int readIntAttribute(QString attribute_name, QXmlStreamReader &xml,
                         int defaultValue = 0);

     // Read string attribute from xmlfile
    QString readStringAttribute(QString attribute_name, QXmlStreamReader &xml,
                                QString defaultValue = "");

    tlvHash_t tlv_base_; // Base of all TLV, read from XML file
    bool isFieldTypeFill_; // Flag, is types already read from file

};

struct tlv_struct_data{ // struct for save one filled TLV with data
    int id; // Meta field for identify tlv when tlvType configured as invalid
    int tlvtype;
    int length;
    bool is_override_length;
    QString name;
    QStringList field;

    int setFieldById(int id, QString hexString)
    // Set data to field. Addressing is carried out by ID
    {
        tlv_struct tlv = tlvmanager::getTlvByName(name);

            for (int i = 0; i < tlv.field.count(); i++)
            {
                if (tlv.field[i].id == id)
                {
                    this->field[i] = hexString;
                    return i;
                }
            }
    }
    int getFieldIndexById(int id)
    // Get index of field in the TLV. Index may not equal to ID.
    // Addressing is carried out by ID
    {
        tlv_struct tlv = tlvmanager::getTlvByName(name);

            for (int i = 0; i < tlv.field.count(); i++)
                if (tlv.field[i].id == id)
                    return i;
        return -1;
    }

    int calculateLength()
    // Return length of fields(without tlvType and tlvLength) in TLV
    {
        int size = 0;
        foreach(QString iField, field)
        {
            size += iField.length();
        }
        size = ceil(size / 2.0);
        if (!is_override_length)
            length = size;
        return size;
    }
};

#endif // _TLVMANAGER_H
