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

#include "stpconfig.h"
#include "stp.h"

#include <QRegExpValidator>
#include <QIntValidator>

#define ONE_BYTE_MAX 255
#define TWO_BYTE_MAX 65535
#define ONE_BIT(pos) ((unsigned int)(1 << (pos)))
#define BYTES(byte) (byte)

StpConfigForm::StpConfigForm(QWidget *parent)
    : AbstractProtocolConfigForm(parent)
{
    QRegExp reMac("([0-9,a-f,A-F]{2,2}[:-]){5,5}[0-9,a-f,A-F]{2,2}");
    QRegExp reUint64("([0-9]{1,9}|[1-3][0-9]{9}|4([01][0-9]{8}|2(["
                     "0-8][0-9]{7}|9([0-3][0-9]{6}|4([0-8][0-9]{5}"
                     "|9([0-5][0-9]{4}|6([0-6][0-9]{3}|7([01][0-9]"
                     "{2}|2([0-8][0-9]|9[0-5])))))))))"
                    );
    setupUi(this);

    QRegExpValidator *validate_macAddress = new QRegExpValidator(reMac, this);
    QIntValidator *validate_oneByte_dec = new QIntValidator(0, ONE_BYTE_MAX, this);
    QIntValidator *validate_twoByte_dec = new QIntValidator(0, TWO_BYTE_MAX, this);
    QRegExpValidator *validate_fourByte_dec = new QRegExpValidator(reUint64,
                                                                   this);

    ui_protocol_id->setValidator(validate_twoByte_dec);
    ui_version_id->setValidator(validate_oneByte_dec);

    ui_bpdu_type->setValidator(validate_oneByte_dec);

    ui_root_id_priority->setValidator(validate_twoByte_dec);
    ui_root_id->setValidator(validate_macAddress);

    ui_root_path_cost->setValidator(validate_fourByte_dec);

    ui_bridge_id_priority->setValidator(validate_twoByte_dec);
    ui_bridge_id->setValidator(validate_macAddress);

    ui_port_id_priority->setValidator(validate_oneByte_dec);
    ui_port_id_number->setValidator(validate_oneByte_dec);

    ui_message_age->setValidator(validate_twoByte_dec);
    ui_max_age->setValidator(validate_twoByte_dec);
    ui_hello_time->setValidator(validate_twoByte_dec);
    ui_forward_delay->setValidator(validate_twoByte_dec);
}

StpConfigForm::~StpConfigForm()
{
}

StpConfigForm* StpConfigForm::createInstance()
{
    return new StpConfigForm;
}

void StpConfigForm::loadWidget(AbstractProtocol *proto)
{
    bool isOk;

    ui_protocol_id->setText(
                proto->fieldData(
                    StpProtocol::stp_protocol_identifier,
                    AbstractProtocol::FieldValue
                ).toString());
    ui_version_id->setText(
                proto->fieldData(
                    StpProtocol::stp_version_identifier,
                    AbstractProtocol::FieldValue
                ).toString());
    ui_bpdu_type->setText(
                proto->fieldData(
                    StpProtocol::stp_bpdu_type,
                    AbstractProtocol::FieldValue
                ).toString());

    quint8 flags = proto->fieldData(
                StpProtocol::stp_flags,
                AbstractProtocol::FieldValue
            ).toUInt();
    ui_flags_tc_check->setChecked(flags & ONE_BIT(0));
    ui_flags_tca_check->setChecked(flags & ONE_BIT(7));

    // Root ID contain two value: Root ID Priority(first 2 bytes)
    // and Root ID MAC (last 6 bytes). (IEEE802.1D-2008)
    ui_root_id->setText(
                proto->fieldData(
                    StpProtocol::stp_root_identifier,
                    AbstractProtocol::FieldValue
                    ).toString().remove(0, BYTES(2) * 2));
    QString stp_root_id = proto->fieldData(
                    StpProtocol::stp_root_identifier,
                    AbstractProtocol::FieldValue
                ).toString().remove(4, BYTES(6) * 2);
    ui_root_id_priority->setText(
                QString("%1").arg(stp_root_id.toUInt(&isOk, BASE_HEX),
                                  1, BASE_DEC, QChar('0')));
    ui_root_path_cost->setText(
                proto->fieldData(
                    StpProtocol::stp_root_path_cost,
                    AbstractProtocol::FieldValue
                ).toString());

    // Bridge ID contain two value: Bridge ID Priority(first 2 bytes)
    // and Bridge ID MAC (last 6 bytes). (IEEE802.1D-2008)
    ui_bridge_id->setText(
                proto->fieldData(
                    StpProtocol::stp_bridge_identifier,
                    AbstractProtocol::FieldValue
                ).toString().remove(0, BYTES(2) * 2));
    QString stp_bridge_id_priority = proto->fieldData(
                    StpProtocol::stp_bridge_identifier,
                    AbstractProtocol::FieldValue
                ).toString().remove(4, BYTES(6) * 2);
    ui_bridge_id_priority->setText(
                QString("%1").arg(stp_bridge_id_priority.toUInt(&isOk,
                                                                BASE_HEX),
                                  1, BASE_DEC, QChar('0')));

    // Port ID contain two value: Port ID Priority(first 1 byte)
    // and Port ID Number (last 1 byte). (IEEE802.1D-2008)
    ui_port_id_priority->setText(
                QString::number(proto->fieldData(
                                    StpProtocol::stp_port_identifier,
                                    AbstractProtocol::FieldValue
                                ).toString().remove(2, 2).toUInt(&isOk,
                                                                 BASE_HEX)));
    ui_port_id_number->setText(
                QString::number(proto->fieldData(
                                    StpProtocol::stp_port_identifier,
                                    AbstractProtocol::FieldValue
                                ).toString().remove(0, 2).toUInt(&isOk,
                                                                 BASE_HEX)));

    ui_message_age->setText(
                proto->fieldData(
                    StpProtocol::stp_message_age,
                    AbstractProtocol::FieldValue
                ).toString());
    ui_max_age->setText(
                proto->fieldData(
                    StpProtocol::stp_max_age,
                    AbstractProtocol::FieldValue
                ).toString());
    ui_hello_time->setText(
                proto->fieldData(
                    StpProtocol::stp_hello_time,
                    AbstractProtocol::FieldValue
                ).toString());
    ui_forward_delay->setText(
                proto->fieldData(
                    StpProtocol::stp_forward_delay,
                    AbstractProtocol::FieldValue
                ).toString());
}

void StpConfigForm::storeWidget(AbstractProtocol *proto)
{
    bool isOk;

    proto->setFieldData(
                StpProtocol::stp_protocol_identifier,
                QString("%1").arg(
                    ui_protocol_id->text().toUInt(&isOk) & TWO_BYTE_MAX));

    proto->setFieldData(
                StpProtocol::stp_version_identifier,
                ui_version_id->text());
    proto->setFieldData(
                StpProtocol::stp_bpdu_type,
                ui_bpdu_type->text());

    char flags = 0;
    if (ui_flags_tc_check->isChecked()) flags = flags | ONE_BIT(0);
    if (ui_flags_tca_check->isChecked()) flags = flags | ONE_BIT(7);
    proto->setFieldData(
                StpProtocol::stp_flags,
                flags);

    QString root_id_prio = QString("%1").arg(
                ui_root_id_priority->text().toUInt(&isOk, BASE_DEC) & TWO_BYTE_MAX,
                4, BASE_HEX, QChar('0'));

    // root ID mac is a last 6 byte (12 symbols in HEX string) of root ID
    // (IEEE802.1D-2008)
    QString root_id = ui_root_id->text().remove(
                QChar(' ')).insert(0, "000000000000").right(BYTES(6) * 2);
    proto->setFieldData(
                StpProtocol::stp_root_identifier,
                root_id_prio + root_id);
    proto->setFieldData(
                StpProtocol::stp_root_path_cost,
                ui_root_path_cost->text());

    QString bridge_id_prio = QString("%1").arg(
                ui_bridge_id_priority->text().toUInt(&isOk, BASE_DEC) & TWO_BYTE_MAX,
                4, BASE_HEX, QChar('0'));

    // bridge ID mac is a last 6 byte (12 symbols in HEX string) of bridge ID
    // (IEEE802.1D-2008)
    QString bridge_id = ui_bridge_id->text().remove(
                QChar(' ')).insert(0, "000000000000").right(BYTES(6) * 2);
    proto->setFieldData(
                StpProtocol::stp_bridge_identifier,
                bridge_id_prio + bridge_id);

    proto->setFieldData(StpProtocol::stp_port_identifier,
                        QString("%1").arg(
                            ui_port_id_priority->text().toUInt(&isOk, BASE_DEC) & ONE_BYTE_MAX,
                            2, BASE_HEX, QChar('0')) +
                        QString("%1").arg(
                            ui_port_id_number->text().toUInt(&isOk, BASE_DEC) & ONE_BYTE_MAX,
                            2, BASE_HEX, QChar('0'))
                       );
    // timers
    proto->setFieldData(
                StpProtocol::stp_message_age,
                QString("%1").arg(
                    ui_message_age->text().toUInt(&isOk, BASE_DEC) & TWO_BYTE_MAX));
    proto->setFieldData(
                StpProtocol::stp_max_age,
                QString("%1").arg(
                    ui_max_age->text().toUInt(&isOk, BASE_DEC) & TWO_BYTE_MAX));
    proto->setFieldData(
                StpProtocol::stp_hello_time,
                QString("%1").arg(
                    ui_hello_time->text().toUInt(&isOk, BASE_DEC) & TWO_BYTE_MAX));
    proto->setFieldData(
                StpProtocol::stp_forward_delay,
                QString("%1").arg(
                    ui_forward_delay->text().toUInt(&isOk, BASE_DEC) & TWO_BYTE_MAX));
}

