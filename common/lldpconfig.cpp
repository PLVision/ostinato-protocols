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

#include "lldpconfig.h"
#include "QVariant"
#include "ipv6addressvalidator.h"
#include "tlvmanager.h"
#include "hexdumpconfig.h"
#include "intcombobox.h"
#include <QHostAddress>
#include "converters.h"
#include "intregexpvalidator.h"

#define HEXDUMP_DEFAULT_HEIGHT 50
#define QLINEEDIT_DEFAULT_HEIGHT 26
#define QLIST_ITEM_DEFAULT_HEIGHT 28
#define MAX_LEN_IPV6 39
#define MAX_LEN_VALUE_FOUR_BYTES 10
#define DEFAULT_SECTION_SIZE_IN_TABLE 149
#define DELTA_FOR_INSIDE_TABLE 3
#define TABLE_BORDER_WIDTH 4
#define TLV_HEAD_ELEMENTS_COUNT 4
#define POW2(n) (1 << n)
#define MAX_VALUE_FOR_BITS(n) (((1L << n) - 1))
#define BITS(n) (n)


LldpConfigForm::LldpConfigForm(QWidget *parent)
    : AbstractProtocolConfigForm(parent)
{
    setupUi(this);

    tlvmanager &s = tlvmanager::getInstance();
    s.readDataFromFile();
    tlv_base = s.getTlvBase();

    ui_available_tlv->addItems((QStringList)tlv_base.keys());
    ui_available_tlv->sortItems(Qt::AscendingOrder);

    ui_tlv_type->setValidator(new QIntValidator(0, MAX_VALUE_FOR_BITS(7), this));
    ui_tlv_length->setValidator(new QIntValidator(0, MAX_VALUE_FOR_BITS(9), this));

    ui_tlv_type->setDisabled(true);
    ui_tlv_length->setDisabled(true);
    ui_is_length->setDisabled(true);

    ui_up->setDisabled(true);
    ui_down->setDisabled(true);
    ui_delete->setDisabled(true);

    connect(ui_tlv_type, SIGNAL(editingFinished()), this, SLOT(save_data()));
    connect(ui_tlv_length, SIGNAL(editingFinished()), this, SLOT(save_data()));
    connect(ui_is_length, SIGNAL(toggled(bool)), this, SLOT(save_data()));
}

void LldpConfigForm::resizeEvent(QResizeEvent *event)
{
    if (this->ui_data_table != NULL)
        this->resize_tables();
    QWidget::resizeEvent(event);
}

void IntComboBox::focusOutEvent(QFocusEvent *event)
{
    if (old_value != currentValue())
        emit focusLost();
    old_value = currentValue();
    QWidget::focusOutEvent(event);
}


LldpConfigForm::~LldpConfigForm()
{
}

LldpConfigForm* LldpConfigForm::createInstance()
{
    return new LldpConfigForm;
}

void LldpConfigForm::loadWidget(AbstractProtocol *proto)
{
    int i = 0;
    for (i = 0; i < proto->fieldCount(); i++)
    {

        bool isOk = false;
        QStringList value = proto->fieldData(i, AbstractProtocol::FieldValue)
                .toString().split(';');

        qint8 tlv_type = value[0].toUInt(&isOk, BASE_DEC); // TLV ID
        qint16 tlv_length = value[1].toUInt(&isOk, BASE_DEC); // TLV length
        int id = value[2].toUInt(&isOk, BASE_DEC); // count of fields
        bool is_length = value[3].toUInt(&isOk, BASE_DEC); // is override length
        connect(ui_is_length, SIGNAL(toggled(bool)), this, SLOT(save_data()));

        QString tlv_name = tlvmanager::getTlvById(id).name;

        ui_selected_tlv->addItem(tlv_name);

        tlv_struct_data new_item;
        new_item.name = tlv_name;
        new_item.is_override_length = is_length;
        new_item.id = id;
        new_item.tlvtype = tlv_type;
        new_item.length = tlv_length;
        new_item.field = tlv_base[tlv_name].getFieldsDefaultValuesList();
        if (tlv_name == "Custom")
        {
            QString custom_string;
            for (int j = TLV_HEAD_ELEMENTS_COUNT; j < value.count(); j++)
                custom_string.append(value[j]);
            new_item.field[0] = custom_string;
        }
        else
        {
             // because first two values is: ID, length and other...
            for (int j = 0; j < value.count() - TLV_HEAD_ELEMENTS_COUNT; j++)
                if (new_item.field.count() > j)
                    new_item.field[j] = value[j + TLV_HEAD_ELEMENTS_COUNT];
        }
        lldp_data.push_back(new_item);
    }
    if (i > 0)
    {
        ui_selected_tlv->setCurrentRow(0);
        on_ui_selected_tlv_currentRowChanged(0);

        ui_up->setEnabled(true);
        ui_down->setEnabled(true);
        ui_delete->setEnabled(true);
    }
}

void LldpConfigForm::storeWidget(AbstractProtocol *proto)
{
    QString res;

    for (int i = 0 ; i < lldp_data.count() ; i++)
    {
        res.clear();
        res.append(QString::number(lldp_data[i].tlvtype) + ';' +
                   QString::number(lldp_data[i].length) + ';' +
                   QString::number(lldp_data[i].id) + ';' +
                   QString::number(lldp_data[i].is_override_length)
                  );
        for (int j = 0; j < tlv_base[lldp_data[i].name].fields_count; j++)
            res.append(';' + lldp_data[i].field[j]);
        proto->setFieldData(i, res);
    }
    if (lldp_data.isEmpty())
        proto->setFieldData(-1,"");
}

void LldpConfigForm::on_ui_select_tlv_button_clicked()
{
    QString tlv_name = ui_available_tlv->selectedItems()[0]->text();

    ui_selected_tlv->blockSignals(true);
    ui_selected_tlv->addItem(tlv_name);
    ui_selected_tlv->blockSignals(false);

    tlv_struct_data new_item;
    new_item.name = tlv_name;
    new_item.is_override_length = false;
    new_item.id = tlv_base[tlv_name].id;
    new_item.tlvtype = tlv_base[tlv_name].tlvtype;
    new_item.length = tlv_base[tlv_name].length;
    new_item.field = tlv_base[tlv_name].getFieldsDefaultValuesList();
    for(int i = 0; i < new_item.field.count(); i++)
    {
        QString item = new_item.field[i];
        if (item.isEmpty())
            new_item.field[i] = allignToSizeHex(QString(""),
                                                tlv_base[tlv_name].field[i]);
    }
    new_item.calculateLength();
    lldp_data.push_back(new_item);

    if (ui_selected_tlv->count() == 1)
    {
        ui_selected_tlv->setCurrentRow(0);
        on_ui_selected_tlv_currentRowChanged(0);

        ui_up->setEnabled(true);
        ui_down->setEnabled(true);
        ui_delete->setEnabled(true);
    }
}

void LldpConfigForm::on_ui_delete_clicked()
{
    int currentRow = ui_selected_tlv->currentRow();
    if (currentRow == -1)
        return;
    if (ui_selected_tlv->count() == 1) // if delete last record
    {
        ui_up->setEnabled(false);
        ui_down->setEnabled(false);
        ui_delete->setEnabled(false);
        ui_tlv_type->setEnabled(false);
        ui_tlv_length->setEnabled(false);
        ui_tlv_type->clear();
        ui_tlv_length->clear();
        ui_is_length->setChecked(false);
        ui_is_length->setEnabled(false);
        ui_tlv_name->clear();

        ui_data_table->setRowCount(0);
        ui_data_table->clear();
    }
    lldp_data.remove(currentRow);
    ui_selected_tlv->blockSignals(true);
    ui_selected_tlv->takeItem(currentRow);
    ui_selected_tlv->blockSignals(false);
}

void LldpConfigForm::on_ui_up_clicked()
{
    int currentRow = ui_selected_tlv->currentRow();
    if (currentRow == -1)
        return;
    if (currentRow > 0) // if select not first TLV
    {
        tlv_struct_data tmp_tlv = lldp_data[currentRow - 1];
        lldp_data.replace(currentRow - 1, lldp_data[currentRow]);
        lldp_data.replace(currentRow, tmp_tlv);

        ui_selected_tlv->blockSignals(true);
        QListWidgetItem* currentItem(ui_selected_tlv->takeItem(currentRow));
        ui_selected_tlv->insertItem(currentRow - 1, currentItem);
        ui_selected_tlv->setCurrentRow(currentRow - 1);
        ui_selected_tlv->blockSignals(false);
    }
}

void LldpConfigForm::on_ui_down_clicked()
{
    int currentRow = ui_selected_tlv->currentRow();
    if (currentRow == -1)
        return;
    if (currentRow < lldp_data.count() - 1) // if select not last TLV
    {
        tlv_struct_data tmp_tlv = lldp_data[currentRow + 1];
        lldp_data.replace(currentRow + 1, lldp_data[currentRow]);
        lldp_data.replace(currentRow, tmp_tlv);

        ui_selected_tlv->blockSignals(true);
        QListWidgetItem* currentItem = ui_selected_tlv->takeItem(currentRow);
        ui_selected_tlv->insertItem(currentRow + 1, currentItem);
        ui_selected_tlv->setCurrentRow(currentRow + 1);
        ui_selected_tlv->blockSignals(false);
    }
}

QWidget* LldpConfigForm::getInputWidget(tlv_fields_struct_t current_field_type,
                                        int field_index,
                                        tlv_struct_data tlv_data)
// return QWidjet according field type
{
    QString text_value = (tlv_data.field[field_index]);
    if (text_value.isEmpty())
        text_value = current_field_type.dafault_value;
    bool isOk;
    tlvmanager &s = tlvmanager::getInstance();

    QRect line_edit_rect;
    line_edit_rect.setHeight(QLINEEDIT_DEFAULT_HEIGHT);

    int switch_value = current_field_type.type;
    l_startSwitch:
    switch (switch_value)
    {
        case THexInput:
        {
            l_hexinput:
            QLineEdit *le = new QLineEdit(allignToSizeHex(text_value,
                                                          current_field_type));
            le->setGeometry(line_edit_rect);
            QString mask;
            for(int i=0; i<current_field_type.getMax(); ++i) mask.append("HH ");
            le->setInputMask(QString(">%1;").arg(mask));

            connect(le, SIGNAL(textEdited(QString)), this, SLOT(save_data()));
            return le;
        }
        case TMacAddress:
        {
            if (text_value.isEmpty())
                text_value = "00:00:00:00:00:00";
            QLineEdit *le = new QLineEdit();
            le->setGeometry(line_edit_rect);
            le->setInputMask(QString(">HH:HH:HH:HH:HH:HH;"));
            le->setText(allignToSizeHex(text_value, current_field_type));
            le->setMaxLength(le->inputMask().length());
            connect(le, SIGNAL(textEdited(QString)), this, SLOT(save_data()));
            return le;
        }
        case TIpv4Address:
        {
            if (text_value.isEmpty())
                text_value = "0.0.0.0";
            QLineEdit *le = new QLineEdit(hexStrToIpv4(text_value));
            le->setGeometry(line_edit_rect);
            le->setInputMask("000.000.000.000");
//            QRegExp reIpv4("^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.)"
//                           "{3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$");
//            QRegExpValidator *validate_ipv4 = new QRegExpValidator(reIpv4,
//                                                                   this);
//            le->setValidator(validate_ipv4);
//          // uncomment for use validation on ranges
            connect(le, SIGNAL(textEdited(QString)), this, SLOT(save_data()));
            return le;
        }
        case TIpv6Address:
        {
            if (text_value.isEmpty())
                text_value = "0000:0000:0000:0000:0000:0000:0000:0000";
            QLineEdit *le = new QLineEdit(hexStrToIpv6(text_value));
            le->setGeometry(line_edit_rect);
            le->setValidator(new IPv6AddressValidator(this));
            le->setMaxLength(MAX_LEN_IPV6);
            connect(le, SIGNAL(textEdited(QString)), this, SLOT(save_data()));
            return le;
        }
        case TAlphaNumeric:
        {
            QLineEdit *le = new QLineEdit(hexStrToAlphaNumeric(text_value));
            le->setGeometry(line_edit_rect);
            QRegExp reAlpha_num("[!\"#$%&'()*+\\`\\.\\,/:;<=>?@[\\]^_{|}~0-9A-Za-z \\-\\\\]*");
            qulonglong max_value = current_field_type.getMax(UnitOctet);
            le->setValidator(new QRegExpValidator(reAlpha_num, this));
            le->setMaxLength(max_value);
            connect(le, SIGNAL(textEdited(QString)), this, SLOT(save_data()));
            return le;
        }
        case TOID:
        {
            QLineEdit *le = new QLineEdit(hexStrToOid(text_value));
            le->setGeometry(line_edit_rect);
            QRegExp reOid("([0-9]*\\.)*[0-9]?");
            qulonglong max_value = current_field_type.getMax(UnitOctet);
            le->setValidator(new QRegExpValidator(reOid, this));
            le->setMaxLength(max_value);
            connect(le, SIGNAL(textEdited(QString)), this, SLOT(save_data()));
            return le;
        }
        case TTime:
        case TLength:
        {
            if (text_value.isEmpty())
                text_value = "0";
            QLineEdit *le = new QLineEdit(hexStrToUDecStr(text_value));
            le->setGeometry(line_edit_rect);
            le->setDisabled(true);
            qulonglong max_value =
                    MAX_VALUE_FOR_BITS(current_field_type.getMax(UnitBit));
            le->setValidator(new QIntValidator(0, max_value, this));
            le->setMaxLength(QString::number(max_value).length());
            connect(le, SIGNAL(textEdited(QString)), this, SLOT(save_data()));
            return le;
        }
        case TDecInput:
        {
            if (text_value.isEmpty())
                text_value = "0";
            QLineEdit *le = new QLineEdit(hexStrToUDecStr(text_value));
            le->setGeometry(line_edit_rect);
            qulonglong max_value =
                    MAX_VALUE_FOR_BITS(current_field_type.getMax(UnitBit));
            if (current_field_type.getMax(UnitBit) > 31)
            {
                QRegExp re_four_bytes("([0-9]{1,9}|[1-3][0-9]{9}|4[01][0-9]{8}|"
                                      "42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-"
                                      "8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6"
                                      "][0-9]{3}|4294967[01][0-9]{2}|42949672[0"
                                      "-8][0-9]|429496729[0-5])");
                le->setValidator(new QRegExpValidator(re_four_bytes, this));
                le->setMaxLength(MAX_LEN_VALUE_FOUR_BYTES);
            }
            else
            {
                le->setValidator(new QIntValidator(0, max_value, this));
                le->setMaxLength(QString::number(max_value).length());
            }
            connect(le, SIGNAL(textEdited(QString)), this, SLOT(save_data()));
            return le;
        }
        case TBinInput:
        {
            QLineEdit *le = new QLineEdit(
                        allignToSizeBin(hexStrToBitStr(text_value),
                                        current_field_type));
            le->setInputMask(QString(">%1;").arg(
                                 QString().fill('B',current_field_type.getMax(UnitBit))));

            le->setGeometry(line_edit_rect);
            connect(le, SIGNAL(textEdited(QString)), this, SLOT(save_data()));
            return le;
        }
        case THexDump:
        {
            QHexEdit *he = new QHexEdit();
            QByteArray array;
            int row_height = HEXDUMP_DEFAULT_HEIGHT;
            if (current_field_type.arguments.contains("hexdumpheight"))
            {
                row_height = current_field_type.
                        arguments["hexdumpheight"].toInt(&isOk);
            }

            array = hexStrToByteArray(text_value);
            he->setData(array);
            he->setMinimumHeight(row_height);
            he->setEnabled(true);
            he->setFont(QFont("Courier"));
            he->setOverwriteMode(false);
            connect(he, SIGNAL(dataChanged()), this, SLOT(save_data()));
            QRect rect = he->geometry();
            rect.setHeight(row_height);  // minus title height
            he->setGeometry(rect);
            return he;
        }
        case TEnum:
        {
            QString enum_name = current_field_type.arguments["enum"];
            IntComboBox *cb = new IntComboBox();
            cb->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
            cb->setFixedHeight(QLIST_ITEM_DEFAULT_HEIGHT);

            qulonglong max_value =
                    MAX_VALUE_FOR_BITS(current_field_type.getMax(UnitBit));
            cb->setValidator(new IntAndRegExpValidator(QRegExp("[0-9]*"),
                                                       0, max_value, this));
            foreach (enum_struct::enum_item_type item,
                     s.enums_base[enum_name].items)
            {
                QString name = item.name;
                int value = 0;
                if (item.value.isEmpty())
                    value = item.id;
                else
                    value = item.value.toInt(&isOk, BASE_HEX);
                cb->addItem(value, name);
            }
            cb->setValue(text_value.toInt(&isOk, BASE_HEX));
            connect(cb, SIGNAL(focusLost()), this, SLOT(save_data()));
            return cb;
        }
        case TItemlist:
        {
            QGroupBox *gb = new QGroupBox();
            QVBoxLayout *vbox = new QVBoxLayout;
            QString enum_name = current_field_type.arguments["enum"];
            QString bin_string = hexStrToBitStr(text_value).right(
                        s.enums_base[enum_name].items.count());
            bin_string = reverseSrting(bin_string); //bits in frame are reversed
            int i = 0;
            if (current_field_type.arguments["subtype"] == "checkbox")
                foreach (enum_struct::enum_item_type item,
                         s.enums_base[enum_name].items)
                {
                    QCheckBox *cb = new QCheckBox(item.name);
                    if (bin_string[i] == '1')
                        cb->setChecked(true);
                    vbox->addWidget(cb);
                    i++;
                    connect(cb, SIGNAL(stateChanged(int)),
                            this, SLOT(save_data()));
                }
            if (current_field_type.arguments["subtype"] == "radio")
                foreach (enum_struct::enum_item_type item,
                         s.enums_base[enum_name].items)
                {
                    QRadioButton *cb = new QRadioButton(item.name);
                    if (bin_string[i] == '1')
                        cb->setChecked(true);
                    vbox->addWidget(cb);
                    i++;
                    connect(cb, SIGNAL(toggled(bool)), this, SLOT(save_data()));
                }
            gb->setLayout(vbox);
            QRect rect = gb->geometry();
            rect.setHeight(i * QLIST_ITEM_DEFAULT_HEIGHT); // minus title height
            gb->setGeometry(rect);
            return gb;
        }
        case TDepend:
        {
            int dependfield = current_field_type.arguments["dependences"]
                                                .toInt(&isOk, BASE_DEC);
            int dependFieldIndex = tlv_data.getFieldIndexById(dependfield);
            if (!tlv_data.field[dependFieldIndex].isEmpty())
            {
                QString item_enum_value = tlv_data.field[dependFieldIndex];
                QString enum_name = tlv_base[tlv_data.name]
                        .field[dependFieldIndex].arguments["enum"];
                int item_enum_index = s.enums_base[enum_name]
                        .getItemByValue(item_enum_value);
                if (item_enum_index == -1)
                    switch_value = THexInput;
                else
                {
                    QString type = s.enums_base[enum_name]
                            .items[item_enum_index].dependentfieldtype;
                    int itype= strToFieldType(type);
                    switch_value = itype;
                }
                if (text_value == "00")
                    text_value.clear();
                goto l_startSwitch;
            }
        }
        case TBitfields:
        {
            QTableWidget *tw = new QTableWidget();
            tlv_struct_data field_tlv_data;
            QVector<tlv_fields_struct_t> current_subfields =
                    current_field_type.subfield;
            QString bin_value = hexStrToBitStr(tlv_data.field[field_index]);
            for (int i = current_subfields.count() - 1; i >= 0; i--)
            {
                field_tlv_data.field.push_front(
                            bitStrToHexStr(bin_value.right(
                                               current_subfields[i]
                                               .getMin(UnitBit))));
                bin_value.remove(bin_value.length() -
                                 current_subfields[i].getMin(UnitBit),
                                 current_subfields[i].getMin(UnitBit));
            }

            tw->clear();
            tw->horizontalHeader()->hide();
            tw->setColumnCount(1);
            tw->setRowCount(current_field_type.subfield.count());
            tw->setVerticalHeaderLabels(current_field_type
                                        .getSubfieldsNameList());
            tw->horizontalHeader()->setDefaultSectionSize(
                        DEFAULT_SECTION_SIZE_IN_TABLE);

            int h = 0;
            for (int i = 0; i < tw->rowCount(); i++)
                h += tw->rowHeight(i);

            for (int i = 0; i < current_subfields.count(); i++)
                tw->setCellWidget(i, 0, getInputWidget(
                                      current_field_type.subfield[i],
                                      i, field_tlv_data));
            QRect rect = tw->geometry();
            rect.setHeight(h + DELTA_FOR_INSIDE_TABLE);
            tw->setGeometry(rect);
            return tw;
        }
        default:
            goto l_hexinput;
    }
}

QString LldpConfigForm::getDataFromWidjet(
        tlv_fields_struct_t current_field_type,
        QTableWidget *sorce_table,
        int field_index,
        tlv_struct_data tlv_data)
{
    bool isOk;
    tlvmanager &s = tlvmanager::getInstance();

    int switch_value = current_field_type.type;
    l_startSwitch:
    switch (switch_value)
    {
        case THexInput:
        {
            l_HexLineInput:
            QLineEdit* le = qobject_cast<QLineEdit*>(
                        sorce_table->cellWidget(field_index, 0));
            QString hex_text = le->text();
            QString res = hex_text.left(
                        hex_text.lastIndexOf(
                            QRegExp("[A-F0-9]")) + 2)
                    .replace(" ","  ").append(" ").insert(0," ");
            res.replace(QRegExp("[ ^]([A-F0-9])[ $]")," 0\\1 ").remove(" ");
            return res;
        }
        case TMacAddress:
        {
            QLineEdit* le = qobject_cast<QLineEdit*>(
                        sorce_table->cellWidget(field_index, 0));
            QString res;
            foreach (QString s, le->text().split(":"))
                res.append(s.insert(0, "00").right(2));
            return res;
        }
        case TIpv4Address:
        {
            QLineEdit* le = qobject_cast<QLineEdit*>(
                        sorce_table->cellWidget(field_index, 0));
            QString res = ipv4ToHexStr(le->text());
            return res;
        }
        case TIpv6Address:
        {
            QLineEdit* le = qobject_cast<QLineEdit*>(
                        sorce_table->cellWidget(field_index, 0));
            QString res = ipV6ToHexStr(le->text());

            return res;
        }
        case TAlphaNumeric:
        {
            QLineEdit* le = qobject_cast<QLineEdit*>(
                        sorce_table->cellWidget(field_index, 0));
            QString res = "";
            foreach (QChar a, le->text()) {
                res.append(QString("%1").arg(a.toAscii(), 2, BASE_HEX, QChar('0')));

            }
            return res;
        }
        case TOID:
        {
            QLineEdit* le = qobject_cast<QLineEdit*>(
                        sorce_table->cellWidget(field_index, 0));
            QString res = "";
            res = oidToHexStr(le->text());
            return res;
        }
        case TTime:
        case TLength:
        case TDecInput:
        {
            QLineEdit* le = qobject_cast<QLineEdit*>(
                        sorce_table->cellWidget(field_index, 0));
            QString res = QString("%1").arg(le->text()
                                            .toUInt(&isOk, BASE_DEC),
                                            2, BASE_HEX, QChar('0'));
            return res;
        }
        case TBinInput:
        {
            QLineEdit* le = qobject_cast<QLineEdit*>(
                        sorce_table->cellWidget(field_index, 0));
            QString res = bitStrToHexStr(le->text());
            return res;
        }
        case THexDump:
        {
            QHexEdit* he = qobject_cast<QHexEdit*>(
                        sorce_table->cellWidget(field_index, 0));
            QByteArray array(he->data(), he->data().size());
            QString res(QString(array.toHex()));
            return res;
        }
        case TEnum:
        {
            QComboBox* cb = qobject_cast<QComboBox*>(
                        sorce_table->cellWidget(field_index, 0));
            repaint();
            int value = cb->currentText().split('-').first().toUInt(&isOk,
                                                                    BASE_DEC);
            QString res = QString("%1").arg(value,
                                            current_field_type.
                                                getMin(UnitOctet) * 2,
                                            BASE_HEX, QChar('0'));
            return res;
        }
        case TItemlist:
        {
            QGroupBox* gb = qobject_cast<QGroupBox*>(
                        sorce_table->cellWidget(field_index, 0));
            QVBoxLayout* vbox = qobject_cast<QVBoxLayout*>(gb->layout());
            QString res;
            for(int i = vbox->count() - 1; i >= 0; i--)
                // bits in frame is reversed
            {
                QWidget* item = qobject_cast<QWidget*>(
                            vbox->itemAt(i)->widget());
                if (current_field_type.arguments["subtype"] == "checkbox")
                {
                    QCheckBox* cb = qobject_cast<QCheckBox*>(item);
                    if (cb->isChecked())
                        res.append("1");
                    else
                        res.append("0");
                }
                if (current_field_type.arguments["subtype"] == "radio")
                {
                    QRadioButton* cb = qobject_cast<QRadioButton*>(item);
                    if (cb->isChecked())
                        res.append("1");
                    else
                        res.append("0");
                }
            }
            int binStrLen = res.length();
            // alignment binary string to full byte
            if (binStrLen % 8 != 0)
                res.insert(0, QString().fill('0', BITS(8) - (binStrLen % 8)));

            return bitStrToHexStr(res);
        }
        case TDepend:
        {
            int dependfield = current_field_type.arguments["dependences"]
                    .toInt(&isOk, BASE_DEC);
            int dependFieldIndex = tlv_data.getFieldIndexById(dependfield);
            if (!tlv_data.field[dependFieldIndex].isEmpty())
            {
                QString item_enum_value = tlv_data.field[dependFieldIndex];
                QString enum_name = tlv_base[tlv_data.name]
                        .field[dependFieldIndex].arguments["enum"];
                int item_enum_index = s.enums_base[enum_name]
                        .getItemByValue(item_enum_value);
                if (item_enum_index == -1)
                    switch_value = THexInput;
                else
                {
                    QString type = s.enums_base[enum_name]
                            .items[item_enum_index].dependentfieldtype;
                    int itype= strToFieldType(type);
                    switch_value = itype;
                }
                goto l_startSwitch;
            }
            goto l_HexLineInput;
        }
        case TBitfields:
        {
            QTableWidget* tw = qobject_cast<QTableWidget*>(
                        sorce_table->cellWidget(field_index, 0));
            QString value_t;
            for (int i = 0; i < current_field_type.subfield.count(); i++)
            {
                QString res = getDataFromWidjet(
                            current_field_type.subfield[i], tw, i, tlv_data);
                QString out = allignToSizeBin(hexStrToBitStr(res),
                                              current_field_type.subfield[i]);
                value_t.append(out);
            }
            return allignToSizeHex(bitStrToHexStr(value_t),current_field_type);
        }
        default:
            goto l_HexLineInput;
    }
}

int LldpConfigForm::loadTlvUi(int tlv_index,
                              QString tlv_name,
                              int first_field = -1,
                              int last_field = -1)
// build table
{
    bool load_all_fields = false;
    if (first_field == -1 and last_field == -1)
    {
        first_field = 0;
        last_field = tlv_base[tlv_name].fields_count;
        load_all_fields = true;
    }
    if (load_all_fields)
    {
        ui_tlv_type->setEnabled(true);
        ui_tlv_length->setEnabled(true);
        ui_is_length->setEnabled(true);

        ui_tlv_name->setText(QString("[%1] %2").arg(QString::number(
                                                        tlv_index + 1),
                                                    lldp_data[tlv_index].name));
        ui_tlv_type->setText(QString::number(lldp_data[tlv_index].tlvtype,
                                             BASE_DEC));
        ui_tlv_length->setText(QString::number(lldp_data[tlv_index].length,
                                               BASE_DEC));
        ui_is_length->setChecked(lldp_data[tlv_index].is_override_length);
        ui_tlv_length->setEnabled(lldp_data[tlv_index].is_override_length);
        ui_data_table->horizontalHeader()->hide();

        ui_data_table->clear();
        ui_data_table->setRowCount(tlv_base[tlv_name].fields_count);
        ui_data_table->setVerticalHeaderLabels(tlv_base[tlv_name]
                                               .getFieldsNameList());
        ui_data_table->horizontalHeader()->setDefaultSectionSize(
                    DEFAULT_SECTION_SIZE_IN_TABLE);
        ui_data_table->insertColumn(0);
    }

    for (int i = first_field; i < last_field; i++)
    {
        if (lldp_data.count() > tlv_index)
        {
            QWidget *qw = getInputWidget(tlv_base[tlv_name].field[i],
                                         i, lldp_data[tlv_index]);
            int height = qw->size().height();
            ui_data_table->setCellWidget(i, 0, qw);
            ui_data_table->setRowHeight(i, height);

            QString current_item = getDataFromWidjet(
                        tlv_base[tlv_name].field[i], ui_data_table, i,
                        lldp_data[tlv_index]);
            QString out = allignToSizeHex(current_item,
                                          tlv_base[tlv_name].field[i]);
            lldp_data[tlv_index].field[i] = out;
        }
    }

    if (load_all_fields)
    {
        resize_tables();
        save_data();
    }
    return 0;
}

void LldpConfigForm::resize_tables()
{
    ui_data_table->repaint();
    ui_data_table->setColumnWidth(0, ui_data_table->width()
                                  - ui_data_table->verticalHeader()->width()
                                  - ui_data_table->verticalScrollBar()->width()
                                  - TABLE_BORDER_WIDTH );
    postLoadTableProcessor();
}

void LldpConfigForm::on_ui_selected_tlv_itemClicked(QListWidgetItem* /*item*/)
// add TLV to selected
{
    int item_index = ui_selected_tlv->currentRow();
    QString item_name = ui_selected_tlv->currentItem()->text();
    loadTlvUi(item_index, item_name);
}

void LldpConfigForm::save_data()
{
    QObject* sender_object=QObject::sender();
    bool isOk;
    int currentTlv = ui_selected_tlv->currentRow();
    QString tlv_name = ui_selected_tlv->currentItem()->text();

    if (sender_object == ui_is_length)
    {
        lldp_data[currentTlv].is_override_length = ui_is_length->isChecked();
        if (!ui_is_length->isChecked())
        {
            lldp_data[currentTlv].calculateLength();
            ui_tlv_length->setText(QString::number(lldp_data[currentTlv].
                                                   length));
        }
        return;
    }
    if (sender_object == ui_tlv_type)
    {
        lldp_data[currentTlv].tlvtype = ui_tlv_type->text().toInt(&isOk);
        return;
    }
    if (sender_object == ui_tlv_length)
    {
        lldp_data[currentTlv].length = ui_tlv_length->text().toInt(&isOk);
        return;
    }
    lldp_data[currentTlv].id = tlv_base[tlv_name].id;

    int edited_field = -1;
    for (int i = 0; i < ui_data_table->rowCount(); i++)
    {
        QWidget* qw = qobject_cast<QWidget*>(sender_object);
        QWidget* qw_from_table = ui_data_table->cellWidget(i, 0);
        if (qw == qw_from_table)
            edited_field = i;
    }

    int first_edited_field = edited_field;
    int last_edited_field = edited_field + 1;
    if (edited_field == -1)
    {
        first_edited_field = 0;
        last_edited_field = ui_data_table->rowCount();
    }

    for (int i = first_edited_field; i < last_edited_field; i++)
    {
        QString current_item = getDataFromWidjet(tlv_base[tlv_name].field[i],
                                                 ui_data_table, i,
                                                 lldp_data[currentTlv]);
        QString out = allignToSizeHex(current_item, tlv_base[tlv_name].field[i]);
        current_item = out;
        lldp_data[currentTlv].field[i] = current_item;

        if (tlv_base[tlv_name].field[i].type == TLength)
        {
            int length = calculateLengthField(i);
            lldp_data[currentTlv].field[i] = allignToSizeHex(
                        QString::number(length, BASE_HEX),
                        tlv_base[tlv_name].field[i]);
            QLineEdit* le = qobject_cast<QLineEdit*>(
                        ui_data_table->cellWidget(i, 0));
            le->setText(QString::number(length));
        }
        if (tlv_base[tlv_name].field[i].arguments.contains("dependlength"))
            //field has depend length field
        {
            int dependLengthFieldIndex = tlv_base[tlv_name]
                    .field[i].arguments["dependlength"].toInt(&isOk);
            int length = calculateLengthField(dependLengthFieldIndex);
            lldp_data[currentTlv].field[dependLengthFieldIndex] =
                    allignToSizeHex(QString::number(length, BASE_HEX),
                                    tlv_base[tlv_name]
                                        .field[dependLengthFieldIndex]);
            QLineEdit* le = qobject_cast<QLineEdit*>(
                        ui_data_table->cellWidget(dependLengthFieldIndex, 0));
            le->setText(QString::number(length));
        }
        if (tlv_base[tlv_name].field[i].type == TEnum)
        {
            QString enum_name = tlv_base[tlv_name].field[i].arguments["enum"];
            QString enum_type = tlvmanager::getEnumByName(enum_name).type;
            if (enum_type == "typelist")
            {
                FieldType depend_field_type;
                QStringList depend_fields;

                for (int j = 0; j < ui_data_table->rowCount(); j++)
                {
                    depend_field_type = tlv_base[tlv_name].field[j].type;
                    depend_fields = tlv_base[tlv_name].field[j]
                            .arguments["dependences"].split(',');
                    if (depend_field_type == TDepend and depend_fields.contains(
                                QString::number(i)))
                    {
                        int field_index = j;
                        if (edited_field != -1)
                            lldp_data[currentTlv].field[field_index] = "";
                        loadTlvUi(currentTlv, tlv_name, field_index,
                                  field_index + 1);
                    }
                }
                if (tlv_base[tlv_name].field[i].arguments.
                        contains("dependlength"))
                {
                    int dependLengthFieldIndex = tlv_base[tlv_name]
                            .field[i].arguments["dependlength"].toInt(&isOk);
                    int length = calculateLengthField(dependLengthFieldIndex);
                    lldp_data[currentTlv].field[dependLengthFieldIndex] =
                            allignToSizeHex(QString::number(length, BASE_HEX),
                                            tlv_base[tlv_name]
                                                .field[dependLengthFieldIndex]);
                    lldp_data[currentTlv].field[dependLengthFieldIndex] =
                            allignToSizeHex(QString::number(length, BASE_HEX),
                                            tlv_base[tlv_name]
                                                .field[dependLengthFieldIndex]);
                    QLineEdit* le = qobject_cast<QLineEdit*>(
                                ui_data_table->cellWidget(dependLengthFieldIndex,
                                                          0));
                    le->blockSignals(true);
                    le->setText(QString::number(length));
                    le->blockSignals(false);
                }
            }
        }
    }
    lldp_data[currentTlv].calculateLength();
    ui_tlv_length->setText(QString::number(lldp_data[currentTlv].length));

}

void LldpConfigForm::repaint_table()
{
    if (ui_selected_tlv->selectedItems().isEmpty())
        return;
    on_ui_selected_tlv_itemClicked(ui_selected_tlv->selectedItems()[0]);
}

void LldpConfigForm::postLoadTableProcessor()
{
    if (ui_selected_tlv->selectedItems().isEmpty())
        return;

    QString selected_tlv_name = ui_selected_tlv->selectedItems()[0]->text();
    for (int i = 0; i < tlv_base[selected_tlv_name].field.count(); i++)
    {
        if (tlv_base[selected_tlv_name].field[i].type == TBitfields)
        {
            QTableWidget* tw = qobject_cast<QTableWidget*>(
                        ui_data_table->cellWidget(i, 0));
            if (tw != NULL)
                tw->setColumnWidth(0,
                                   ui_data_table->columnWidth(0) -
                                   tw->verticalHeader()->width() -
                                   TABLE_BORDER_WIDTH
                                   );
        }
    }
}

int  LldpConfigForm::calculateLengthField(int currentField)
{
    bool isOk = true;
    QString tlv_name = ui_selected_tlv->currentItem()->text();
    tlv_struct current_tlv = tlv_base[tlv_name];
    int currentTlv_index = ui_selected_tlv->currentRow();
    int length = 0;
        if (current_tlv.field[currentField].type == TLength)
        {
            QStringList depend = current_tlv.field[currentField]
                    .arguments["dependences"].split(',');
            foreach (QString field, depend)
            {
                int need_index = lldp_data[currentTlv_index].getFieldIndexById(
                            field.toInt(&isOk, BASE_DEC));
                length += lldp_data[currentTlv_index].field[need_index]
                        .length();
            }
        }
    return ceil(length / 2.0); // two symbols represent one byte in HEX base
}

void LldpConfigForm::on_tabWidget_currentChanged(int index)
{
    if (index == 1)
        repaint_table();
}

void LldpConfigForm::on_ui_prev_tlv_clicked()
{
    int sel_index = ui_selected_tlv->currentRow();
    if (sel_index > 0)
        ui_selected_tlv->setCurrentRow(sel_index - 1);
}

void LldpConfigForm::on_ui_next_tlv_clicked()
{
    int sel_index = ui_selected_tlv->currentRow();
    if (sel_index < ui_selected_tlv->count() - 1)
        ui_selected_tlv->setCurrentRow(sel_index + 1);
}

void LldpConfigForm::on_ui_selected_tlv_currentRowChanged(int /*currentRow*/)
{
    on_ui_selected_tlv_itemClicked(ui_selected_tlv->currentItem());
}
