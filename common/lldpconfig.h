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

#ifndef _LLDP_CONFIG_H
#define _LLDP_CONFIG_H

#include "abstractprotocolconfig.h"
#include "ui_lldp.h"
#include "lldp.h"
#include "tlvmanager.h"

class LldpConfigForm :
    public AbstractProtocolConfigForm, 
    private Ui::Lldp
{
    Q_OBJECT
public:
    LldpConfigForm(QWidget *parent = 0);
    virtual ~LldpConfigForm();
    static LldpConfigForm* createInstance();

    virtual void loadWidget(AbstractProtocol *proto);
    virtual void storeWidget(AbstractProtocol *proto);
    QWidget* getInputWidget(tlv_fields_struct_t current_field_type,
                            int field_index, tlv_struct_data tlv_data);
    QString getDataFromWidjet(tlv_fields_struct_t current_field_type,
                              QTableWidget *sorce_table,
                              int field_index, tlv_struct_data tlv_data);
    int loadTlvUi(int tlv_index, QString tlv_name, int first_field,
                  int last_field);
    int calculateLengthField(int currentField);
    void postLoadTableProcessor();

    void resizeEvent(QResizeEvent *event);

    QHash<QString, tlv_struct> tlv_base;
    QVector<tlv_struct_data> lldp_data;

private slots:
    void on_ui_select_tlv_button_clicked();
    void on_ui_selected_tlv_itemClicked(QListWidgetItem *);
    void on_ui_delete_clicked();
    void on_ui_up_clicked();
    void on_ui_down_clicked();
    void repaint_table();
    void on_tabWidget_currentChanged(int index);

    void on_ui_prev_tlv_clicked();

    void on_ui_next_tlv_clicked();

    void on_ui_selected_tlv_currentRowChanged(int );

public slots:
    void save_data();
    void resize_tables();
};

#endif
