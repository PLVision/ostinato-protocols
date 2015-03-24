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

#ifndef _LLDP_H
#define _LLDP_H

#include "abstractprotocol.h"
#include "lldp.pb.h"
#include "QStringList"
#include "tlvmanager.h"

/* 
Lldp Protocol Frame Format -
    +----------+-------+     +---------------+
    |   Tlv   |  TLv   |     | End of lldpd  |
    |         |        | ... |     tlv       |
    +----------+-------+     +---------------+
Lldp Tlv Frame Format -
    +----------+---------+---------------+
    |   Tlv   |  TLv     | configuration |
    |   Type  | Length   |     string    |
    +----------+---------+---------------+
*/

class LldpProtocol : public AbstractProtocol
{
public:

    LldpProtocol(StreamBase *stream, AbstractProtocol *parent = 0);
    virtual ~LldpProtocol();

    static AbstractProtocol* createInstance(StreamBase *stream,
                                            AbstractProtocol *parent = 0);
    virtual quint32 protocolNumber() const;

    virtual void protoDataCopyInto(OstProto::Protocol &protocol) const;
    virtual void protoDataCopyFrom(const OstProto::Protocol &protocol);

    virtual ProtocolIdType protocolIdType() const;
    virtual quint32 protocolId(ProtocolIdType type) const;

    virtual QString name() const;
    virtual QString shortName() const;

    virtual int fieldCount() const;
    virtual int frameFieldCount() const;

    virtual AbstractProtocol::FieldFlags fieldFlags(int index) const;
    virtual QVariant fieldData(int index, FieldAttrib attrib,
                               int streamIndex = 0) const;
    virtual bool setFieldData(int index, const QVariant &value,
                              FieldAttrib = FieldValue);

    virtual int protocolFrameSize(int  = 0) const;

private:
    OstProto::Lldp data;
};

#endif
