
#ifndef __INT_REGEXP_VALIDATOR
#define __INT_REGEXP_VALIDATOR

#include <QValidator>

class IntAndRegExpValidator : public QValidator
{
public:
    IntAndRegExpValidator(const QRegExp & rv, int min, int max,
                          QObject * parent) : QValidator(parent), regexp_(parent), intValidator_(parent)
    {
        regexp_.setRegExp(rv);
        intValidator_.setRange(min, max);
        maxValue_ = max;
    }
virtual QValidator::State validate ( QString & input, int & pos ) const
    {
        QValidator::State res_re = regexp_.validate(input, pos);
        QValidator::State res_int = intValidator_.validate(input, pos);

        if ((res_re == Acceptable and
             res_int == Acceptable and
             input.length() <= QString::number(maxValue_).length()
            ) or
            input.isEmpty())
            return QValidator::Acceptable;
        else
            return QValidator::Invalid;
    }

private:
    int maxValue_;
    QRegExpValidator regexp_;
    QIntValidator intValidator_;
};

#endif
