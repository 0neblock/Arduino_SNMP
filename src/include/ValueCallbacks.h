#ifndef VALUE_CALLBACKS_h
#define VALUE_CALLBACKS_h

#include "BER.h"
#include <deque>
#include <algorithm>

class ValueCallback {
  public:
    ValueCallback(SortableOIDType* oid, ASN_TYPE type): OID(oid), type(type){};
    ~ValueCallback(){
        delete OID;
    }
    SortableOIDType * const OID;

    ASN_TYPE type;

    bool isSettable = false;
    bool setOccurred = false;

    void resetSetOccurred(){
        setOccurred = false;
    }

    static ValueCallback* findCallback(std::deque<ValueCallback*> &callbacks, const OIDType* const oid, bool walk, size_t startAt = 0, size_t *foundAt = nullptr);
    static std::shared_ptr<BER_CONTAINER> getValueForCallback(ValueCallback* callback);
    static SNMP_ERROR_STATUS setValueForCallback(ValueCallback* callback, const std::shared_ptr<BER_CONTAINER> &value);

protected:
    virtual std::shared_ptr<BER_CONTAINER> buildTypeWithValue() = 0;
    virtual SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) = 0;
};

bool compare_callbacks (const ValueCallback* first, const ValueCallback* second);
void sort_handlers(std::deque<ValueCallback*>&);
bool remove_handler(std::deque<ValueCallback*>&, ValueCallback*);

class IntegerCallback: public ValueCallback {
  public:
    IntegerCallback(SortableOIDType* oid, int* value): ValueCallback(oid, INTEGER), value(value) {};

  protected:
    int* const value;
    int modifier = 0;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

class TimestampCallback: public ValueCallback {
  public:
    TimestampCallback(SortableOIDType* oid, int* value): ValueCallback(oid, TIMESTAMP), value(value) {};

  protected:
    int* const value;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

class ReadOnlyStringCallback: public ValueCallback {
public:
    ReadOnlyStringCallback(SortableOIDType* oid, std::string value): ValueCallback(oid, STRING), value(value) {};

protected:
    std::string value;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER*) override {
        return NO_ACCESS;
    };
};

class StringCallback: public ValueCallback {
  public:
    StringCallback(SortableOIDType* oid, char** value, int max_len): ValueCallback(oid, STRING), value(value), max_len(max_len) {};

  protected:
    char** const value;
    size_t const max_len;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

class OpaqueCallback: public ValueCallback {
  public:
    OpaqueCallback(SortableOIDType* oid, uint8_t* value, int data_len): ValueCallback(oid, OPAQUE), value(value), data_len(data_len) {};

  protected:
    uint8_t* const value;
    int const data_len;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

class OIDCallback: public ValueCallback {
  public:
    OIDCallback(SortableOIDType* oid, std::string value): ValueCallback(oid, ASN_TYPE::OID), value(value) {};

  protected:
    std::string const value;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
    SNMP_ERROR_STATUS setTypeWithValue (BER_CONTAINER*) override{
        return NO_ACCESS;
    };
};

class Counter32Callback: public ValueCallback {
  public:
    Counter32Callback(SortableOIDType* oid, uint32_t* value): ValueCallback(oid, COUNTER32), value(value) {};

  protected:
    uint32_t* const value;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

class Guage32Callback: public ValueCallback {
  public:
    Guage32Callback(SortableOIDType* oid, uint32_t* value): ValueCallback(oid, GUAGE32), value(value) {};

  protected:
    uint32_t* const value;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

class Counter64Callback: public ValueCallback {
  public:
    Counter64Callback(SortableOIDType* oid, uint64_t* value): ValueCallback(oid, COUNTER64), value(value) {};

  protected:
    uint64_t* const value;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

#endif