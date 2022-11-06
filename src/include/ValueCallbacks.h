#ifndef VALUE_CALLBACKS_h
#define VALUE_CALLBACKS_h

#include "BER.h"
#include <deque>
#include <algorithm>

typedef int (*GETINT_FUNC)() ;
typedef uint32_t (*GETUINT_FUNC)();
typedef const std::string (*GETSTRING_FUNC)();

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

class StaticIntegerCallback: public ValueCallback {
  public:
    StaticIntegerCallback(SortableOIDType* oid, int value): ValueCallback(oid, INTEGER), val(value) {};

  protected:
    const int val;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override {
        return std::make_shared<IntegerType>(val);
    }

    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER*) override {
        return NO_ACCESS;
    }
};

class DynamicIntegerCallback: public ValueCallback {
public:
    DynamicIntegerCallback(SortableOIDType* oid, GETINT_FUNC callback_func):
        ValueCallback(oid, INTEGER), m_callback(callback_func) {};

protected:
    GETINT_FUNC m_callback;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override {
        return std::make_shared<IntegerType>(m_callback());
    }

    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER*) override {
        return NO_ACCESS;
    }
};

class TimestampCallback: public ValueCallback {
  public:
    TimestampCallback(SortableOIDType* oid, uint32_t* value): ValueCallback(oid, TIMESTAMP), value(value) {};

  protected:
    uint32_t* const value;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

class DynamicTimestampCallback: public ValueCallback {
public:
    DynamicTimestampCallback(SortableOIDType* oid, GETUINT_FUNC callback_func):
    ValueCallback(oid, TIMESTAMP), m_callback(callback_func) {};

protected:
    GETUINT_FUNC m_callback;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override {
        return std::make_shared<TimestampType>(m_callback());
    }

    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER*) override {
        return NO_ACCESS;
    }
};

class ReadOnlyStringCallback: public ValueCallback {
public:
    ReadOnlyStringCallback(SortableOIDType* oid, const std::string &value): ValueCallback(oid, STRING), value(value) {};

protected:
    std::string value;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER*) override {
        return NO_ACCESS;
    };
};

class DynamicStringCallback: public ValueCallback {
public:
    DynamicStringCallback(SortableOIDType* oid, GETSTRING_FUNC callback): ValueCallback(oid, STRING), m_callback(callback) {};

protected:
    GETSTRING_FUNC m_callback;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override {
      return std::make_shared<OctetType>(m_callback());
    }
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER*) override {
        return NO_ACCESS;
    };
};

class StringCallback: public ValueCallback {
  public:
    StringCallback(SortableOIDType* oid, char** value, size_t max_len): ValueCallback(oid, STRING), value(value), max_len(max_len) {};

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
    OIDCallback(SortableOIDType* oid, const std::string &value): ValueCallback(oid, ASN_TYPE::OID), value(value) {};

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


class Gauge32Callback: public ValueCallback {
  public:
    Gauge32Callback(SortableOIDType* oid, uint32_t* value): ValueCallback(oid, GAUGE32), value(value) {};

  protected:
    uint32_t* const value;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

class DynamicGauge32Callback: public ValueCallback {
  public:
    DynamicGauge32Callback(SortableOIDType* oid, GETUINT_FUNC callback_func): ValueCallback(oid, GAUGE32), m_callback(callback_func) {};

  protected:
    GETUINT_FUNC m_callback;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override {
        return std::make_shared<Gauge>(m_callback());
    }
    SNMP_ERROR_STATUS setTypeWithValue (BER_CONTAINER*) override{
        return NO_ACCESS;
    };
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
