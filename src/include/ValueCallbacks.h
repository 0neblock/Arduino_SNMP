#ifndef VALUE_CALLBACKS_h
#define VALUE_CALLBACKS_h

#include "BER.h"
#include "SNMPDevice.h"
#include <deque>
#include <algorithm>
#include <utility>
#include "PollingInfo.h"

class ValueCallback;

class ValueCallbackContainer {
  public:
    explicit ValueCallbackContainer(ValueCallback* callback): valueCallback(callback){};
    explicit ValueCallbackContainer(SNMPDevice* ip, ValueCallback* callback): agentDevice(ip), valueCallback(callback) {};
    explicit ValueCallbackContainer(SNMPDevice* ip, ValueCallback* callback, std::shared_ptr<PollingInfo> pollingInfo): agentDevice(ip), pollingInfo(std::move(pollingInfo)), valueCallback(callback){};
    ValueCallbackContainer(const ValueCallbackContainer& other): agentDevice(other.agentDevice), pollingInfo(other.pollingInfo), valueCallback(other.valueCallback){};

    ValueCallback* operator -> () const {
        return this->valueCallback;
    }

    bool operator != (ValueCallback* other) const {
        return this->valueCallback != other;
    }

    bool operator == (ValueCallback* other) const {
        return !(operator!=(other));
    }

    explicit operator bool() const {
        return this->valueCallback != nullptr;
    }
    
    ValueCallbackContainer& operator=(ValueCallbackContainer&&) {
        return *this;
    };

    // Only used in manager contexts
    const SNMPDevice* const agentDevice = nullptr;
    const std::shared_ptr<PollingInfo> pollingInfo = nullptr;

  private:
    friend class ValueCallback;
    ValueCallback* const valueCallback = nullptr;
};

const ValueCallbackContainer NO_CALLBACK(nullptr);

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

    static const ValueCallbackContainer& findCallback(const std::deque<ValueCallbackContainer> &callbacks, const OIDType* const oid, bool walk, size_t startAt = 0, size_t *foundAt = nullptr, const SNMPDevice &device = NO_DEVICE);
    static std::shared_ptr<BER_CONTAINER> getValueForCallback(const ValueCallbackContainer& callback);
    static SNMP_ERROR_STATUS setValueForCallback(const ValueCallbackContainer& callback, const std::shared_ptr<BER_CONTAINER> &value,
                                                 bool isAgentContext);

    virtual std::shared_ptr<BER_CONTAINER> buildTypeWithValue() = 0;
protected:
    virtual SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) = 0;
};

void sort_handlers(std::deque<ValueCallbackContainer>&);
bool remove_handler(std::deque<ValueCallbackContainer>&, ValueCallback*);

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

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;

  protected:
    int* const value;

    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

class ReadOnlyStringCallback: public ValueCallback {
public:
    ReadOnlyStringCallback(SortableOIDType* oid, std::string value): ValueCallback(oid, STRING), value(std::move(value)) {};

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