#ifndef VALUE_CALLBACKS_h
#define VALUE_CALLBACKS_h

#include "BER.h"
#include "PollingInfo.h"
#include "SNMPDevice.h"
#include <algorithm>
#include <deque>
#include <utility>

class ValueCallback;

class ValueCallbackContainer {
  public:
    explicit ValueCallbackContainer(ValueCallback *callback) : valueCallback(callback){};

    explicit ValueCallbackContainer(SNMPDevice *ip, ValueCallback *callback) : agentDevice(ip),
                                                                               valueCallback(callback){};

    explicit ValueCallbackContainer(SNMPDevice *ip, ValueCallback *callback, std::shared_ptr<PollingInfo> pollingInfo)
        : agentDevice(ip), pollingInfo(std::move(pollingInfo)), valueCallback(callback){};


    ValueCallback *operator->() const {
        return this->valueCallback;
    }

    bool operator!=(ValueCallback *other) const {
        return this->valueCallback != other;
    }

    bool operator==(ValueCallback *other) const {
        return !(operator!=(other));
    }

    explicit operator bool() const {
        return this->valueCallback != nullptr;
    }

    // Only used in manager contexts
    const SNMPDevice *agentDevice = nullptr;
    std::shared_ptr<PollingInfo> pollingInfo = nullptr;

  private:
    friend class ValueCallback;

    ValueCallback *valueCallback = nullptr;
};

const ValueCallbackContainer NO_CALLBACK(nullptr);

class ValueCallback {
  public:
    ValueCallback(SortableOIDType *oid, ASN_TYPE type) : OID(oid), type(type){};

    ~ValueCallback() {
        delete OID;
    }

    SortableOIDType *const OID;

    const ASN_TYPE type;

    bool isSettable = false;
    bool mutable setOccurred = false;

    void resetSetOccurred() const {
        setOccurred = false;
    }

    static const ValueCallbackContainer &
    findCallback(const std::deque<ValueCallbackContainer> &callbacks, const OIDType *const oid, bool walk,
                 size_t startAt = 0, size_t *foundAt = nullptr, const SNMPDevice &device = NO_DEVICE);

    static std::shared_ptr<BER_CONTAINER> getValueForCallback(const ValueCallbackContainer &callback);

    static SNMP_ERROR_STATUS
    setValueForCallback(const ValueCallbackContainer &callback, const std::shared_ptr<BER_CONTAINER> &value,
                        bool isAgentContext);

    virtual std::shared_ptr<BER_CONTAINER> buildTypeWithValue() const = 0;

  protected:
    virtual SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER *value) const = 0;
};

void sort_handlers(std::deque<ValueCallbackContainer> &);

bool remove_handler(std::deque<ValueCallbackContainer> &, ValueCallback *);

class IntegerCallback : public ValueCallback {
  public:
    IntegerCallback(SortableOIDType *oid, int *value) : ValueCallback(oid, INTEGER), value(value){};

  protected:
    int *const value;
    int modifier = 0;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() const override;

    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER *value) const override;
};

class TimestampCallback : public ValueCallback {
  public:
    TimestampCallback(SortableOIDType *oid, int *value) : ValueCallback(oid, TIMESTAMP), value(value){};

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() const override;

  protected:
    int *const value;

    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER *value) const override;
};

class ReadOnlyStringCallback : public ValueCallback {
  public:
    ReadOnlyStringCallback(SortableOIDType *oid, const std::string &value) : ValueCallback(oid, STRING),
                                                                             value(std::move(value)){};

  protected:
    const std::string value;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() const override;

    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER *) const override {
        return NO_ACCESS;
    };
};

class StringCallback : public ValueCallback {
  public:
    StringCallback(SortableOIDType *oid, char *const *const value, const int max_len) : ValueCallback(oid, STRING), value(value),
                                                                                        max_len(max_len){};

  protected:
    char *const *const value;
    const size_t max_len;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() const override;

    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER *value) const override;
};

class OpaqueCallback : public ValueCallback {
  public:
    OpaqueCallback(SortableOIDType *oid, uint8_t *value, const int data_len) : ValueCallback(oid, OPAQUE), value(value),
                                                                               data_len(data_len){};

  protected:
    uint8_t *const value;
    const int data_len;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() const override;

    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER *value) const override;
};

class OIDCallback : public ValueCallback {
  public:
    OIDCallback(SortableOIDType *oid, std::string value) : ValueCallback(oid, ASN_TYPE::OID), value(value){};

  protected:
    std::string const value;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() const override;

    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER *) const override {
        return NO_ACCESS;
    };
};

class Counter32Callback : public ValueCallback {
  public:
    Counter32Callback(SortableOIDType *oid, uint32_t *value) : ValueCallback(oid, COUNTER32), value(value){};

  protected:
    uint32_t *const value;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() const override;

    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER *value) const override;
};

class Guage32Callback : public ValueCallback {
  public:
    Guage32Callback(SortableOIDType *oid, uint32_t *value) : ValueCallback(oid, GUAGE32), value(value){};

  protected:
    uint32_t *const value;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() const override;

    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER *value) const override;
};

class Counter64Callback : public ValueCallback {
  public:
    Counter64Callback(SortableOIDType *oid, uint64_t *value) : ValueCallback(oid, COUNTER64), value(value){};

  protected:
    uint64_t *const value;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() const override;

    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER *value) const override;
};

#endif