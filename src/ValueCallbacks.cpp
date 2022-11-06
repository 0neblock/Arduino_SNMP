#include "include/ValueCallbacks.h"
#include "include/BER.h"

#include <algorithm>

#define ASSERT_VALID_VALUE(value) if(!value) return nullptr;

#define SETTING_NON_SETTABLE_ERROR READ_ONLY
// If the value to be set is invalid
#define ASSERT_VALID_SETTABLE_VALUE(value) if(!value) return GEN_ERR;
#define ASSERT_VALID_SETTING_VALUE(value) if(!value) return WRONG_VALUE;

// If we ever remove the setting pre-check, use this
// #define ASSERT_CALLBACK_SETTABLE if(!(static_cast<ValueCallback*>(this)->isSettable)) return SETTING_NON_SETTABLE_ERROR;
#define ASSERT_CALLBACK_SETTABLE()

ValueCallback* ValueCallback::findCallback(std::deque<ValueCallback*> &callbacks, const OIDType* const oid, bool walk, size_t startAt, size_t *foundAt){
    bool useNext = false;

    for(size_t i = startAt; i < callbacks.size(); i++){
        auto callback = callbacks[i];

        if(useNext){
            if(foundAt){
                *foundAt = i;
            }
            return callback;
        }

        if(oid->equals(callback->OID)){
            if(walk){
                useNext = true;
                continue;
            }
            if(foundAt){
                *foundAt = i;
            }
            return callback;
        }

        if(walk && callback->OID->isSubTreeOf(oid)){
            // If the oid passed in is a substring of our current callback, and it begins at the start
            if(foundAt){
                *foundAt = i;
            }
            return callback;
        }
    }
    return nullptr;
}

std::shared_ptr<BER_CONTAINER> ValueCallback::getValueForCallback(ValueCallback* callback){
    SNMP_LOGD("Getting value for callback of OID: %s, type: %d\n", callback->OID->string().c_str(), callback->type);
    auto value = callback->buildTypeWithValue();
    return value;
}

SNMP_ERROR_STATUS ValueCallback::setValueForCallback(ValueCallback* callback, const std::shared_ptr<BER_CONTAINER> &value){
    SNMP_LOGD("Setting value for callback of OID: %s\n", callback->OID->string().c_str());

    if(!callback->isSettable){
        return SETTING_NON_SETTABLE_ERROR;
    }

    SNMP_ERROR_STATUS valid = callback->setTypeWithValue(value.get());

    if(valid == NO_ERROR){
        callback->setOccurred = true;
    }

    return valid;
}

std::shared_ptr<BER_CONTAINER> IntegerCallback::buildTypeWithValue(){
    ASSERT_VALID_VALUE(this->value);

    auto val = std::make_shared<IntegerType>(*this->value);
    if(this->modifier != 0){
        // Apple local division if callback was asked to
        val->_value /= this->modifier;
    }
    return val;
}

SNMP_ERROR_STATUS IntegerCallback::setTypeWithValue(BER_CONTAINER* rawValue){
    ASSERT_CALLBACK_SETTABLE();
    ASSERT_VALID_SETTABLE_VALUE(this->value);

    IntegerType* val = static_cast<IntegerType*>(rawValue);
    if(this->modifier){
        // Apple local division if callback was asked to
        // val->_value /= this->modifier;
    }
    *this->value = val->_value;

    return NO_ERROR;
}

std::shared_ptr<BER_CONTAINER> TimestampCallback::buildTypeWithValue(){
    ASSERT_VALID_VALUE(this->value);

    return std::make_shared<TimestampType>(*this->value);
}

SNMP_ERROR_STATUS TimestampCallback::setTypeWithValue(BER_CONTAINER* rawValue){
    ASSERT_CALLBACK_SETTABLE();
    ASSERT_VALID_SETTABLE_VALUE(this->value);

    TimestampType* val = static_cast<TimestampType*>(rawValue);
    *this->value = val->_value;

    return NO_ERROR;
}

std::shared_ptr<BER_CONTAINER> StringCallback::buildTypeWithValue(){
    ASSERT_VALID_VALUE(this->value);

    return std::make_shared<OctetType>(*this->value);
}

SNMP_ERROR_STATUS StringCallback::setTypeWithValue(BER_CONTAINER* rawValue){
    ASSERT_CALLBACK_SETTABLE();
    ASSERT_VALID_SETTABLE_VALUE(this->value);

    OctetType* val = static_cast<OctetType*>(rawValue);
    if(val->_value.length() >= this->max_len) return WRONG_LENGTH;
    strncpy(*this->value, val->_value.data(), this->max_len);

    return NO_ERROR;
}

std::shared_ptr<BER_CONTAINER> ReadOnlyStringCallback::buildTypeWithValue(){
    return std::make_shared<OctetType>(this->value);
}


std::shared_ptr<BER_CONTAINER> OpaqueCallback::buildTypeWithValue(){
    ASSERT_VALID_VALUE(this->value);

    return std::make_shared<OpaqueType>(this->value, this->data_len);
}

SNMP_ERROR_STATUS OpaqueCallback::setTypeWithValue(BER_CONTAINER* rawValue){
    ASSERT_CALLBACK_SETTABLE();
    ASSERT_VALID_SETTABLE_VALUE(this->value);

    OpaqueType* val = static_cast<OpaqueType*>(rawValue);
    ASSERT_VALID_SETTING_VALUE(val->_value);
    if(val->_dataLength > this->data_len) return WRONG_LENGTH;
    memcpy(this->value, val->_value, this->data_len);

    return NO_ERROR;
}

std::shared_ptr<BER_CONTAINER> OIDCallback::buildTypeWithValue(){
    auto oid = std::make_shared<OIDType>(this->value);
    if(!oid->valid) return nullptr;
    return oid;
}

std::shared_ptr<BER_CONTAINER> Counter32Callback::buildTypeWithValue(){
    ASSERT_VALID_VALUE(this->value);

    return std::make_shared<Counter32>(*this->value);
}

SNMP_ERROR_STATUS Counter32Callback::setTypeWithValue(BER_CONTAINER* rawValue){
    ASSERT_CALLBACK_SETTABLE();
    ASSERT_VALID_SETTABLE_VALUE(this->value);

    Counter32* val = static_cast<Counter32*>(rawValue);
    *this->value = val->_value;
    return NO_ERROR;
}

std::shared_ptr<BER_CONTAINER> Gauge32Callback::buildTypeWithValue(){
    ASSERT_VALID_VALUE(this->value);

    return std::make_shared<Gauge>(*this->value);
}

SNMP_ERROR_STATUS Gauge32Callback::setTypeWithValue(BER_CONTAINER* rawValue){
    ASSERT_CALLBACK_SETTABLE();
    ASSERT_VALID_SETTABLE_VALUE(this->value);

    Gauge* val = static_cast<Gauge*>(rawValue);
    *this->value = val->_value;

    return NO_ERROR;
}

std::shared_ptr<BER_CONTAINER> Counter64Callback::buildTypeWithValue(){
    ASSERT_VALID_VALUE(this->value);

    return std::make_shared<Counter64>(*this->value);
}

SNMP_ERROR_STATUS Counter64Callback::setTypeWithValue(BER_CONTAINER* rawValue){
    ASSERT_CALLBACK_SETTABLE();
    ASSERT_VALID_SETTABLE_VALUE(this->value);

    Counter64* val = static_cast<Counter64*>(rawValue);
    *this->value = val->_value;

    return NO_ERROR;
}

bool SortableOIDType::sort_oids(SortableOIDType* oid1, SortableOIDType* oid2){ // returns true if oid1 EARLIER than oid2
    const auto& map1 = oid1->sortingMap;
    const auto& map2 = oid2->sortingMap;

    if(map1.empty()) return false;
    if(map2.empty()) return true;

    int i;

    if(map1.size() < map2.size()){
        i = map1.size();
    } else {
        i = map2.size();
    }

    for(int j = 0; j < i; j++){
        if(map1[j] != map2[j]){ // if they're the same then we're on same level
            return map1[j] < map2[j];
        }
    }

    return map1.size() < map2.size();
}

bool compare_callbacks (const ValueCallback* first, const ValueCallback* second){
    return SortableOIDType::sort_oids(first->OID, second->OID);
}

void sort_handlers(std::deque<ValueCallback*>& callbacks){
    std::sort(callbacks.begin(), callbacks.end(), compare_callbacks);
}

bool remove_handler(std::deque<ValueCallback*>& callbacks, ValueCallback* callback){
    int i = 0;
    int found = -1;
    for(auto cb : callbacks){
        if(cb == callback){
            found = i;
            break;
        }
        i++;
    }

    if(found > -1){
        auto it = callbacks.begin();
        std::advance(it, found);
        callbacks.erase(it);
        return true;
    } else {
        return false;
    }
}