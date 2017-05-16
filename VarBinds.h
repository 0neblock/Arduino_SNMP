#ifndef VarBinds_h
#define VarBinds_h

typedef struct VarBindStruct {
    ~VarBindStruct(){
//        if(value) delete value;
//        if(oid) delete oid;
    };
    OIDType* oid = 0;
    ASN_TYPE type;
    BER_CONTAINER* value = 0;
} VarBind;

typedef struct VarBindListStruct {
    ~VarBindListStruct(){
        delete next; next = 0;
        delete value; value = 0;
    };
    struct VarBindStruct* value = 0;
    struct VarBindListStruct* next = 0;
} VarBindList;

#endif