#ifndef SNMP_DEFS_h
#define SNMP_DEFS_h

typedef enum SNMP_ERROR_RESPONSE {
    SNMP_NO_UDP = -10,
    SNMP_REQUEST_TOO_LARGE = -5,
    SNMP_REQUEST_INVALID = -4,
    SNMP_REQUEST_INVALID_COMMUNITY = -3,
    SNMP_FAILED_SERIALISATION = -2,
    SNMP_GENERIC_ERROR = -1,
    SNMP_NO_PACKET = 0,
    SNMP_NO_ERROR = 1,
    SNMP_GET_OCCURRED = 2,
    SNMP_GETNEXT_OCCURRED = 3,
    SNMP_GETBULK_OCCURRED = 4,
    SNMP_SET_OCCURRED = 5,
    SNMP_ERROR_PACKET_SENT = 6, // A packet indicating that an error occurred was sent
    SNMP_INFORM_RESPONSE_OCCURRED = 7,
    SNMP_UNKNOWN_PDU_OCCURRED = 8
} SNMP_ERROR_RESPONSE;

typedef unsigned long snmp_request_id_t;

#define INVALID_SNMP_REQUEST_ID 0


typedef enum SnmpVersionEnum {
    SNMP_VERSION_1,
    SNMP_VERSION_2C,
    SNMP_VERSION_MAX
} SNMP_VERSION;

typedef enum {
     SNMP_PERM_NONE,
     SNMP_PERM_READ_ONLY,
     SNMP_PERM_READ_WRITE
} SNMP_PERMISSION;

extern const char* SNMP_TAG;

#define MAX_SNMP_PACKET_LENGTH 1400
#define OCTET_TYPE_MAX_LENGTH 500

#define SNMP_ERROR_OK 1

#define SNMP_PACKET_PARSE_ERROR_OFFSET -20
#define SNMP_BUFFER_PARSE_ERROR_OFFSET -10
#define SNMP_BUFFER_ENCODE_ERROR_OFFSET -30

typedef enum ERROR_STATUS_WITH_VALUE {
    // V1 Errors
    NO_ERROR = 0,
    TOO_BIG = 1,
    NO_SUCH_NAME = 2,
    BAD_VALUE = 3,
    READ_ONLY = 4,
    GEN_ERR = 5,
        
    // V2c Errors
    NO_ACCESS = 6,
    WRONG_TYPE = 7,
    WRONG_LENGTH = 8,
    WRONG_ENCODING = 9,
    WRONG_VALUE = 10,
    NO_CREATION = 11,
    INCONSISTENT_VALUE = 12,
    RESOURCE_UNAVAILABLE = 13,
    COMMIT_FAILED = 14,
    UNDO_FAILED = 15,
    AUTHORIZATION_ERROR = 16,
    NOT_WRITABLE = 17,
    INCONSISTENT_NAME = 18
} SNMP_ERROR_STATUS;

#define SNMP_V1_MAX_ERROR GEN_ERR

#define SNMP_ERROR_VERSION_CTRL(error, version) ((version == SNMP_VERSION_1 && error > SNMP_V1_MAX_ERROR) ? SNMP_V1_MAX_ERROR : error)

// Used for situations where in V2 an error exists but in V1 a less-specific error exists that isn't GEN_ERR
#define SNMP_ERROR_VERSION_CTRL_DEF(error, version, elseError) ((version == SNMP_VERSION_1 && error > SNMP_V1_MAX_ERROR) ? SNMP_ERROR_VERSION_CTRL(elseError, version) : error)

// FC1213 OIDs
#define RFC1213_OID_sysDescr            (char*)(".1.3.6.1.2.1.1.1.0")
#define RFC1213_OID_sysObjectID         (char*)(".1.3.6.1.2.1.1.2.0")
#define RFC1213_OID_sysUpTime           (char*)(".1.3.6.1.2.1.1.3.0")
#define RFC1213_OID_sysContact          (char*)(".1.3.6.1.2.1.1.4.0")
#define RFC1213_OID_sysName             (char*)(".1.3.6.1.2.1.1.5.0")
#define RFC1213_OID_sysLocation         (char*)(".1.3.6.1.2.1.1.6.0")
#define RFC1213_OID_sysServices         (char*)(".1.3.6.1.2.1.1.7.0")

typedef struct RFC1213SystemStruct
{
char*           sysDescr;               /* .1.3.6.1.2.1.1.1.0 */
char*           sysObjectID;            /* .1.3.6.1.2.1.1.2.0 */
uint32_t        sysUpTime;              /* .1.3.6.1.2.1.1.3.0 */
char*           sysContact;             /* .1.3.6.1.2.1.1.4.0 */
char*           sysName;                /* .1.3.6.1.2.1.1.5.0 */
char*           sysLocation;            /* .1.3.6.1.2.1.1.6.0 */
int32_t         sysServices;            /* .1.3.6.1.2.1.1.7.0 */
} RFC1213_list;

// DEBUG
#ifndef COMPILING_TESTS
    #include <esp_log.h>
    
    #define SNMP_LOGD(...) ESP_LOGD(SNMP_TAG, __VA_ARGS__)
    #define SNMP_LOGI(...) ESP_LOGI(SNMP_TAG, __VA_ARGS__)
    #define SNMP_LOGW(...) ESP_LOGW(SNMP_TAG, __VA_ARGS__)
    #define SNMP_LOGE(...) ESP_LOGE(SNMP_TAG, __VA_ARGS__)
    
#else
    #if (DEBUG ==1)
        #define SNMP_LOGD(...) printf(__VA_ARGS__)
        #define SNMP_LOGI(...) printf(__VA_ARGS__)
        #define SNMP_LOGW(...) printf(__VA_ARGS__)
        #define SNMP_LOGE(...) printf(__VA_ARGS__)
        
    #if (DEBUG ==2)
        #define SNMP_LOGD(...)
        #define SNMP_LOGI(...) printf(__VA_ARGS__)
        #define SNMP_LOGW(...) printf(__VA_ARGS__)
        #define SNMP_LOGE(...) printf(__VA_ARGS__)
        
    #else
        #define SNMP_LOGD(...)
        #define SNMP_LOGI(...)
        #define SNMP_LOGW(...)
        #define SNMP_LOGE(...)
        
    #endif
#endif

#endif
