/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rules.h"
#include "decoders/decoder.h"
#include "eventinfo.h"
#include "../config/logtest-config.h"
#include "../os_net/os_net.h"
#include "../os_crypto/md5/md5_op.h"

/* JSON REQUEST fields inputs names */
#define JSON_INPUT_TOKEN         "token"       //< Token field name of json input
#define JSON_INPUT_EVENT         "event"       //< Event field name of json input
#define JSON_INPUT_LOGFORMAT     "log_format"  //< Log format field name of json input
#define JSON_INPUT_LOCATION      "location"    //< Location field name of json input

/* JSON RESPONSE fields output names */
#define JSON_OUTPUT_TOKEN          "token"      //< Token field name of json output
#define JSON_OUTPUT_ALERT          "alert"      //< Alert field name of json output (true/false)
#define JSON_OUTPUT_MESSAGE      "message"      //< Message format field name of json output
#define JSON_OUTPUT_CODE         "codemsg"      //< Code of message field name of json output (int)
#define JSON_OUTPUT_OUTPUT        "output"      //< Output field name of json output


#define TOKEN_LENGH              32            //< Lenght of token (MD5 size, 32 characters)

/* Error messages */

/**/

/**
 * @brief A w_logtest_session_t instance represents a client
 */
typedef struct w_logtest_session_t {

    char* token;                              ///< Client ID
    time_t last_connection;                 ///< Timestamp of the last query

    RuleNode *rule_list;                    ///< Rule list
    OSDecoderNode *decoderlist_forpname;    ///< Decoder list to match logs which have a program name
    OSDecoderNode *decoderlist_nopname;     ///< Decoder list to match logs which haven't a program name
    ListNode *cdblistnode;                  ///< List of CDB lists
    ListRule *cdblistrule;                  ///< List to attach rules and CDB lists
    EventList *eventlist;                   ///< Previous events list
    OSHash *g_rules_hash;                   ///< Hash table of rules
    OSList *fts_list;                       ///< Save FTS previous events
    OSHash *fts_store;                      ///< Save FTS values processed
    OSHash *acm_store;                      ///< Hash to save data which have the same id
    int acm_lookups;                        ///< Counter of the number of times purged. Option accumulate
    time_t acm_purge_ts;                    ///< Counter of the time interval of last purge. Option accumulate

} w_logtest_session_t;

/**
 * @brief List of client actives
 */
OSHash *w_logtest_sessions;

/**
 * @brief An instance of w_logtest_connection allow managing the connections with the logtest socket
 */
typedef struct w_logtest_connection {

    pthread_mutex_t mutex;      ///< Mutex to prevent race condition in accept syscall
    int sock;                   ///< The open connection with logtest queue

} w_logtest_connection;


/**
 * @brief A w_logtest_request instance represents a client requeset
 * @TODO FREE STRUCT
 */
typedef struct w_logtest_request {

    char* token;             ///< Client ID (MD5 value)
    char* event;             ///< Log to be processed
    char* log_format;        ///< Type of log. Syslog, syscheck_event, eventchannel, eventlog, etc
    char* location;          ///< The origin of the log. User, agent, IP and file (if collected by Logcollector).

} w_logtest_request;

/**
 * @brief Initialize Wazuh Logtest. Initialize the listener and create threads
 * Then, call function w_logtest_main
 */
void *w_logtest_init();

/**
 * @brief Initialize logtest configuration. Then, call ReadConfig
 *
 * @return OS_SUCCESS on success, otherwise OS_INVALID
 */
int w_logtest_init_parameters();

/**
 * @brief Main function of Wazuh Logtest module
 *
 * Listen and treat connections with clients
 *
 * @param connection The listener where clients connect
 */
void *w_logtest_main(w_logtest_connection * connection);

/**
 * @brief Create resources necessary to service client
 * @param fd File descriptor which represents the client
 */
w_logtest_session_t *w_logtest_initialize_session(const char * token, char ** msg_error);

/**
 * @brief Process client's request
 * @param fd File descriptor which represents the client
 */
void w_logtest_process_log(char* token);

/**
 * @brief Free resources after client closes connection
 * @param fd File descriptor which represents the client
 */
void w_logtest_remove_session(char* token);

/**
 * @brief Check the active log-test sessions
 *
 * Check all sessions. If a session is created and the client has been offline
 * for more than 15 minutes, remove it.
 */
void w_logtest_check_active_sessions();

/**
 * @brief Initialize FTS engine for a client session
 * @param fts_list list which save fts previous events
 * @param fts_store hash table which save fts values processed previously
 * @return 1 on success, otherwise return 0
 */
int w_logtest_fts_init(OSList **fts_list, OSHash **fts_store);
