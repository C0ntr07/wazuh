/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "logtest.h"

/**
 * @brief Check if input_json its valid and generate a client requeset
 * 
 * If the entry is valid and the token field is empty or invalid, a new token is generated, then 1 its returns.
 * @param[out] req Client request information.
 * @param[in]  input_json Raw JSON input of requeset.
 * @param[out] msg_error  Store warnings and error as result of call
 * @return int 1 Success, but with message.
 *             0 Normal success. 
 *            -1 Critical error (Parcing errors, invalid fields), *w_logtest_request internal memory was released
 * @note If *msg==null, memory are allocate, otherwise memory are reallocate and the original content is lost.
 * @warning w_logtest_request internal pointers should not point to allocated memory (Memory leak \ref w_logtest_free_request)
 */
static int w_logtest_check_input(char* input_json, w_logtest_request* req, char ** msg_error);

/**
 * @brief Frer internal memory of a request
 * 
 * @param req request to release
 */
static void w_logtest_free_request (w_logtest_request* req);

void *w_logtest_init() {

    w_logtest_connection connection;

    if (w_logtest_init_parameters() == OS_INVALID) {
        merror(LOGTEST_ERROR_INV_CONF);
        return NULL;
    }

    if (!w_logtest_conf.enabled) {
        minfo(LOGTEST_DISABLED);
        return NULL;
    }

    if (connection.sock = OS_BindUnixDomain(LOGTEST_SOCK, SOCK_STREAM, OS_MAXSTR), connection.sock < 0) {
        merror(LOGTEST_ERROR_BIND_SOCK, LOGTEST_SOCK, errno, strerror(errno));
        return NULL;
    }

    if (w_logtest_sessions = OSHash_Create(), !w_logtest_sessions) {
        merror(LOGTEST_ERROR_INIT_HASH);
        return NULL;
    }

    w_mutex_init(&connection.mutex, NULL);

    minfo(LOGTEST_INITIALIZED);

    for (int i = 1; i < w_logtest_conf.threads; i++) {
        w_create_thread(w_logtest_main, &connection);
    }

    w_logtest_main(&connection);

    close(connection.sock);
    if (unlink(LOGTEST_SOCK)) {
        merror(DELETE_ERROR, LOGTEST_SOCK, errno, strerror(errno));
    }

    w_mutex_destroy(&connection.mutex);

    return NULL;
}


int w_logtest_init_parameters() {

    int modules = CLOGTEST;

    w_logtest_conf.enabled = true;
    w_logtest_conf.threads = LOGTEST_THREAD;
    w_logtest_conf.max_sessions = LOGTEST_MAX_SESSIONS;
    w_logtest_conf.session_timeout = LOGTEST_SESSION_TIMEOUT;

    if (ReadConfig(modules, OSSECCONF, NULL, NULL) < 0) {
        return OS_INVALID;
    }

    return OS_SUCCESS;
}

// non return attribute ?
void *w_logtest_main(w_logtest_connection *connection) {

    int client;
    char msg_received[OS_MAXSTR];
    int size_msg_received;

    char* error_msg;

    /* input-ouput */
    w_logtest_request req = {0};
    cJSON* json_response;
    char* str_response;

    while(1) {
        json_response = cJSON_CreateObject();
        error_msg = NULL;

        /* Wait for client */
        w_mutex_lock(&connection->mutex);

        if (client = accept(connection->sock, (struct sockaddr *)NULL, NULL), client < 0) {
            merror(LOGTEST_ERROR_ACCEPT_CONN, strerror(errno));
            continue;
        }

        w_mutex_unlock(&connection->mutex);

        if (size_msg_received = recv(client, msg_received, OS_MAXSTR - 1, 0), size_msg_received < 0) {
            merror(LOGTEST_ERROR_RECV_MSG, strerror(errno));
            close(client);
            continue;
        }
        msg_received[size_msg_received] = '\0';

        /* Check msg and generate a request */
        if (w_logtest_check_input(msg_received, &req, &error_msg) == -1) {
            cJSON_AddStringToObject(json_response, JSON_OUTPUT_CODE,    "-1");
            cJSON_AddStringToObject(json_response, JSON_OUTPUT_MESSAGE, error_msg);
            goto response;
        }

        /* LOOPBACK RESPONSE (TEMPORARY - TEST PURPOSE) */

        /* Why this is it not covered in the rest of the code? */
        if (cJSON_AddStringToObject(json_response, JSON_OUTPUT_TOKEN, req.token) == NULL) {
            merror("(0000) %s error creating json response", JSON_OUTPUT_TOKEN);
            goto cleanup;
        }

        if (cJSON_AddStringToObject(json_response, JSON_INPUT_EVENT, req.event) == NULL) {
            merror("(0000) %s error creating json response", JSON_INPUT_EVENT);
            goto cleanup;
        }

        if (cJSON_AddStringToObject(json_response, JSON_INPUT_LOCATION, req.location) == NULL) {
            merror("(0000) %s error creating json response", JSON_INPUT_LOCATION);
            goto cleanup;
        }

        if (cJSON_AddStringToObject(json_response, JSON_INPUT_LOGFORMAT, req.log_format) == NULL) {
            merror("(0000) %s error creating json response", JSON_INPUT_LOGFORMAT);
            goto cleanup;
        }
  
response:
        // cJSON_PrintUnformatted for non pretty format
        str_response = cJSON_Print(json_response);

        if (send(client, str_response, strlen(str_response) + 1, 0) == -1) {
             merror("(0000) Error seding response: [%i] %s ", errno, strerror(errno));
             // msg to debug request?
        }
cleanup:
        
        w_logtest_free_request(&req);
        os_free(error_msg);
        os_free(str_response);
        cJSON_Delete(json_response);

        close(client);
    }

    return NULL;
}


w_logtest_session_t *w_logtest_initialize_session(const char * token, char ** msg_error) {

    return NULL;

}


void w_logtest_process_log(char* token) {

}


void w_logtest_remove_session(char* token) {

}


void w_logtest_check_active_sessions() {

}


int w_logtest_fts_init(OSList **fts_list, OSHash **fts_store) {

    int list_size = getDefine_Int("analysisd", "fts_list_size", 12, 512);

    if (*fts_list = OSList_Create(), *fts_list == NULL) {
        merror(LIST_ERROR);
        return 0;
    }

    if (!OSList_SetMaxSize(*fts_list, list_size)) {
        merror(LIST_SIZE_ERROR);
        return 0;
    }

    if (*fts_store = OSHash_Create(), *fts_store == NULL) {
        merror(HASH_ERROR);
        return 0;
    }
    if (!OSHash_setSize(*fts_store, 2048)) {
        merror(LIST_SIZE_ERROR);
        return 0;
    }

    return 1;
}

static int w_logtest_check_input(char* input_json, w_logtest_request* req, char ** msg_error) {

    int ret = -1; // -1 means critical error
    char* output_msg = NULL;
    
    /* Parse raw JSON input */
    cJSON* root;
    cJSON* location;
    cJSON* log_format;
    cJSON* event;
    cJSON* token;
    const char *jsonErrPtr;
    
    // @TODO Create a check for valid other field, such as location empty?

    // print must be smerror(msg_error, ...)
    root = cJSON_ParseWithOpts(input_json, &jsonErrPtr, 0);
    if (!root)
    {
        printf("(0000) Error parsing JSON input.\n");
        printf("(0000) Error in position %i, ... %.20s ...\n", (int)(jsonErrPtr - input_json),
               (char *)(jsonErrPtr - 10 < input_json ? input_json : jsonErrPtr - 10));
        // Its so ugly -----------------------------^
        goto cleanup;
    }

    /* Check JSON fields */
    location = cJSON_GetObjectItemCaseSensitive(root, JSON_INPUT_LOCATION);
    if (!(cJSON_IsString(location) && (location->valuestring != NULL)))
    {
        printf("(0000)\"%s\" JSON field is required and must be a string\n", JSON_INPUT_LOCATION);
        goto cleanup;
    }
    

    log_format = cJSON_GetObjectItemCaseSensitive(root, JSON_INPUT_LOGFORMAT);
    if (!(cJSON_IsString(log_format) && (log_format->valuestring != NULL)))
    {
        printf("(0000)\"%s\" JSON field is required and must be a string\n", JSON_INPUT_LOGFORMAT);
        goto cleanup;
    }

    event = cJSON_GetObjectItemCaseSensitive(root, JSON_INPUT_EVENT);
    if (!(cJSON_IsString(event) && (event->valuestring != NULL)))
    {
        printf("(0000) \"%s\" field is required and must be a string\n", JSON_INPUT_EVENT);
        goto cleanup;
    }

    /* special treatment for token */
    token = cJSON_GetObjectItemCaseSensitive(root, JSON_INPUT_TOKEN);
    
    // Invalid token
    if (cJSON_IsString(token) && (token->valuestring != NULL)) {
        os_malloc(TOKEN_LENGH + 1, req->token);
        struct timeval now;
        gettimeofday(&now, NULL);
        const char* md5_seed = (char*) &now;

        if (strlen(token->valuestring) != TOKEN_LENGH) {
            printf("(0000) \"%s\" It is not a valid token\n", token->valuestring);
        }
        
        printf("(0000) A new token will be generated: %s\n", token->valuestring);
        
        // Time-based MD5 session token
        OS_MD5_Str(md5_seed, sizeof(struct timeval), req->token);
    } 
    // Valid Token 
    else {
        os_strdup(token->valuestring, req->token);
    }

    os_strdup(location->valuestring, req->location);
    os_strdup(log_format->valuestring, req->log_format);
    os_strdup(event->valuestring, req->event);

    ret = 0;
    
cleanup:
    if (output_msg) {
        os_free(*msg_error);
        *msg_error = output_msg;
        // Is not an error but there is a msg
        ret = (ret == 0) ? 1 : 0;
    }
    cJSON_Delete(root);
    return ret;
}

static void w_logtest_free_request (w_logtest_request* req){
    
    os_free(req->event);
    os_free(req->token);
    os_free(req->location);
    os_free(req->log_format);

}
