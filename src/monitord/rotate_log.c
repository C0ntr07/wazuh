/* Copyright (C) 2015-2019, Wazuh Inc.
 * June 12, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "monitord.h"

#ifdef WIN32
#define mkdir(x, y) _mkdir(x)
#define unlink(x) _unlink(x)
#define localtime_r(x, y) localtime_s(y, x)
#endif

static const char * MONTHS[] = {
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec"
};

char *w_rotate_log(char *old_file, int compress, int maxage, int new_day, int rotate_json, int daily_rotations, int last_counter) {
    char year_dir[PATH_MAX];
    char month_dir[PATH_MAX];
    char new_path[PATH_MAX];
    char *dir = NULL;
    char new_path_json[PATH_MAX];
    char compressed_path[PATH_MAX];
    char tag[OS_FLSIZE];
    struct tm tm;
    time_t now;
    int counter = 0;

    if (new_day)
        minfo("Running daily rotation of log files.");
    else {
        if (rotate_json)
            minfo("Rotating 'ossec.json' file.");
        else
            minfo("Rotating 'ossec.log' file.");
    }


    now = time(NULL);

    if (new_day)
        now = now - (3600*24);

    localtime_r(&now, &tm);

#ifdef WIN32
    char base_dir[PATH_MAX];
    char log_dir[PATH_MAX];

    // ossec.log
    snprintf(new_path, PATH_MAX, "%s", LOGFILE);
    // ossec.json
    snprintf(new_path_json, PATH_MAX, "%s", LOGJSONFILE);
    // logs
    strcpy(base_dir, "logs");
    strcpy(log_dir, base_dir);
    snprintf(tag, OS_FLSIZE, "logs");
#else
    char *base_dir;
    char log_dir[PATH_MAX] = "\0";
    os_strdup(old_file, dir);
    base_dir = dirname(dir);
    if(!strncmp(old_file, LOGFILE, strlen(LOGFILE)) || !strncmp(old_file, LOGJSONFILE, strlen(LOGJSONFILE))){
        snprintf(tag, OS_FLSIZE, "logs");
        snprintf(log_dir, PATH_MAX, "%s/ossec", base_dir);
    } else if(!strncmp(old_file, ALERTS_DAILY, strlen(ALERTS_DAILY)) || !strncmp(old_file, ALERTSJSON_DAILY, strlen(ALERTSJSON_DAILY))){
        snprintf(tag, OS_FLSIZE, "alerts");
    } else if(!strncmp(old_file, EVENTS_DAILY, strlen(EVENTS_DAILY)) || !strncmp(old_file, EVENTSJSON_DAILY, strlen(EVENTSJSON_DAILY))){
        snprintf(tag, OS_FLSIZE, "archive");
    }

#endif
    if(!strncmp(base_dir, "/logs", strlen(base_dir))){
        snprintf(year_dir, PATH_MAX, "%s/ossec/%d", base_dir, tm.tm_year + 1900);
    } else {
        snprintf(year_dir, PATH_MAX, "%s/%d", base_dir, tm.tm_year + 1900);
    }
    snprintf(month_dir, PATH_MAX, "%s/%s", year_dir, MONTHS[tm.tm_mon]);
    snprintf(new_path, PATH_MAX, "%s/ossec-%s-%02d.log", month_dir, tag, tm.tm_mday);
    snprintf(new_path_json, PATH_MAX, "%s/ossec-%s-%02d.json", month_dir, tag, tm.tm_mday);

    snprintf(compressed_path, PATH_MAX, "%s.gz", new_path);


     // Create folders

    if (IsDir(year_dir) < 0 && mkdir(year_dir, 0770) < 0) {
        os_free(dir);
        merror_exit(MKDIR_ERROR, year_dir, errno, strerror(errno));
    }

    if (IsDir(month_dir) < 0 && mkdir(month_dir, 0770) < 0) {
        os_free(dir);
        merror_exit(MKDIR_ERROR, month_dir, errno, strerror(errno));
    }


    if (!rotate_json) {

        /* If we have a previous log of the same day, create the next one. */
        if(last_counter != -1) {
            counter = last_counter + 1;
            snprintf(new_path, PATH_MAX, "%s/ossec-%s-%02d-%03d.log", month_dir, tag, tm.tm_mday, counter);
            snprintf(compressed_path, PATH_MAX, "%s.gz", new_path);
        }

        /* Rotate compressed logs if needed */
        if (counter == daily_rotations) {
            mdebug2("The internal_option 'daily_rotations' has been deprecated. It's being ignored in the log rotation.");
        }

        if (!IsFile(old_file)) {
            if (rename_ex(old_file, new_path) == 0) {
                if (compress) {
                    OS_CompressLog(new_path);
                }
            } else {
                merror("Couldn't rename '%s' to '%s': %s", old_file, new_path, strerror(errno));
            }
        }

    }

    else {

        snprintf(compressed_path, PATH_MAX, "%s.gz", new_path_json);

       /* If we have a previous log of the same day, create the next one. */
        if(last_counter != -1) {
            counter = last_counter + 1;
            snprintf(new_path_json, PATH_MAX, "%s/ossec-%s-%02d-%03d.json", month_dir, tag, tm.tm_mday, counter);
            snprintf(compressed_path, PATH_MAX, "%s.gz", new_path);
        }

        /* Rotate compressed logs if needed */
        if (counter == daily_rotations) {
            mdebug2("The internal_option 'daily_rotations' has been deprecated. It's being ignored in the log rotation.");
        }

        if (!IsFile(old_file)) {
            if (rename_ex(old_file, new_path_json) == 0) {
                if (compress) {
                    OS_CompressLog(new_path_json);
                }
            } else {
                merror("Couldn't rename '%s' to '%s': %s", old_file, new_path_json, strerror(errno));
            }
        }
    }

    minfo("Starting new log after rotation.");
    // Remove old compressed files
    remove_old_logs(log_dir, maxage, "logs");
    os_free(dir);
    if(rotate_json)
        return strdup(new_path_json);
    else
        return strdup(new_path);
}