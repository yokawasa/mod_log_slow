/*
 * mod_log_slow.c - Logging Slow Request Module for Apache2.X
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright 2008 Yoichi Kawasaki <yokawasa@gmail.com>
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"      // ap_log_rerror
#include "ap_config.h"
#include <sys/time.h>
#include <sys/resource.h>

#define MAX_LOG_SLOW_REQUEST 1000*30  //30sec
#define MIN_LOG_SLOW_REQUEST 0

module AP_MODULE_DECLARE_DATA log_slow_module;

typedef struct st_log_slow_usage {
    struct timeval tv;
    struct rusage ru;
} log_slow_usage_t;

typedef struct st_log_slow_conf {
    int enabled;            /* engine is set to be on(1) or off(0) */
    long long_request_time;  /* log resource consumption only on slow request in msec */
} log_slow_conf_t;


static log_slow_usage_t usage_start;

static const char *set_enabled(cmd_parms *parms, void *mconfig, int arg)
{
    log_slow_conf_t *conf =
            ap_get_module_config(parms->server->module_config, &log_slow_module);
    if (conf == NULL){
        return "LogSlowModule: Failed to retrieve configuration for mod_log_slow";
    }
    conf->enabled = arg;
    return NULL;
}

static const char *set_log_slow_long_request_time(cmd_parms *parms,
                                    void *mconfig, const char *arg)
{
    long val;
    val = atol(arg);

    if (val < MIN_LOG_SLOW_REQUEST ) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                "LogSlowLongRequestTime of %ld must be greater than %ld",
                val, MIN_LOG_SLOW_REQUEST);
        return "LogSlowModule: Wrong param: LogSlowLongRequestTime";
    }
    if (val > MAX_LOG_SLOW_REQUEST ) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                "LogSlowLongRequestTime of %ld must not exceed %ld",
                val, MAX_LOG_SLOW_REQUEST);
        return "LogSlowModule: Wrong param: LogSlowLongRequestTime";
    }

    log_slow_conf_t *conf =
            ap_get_module_config(parms->server->module_config, &log_slow_module);
    if (conf == NULL){
        return "LogSlowModule: Failed to retrieve configuration for mod_log_slow";
    }
    conf->long_request_time = val;
    return NULL;
}

void mod_log_slow_set_default(log_slow_conf_t *conf) {
    if (conf) {
        conf->enabled = 1;
        conf->long_request_time = 0;
    }
}

static void* log_slow_create_server_config(apr_pool_t* p, server_rec* s)
{
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "log_slow_create_server_config");
    log_slow_conf_t* conf = apr_pcalloc(p, sizeof(log_slow_conf_t));
    mod_log_slow_set_default(conf);
    return conf;
}

static double log_slow_time_elapsed( struct timeval *before, struct timeval *after )
{
    double a,b;

    if ( !before || !after || !timerisset(before) || !timerisset(after) ) {
        fprintf(stderr, "[%d] NULL time handed to log_slow_time_elapsed",
            (int)getpid());
        return 0;
    }
    b = before->tv_sec + (double)before->tv_usec*1e-6;
    a = after->tv_sec + (double)after->tv_usec*1e-6;
    return (a-b);
}

static void log_slow_snapshot( log_slow_usage_t *u )
{
    if (!u) {
        fprintf(stderr, "[%d] NULL log_slow_usage_t handed to log_slow_snapshot",
            (int)getpid());
        return;
    }
    getrusage(RUSAGE_SELF, &(u->ru));
    gettimeofday(&(u->tv), NULL);
}

static void log_slow_show_snapshot(request_rec *r,
                            log_slow_usage_t *u, const char* name )
{
    char* n;
    if (!r ||!u ) {
        fprintf(stderr,"[%d] NULL request_rec or log_slow_usage_t handed to log_slow_show_snapshot",
            (int)getpid());
        return;
    }
    if ( name != 0 && *name != 0 ) {
        n = (char*)name;
    } else {
        n  = "SNAPSHOT";
    }
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
        "%s[%d] - time: %ld.%06ld  utime: %ld.%06ld stime: %ld.%06ld ",
        n, (int)getpid(),
        u->tv.tv_sec, u->tv.tv_usec,
        u->ru.ru_utime.tv_sec, u->ru.ru_utime.tv_usec,
        u->ru.ru_stime.tv_sec, u->ru.ru_stime.tv_usec);
}

static int log_slow_post_read_request(request_rec *r)
{
    log_slow_conf_t *conf =
          (log_slow_conf_t *) ap_get_module_config(r->server->module_config, &log_slow_module);
    if (conf && conf->enabled ) {
        log_slow_snapshot(&usage_start);
#ifdef LOGRC_DEBUG
        log_slow_show_snapshot(r,&usage_start,"START");
#endif
    }
    return OK;
}

static int log_slow_log_transaction(request_rec *r)
{
    log_slow_conf_t *conf;
    double time_elapsed,utime_elapsed,stime_elapsed;
    conf = (log_slow_conf_t *) ap_get_module_config(r->server->module_config, &log_slow_module);

    if (conf && conf->enabled ) {
        log_slow_usage_t usage_end;
        log_slow_snapshot(&usage_end);
#ifdef LOGRC_DEBUG
        log_slow_show_snapshot(r, &usage_end, "END");
#endif
        time_elapsed =
            log_slow_time_elapsed(&(usage_start.tv), &(usage_end.tv));

        if ( conf->long_request_time > (long)(time_elapsed*1000.000) ) {
            return OK;
        }
        utime_elapsed =
            log_slow_time_elapsed(&(usage_start.ru.ru_utime),&(usage_end.ru.ru_utime)),
        stime_elapsed =
            log_slow_time_elapsed(&(usage_start.ru.ru_stime),&(usage_end.ru.ru_stime)),

        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
            "SLOWLOG[%d] - elapsed: %.6lf "
            "CPU: %.6lf(usr)/%.6lf(sys) "
            "- hostname: %s uri: %s",
            (int)getpid(), time_elapsed, utime_elapsed, stime_elapsed,
            r->hostname, r->uri
           );
    }
    return OK;
}

static void log_slow_register_hooks(apr_pool_t *p)
{
    ap_hook_post_read_request(log_slow_post_read_request,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_log_transaction(log_slow_log_transaction, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec log_slow_cmds[] =
{
    AP_INIT_FLAG("LogSlowEnabled", set_enabled, NULL, RSRC_CONF,
            "set \"On\" to enable log_slow, \"Off\" to disable"),
    AP_INIT_TAKE1("LogSlowLongRequestTime", set_log_slow_long_request_time, NULL, RSRC_CONF,
            "set the limit of request handling time in millisecond. Default \"0\""),
    {NULL}
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA log_slow_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                           /* create per-dir    config structures */
    NULL,                           /* merge  per-dir    config structures */
    log_slow_create_server_config,  /* create per-server config structures */
    NULL,                           /* merge  per-server config structures */
    log_slow_cmds,                  /* table of config file commands       */
    log_slow_register_hooks         /* register hooks                      */
};

