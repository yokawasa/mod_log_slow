/*
 * mod_log_slow.c - Logging Slow Request Module for Apache2.X
 *
 * Copyright (C) 2008-2009 Yoichi Kawasaki All rights reserved.
 * www.yk55.com
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
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"      // ap_log_rerror
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_atomic.h"
#include <sys/time.h>
#include <sys/resource.h>

#define MAX_LOG_SLOW_REQUEST     (1000*30)  //30sec
#define MIN_LOG_SLOW_REQUEST     (0)
#define DEFAULT_LOG_SLOW_REQUEST (1000*1)   //1sec

module AP_MODULE_DECLARE_DATA log_slow_module;

typedef struct st_log_slow_usage {
    struct timeval tv;
    struct rusage ru;
} log_slow_usage_t;

typedef struct st_log_slow_conf {
    int enabled;             /* engine is set to be on(1) or off(0) */
    long long_request_time;  /* log resource consumption only on slow request in msec */
    const char *filename;    /* filename of slow log */
    apr_file_t *fd;
} log_slow_config;

static apr_uint32_t next_id;

static log_slow_usage_t usage_start;

static const char *set_enabled(cmd_parms *parms, void *mconfig, int arg)
{
    log_slow_config *conf =
        ap_get_module_config(parms->server->module_config, &log_slow_module);
    if (!conf){
        return "LogSlowModule: Failed to retrieve configuration for mod_log_slow";
    }
    conf->enabled = arg;
    return NULL;
}

static const char *set_long_request_time(cmd_parms *parms,
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

    log_slow_config *conf =
        ap_get_module_config(parms->server->module_config, &log_slow_module);
    if (!conf){
        return "LogSlowModule: Failed to retrieve configuration for mod_log_slow";
    }
    conf->long_request_time = val;
    return NULL;
}

static const char *set_filename(cmd_parms *parms,
                                    void *mconfig, const char *arg)
{
    log_slow_config *conf =
        ap_get_module_config(parms->server->module_config, &log_slow_module);
    if (!conf){
        return "LogSlowModule: Failed to retrieve configuration for mod_log_slow";
    }
    conf->filename = (char*)arg;
    return NULL;
}

void set_default(log_slow_config *conf) {
    if (conf) {
        conf->enabled = 0;
        conf->long_request_time = DEFAULT_LOG_SLOW_REQUEST;
        conf->filename= NULL;
        conf->fd =  NULL;
    }
}

static void* log_slow_create_server_config(apr_pool_t* p, server_rec* s)
{
    log_slow_config* conf = apr_pcalloc(p, sizeof(*conf) );
    set_default(conf);
    return conf;
}

static void *log_slow_merge_server_config(apr_pool_t *p,
                            void *parent_conf, void *new_conf)
{
    log_slow_config* conf = (log_slow_config *)apr_pcalloc(p, sizeof *conf);
    log_slow_config* pc = (log_slow_config *)parent_conf;
    log_slow_config* nc = (log_slow_config *)new_conf;

    conf->enabled = (nc->enabled ? nc->enabled : pc->enabled);
    conf->long_request_time = (nc->long_request_time!=DEFAULT_LOG_SLOW_REQUEST
                    ? nc->long_request_time : pc->long_request_time);
    conf->filename = apr_pstrdup(p, nc->filename ? nc->filename : pc->filename);
    conf->fd = NULL;

    return conf;
}

static double get_time_elapsed( struct timeval *before, struct timeval *after )
{
    double a,b;

    if ( !before || !after || !timerisset(before) || !timerisset(after) ) {
#ifdef LOGSLOW_DEBUG
        // this error messages may be output in every apache stop and start,
        // so put this only in debug mode
        fprintf(stderr, "[%d] NULL time handed to get_time_elapsed\n",
            (int)getpid());
#endif
        return 0;
    }
    b = before->tv_sec + (double)before->tv_usec*1e-6;
    a = after->tv_sec + (double)after->tv_usec*1e-6;
    return (a-b);
}

static void set_snapshot( log_slow_usage_t *u )
{
    if (!u) {
#ifdef LOGSLOW_DEBUG
        fprintf(stderr, "[%d] NULL log_slow_usage_t handed to set_snapshot\n",
            (int)getpid());
#endif
        return;
    }
    getrusage(RUSAGE_SELF, &(u->ru));
    gettimeofday(&(u->tv), NULL);
}

static void show_snapshot(request_rec *r,
                            log_slow_usage_t *u, const char* name )
{
    char* n;
    if (!r ||!u ) {
#ifdef LOGSLOW_DEBUG
        fprintf(stderr,"[%d] NULL request_rec or log_slow_usage_t handed to show_snapshot\n",
            (int)getpid());
#endif
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

/* code from mod_log_forensic, and modified a bit */
static int open_log(server_rec *s, apr_pool_t *p)
{
    log_slow_config *conf = ap_get_module_config(s->module_config, &log_slow_module);

    if (!conf || !conf->filename || conf->fd)
        return 1;

    if (*conf->filename == '|') {
        piped_log *pl;
        const char *pname = ap_server_root_relative(p, conf->filename + 1);

        pl = ap_open_piped_log(p, pname);
        if (pl == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "couldn't spawn slow log pipe %s", conf->filename);
            return 0;
        }
        conf->fd = ap_piped_log_write_fd(pl);
    }
    else {
        const char *fname = ap_server_root_relative(p, conf->filename);
        apr_status_t rv;

        if ((rv = apr_file_open(&conf->fd, fname,
                                APR_WRITE | APR_APPEND | APR_CREATE,
                                APR_OS_DEFAULT, p)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "could not open slow log file %s.", fname);
            return 0;
        }
    }
    return 1;
}

static int log_slow_open_logs(apr_pool_t *pc, apr_pool_t *p, apr_pool_t *pt, server_rec *s)
{
    for ( ; s ; s = s->next) {
        if (!open_log(s, p)) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    return OK;
}

static int log_slow_post_read_request(request_rec *r)
{
    log_slow_config *conf =
         ap_get_module_config(r->server->module_config, &log_slow_module);

    if (!conf || !conf->enabled ) {
        return DECLINED;
    }

    set_snapshot(&usage_start);
#ifdef LOGSLOW_DEBUG
    show_snapshot(r,&usage_start,"START");
#endif
    return OK;
}

static int log_slow_log_transaction(request_rec *r)
{
    log_slow_config *conf;
    double time_elapsed,utime_elapsed,stime_elapsed;
    char* logbuf;
    char *id;
    char *elapsed_s;
    apr_size_t logsize;
    apr_status_t rv;
    conf = ap_get_module_config(r->server->module_config, &log_slow_module);

    if (!conf || !conf->enabled ) {
        return DECLINED;
    }
    if (!conf->fd || r->prev) {
        return DECLINED;
    }

    log_slow_usage_t usage_end;
    set_snapshot(&usage_end);
#ifdef LOGSLOW_DEBUG
    show_snapshot(r, &usage_end, "END");
#endif
    time_elapsed =
        get_time_elapsed(&(usage_start.tv), &(usage_end.tv));

    if ( conf->long_request_time > (long)(time_elapsed*1000.000) ) {
        return DECLINED;
    }
    /* code from mod_log_forensic, and modified a bit */
    if (!(id = (char*)apr_table_get(r->subprocess_env, "UNIQUE_ID"))) {
        /* we make the assumption that we can't go through all the PIDs in
        under 1 second */
        id = apr_psprintf(r->pool, "%x:%lx:%x", getpid(), time(NULL),
                          apr_atomic_inc32(&next_id));
    }

    utime_elapsed =
        get_time_elapsed(&(usage_start.ru.ru_utime),&(usage_end.ru.ru_utime)),
    stime_elapsed =
        get_time_elapsed(&(usage_start.ru.ru_stime),&(usage_end.ru.ru_stime)),

    elapsed_s = (char*)apr_psprintf(r->pool, "%.2lf", time_elapsed);

    logbuf = (char*)apr_psprintf(r->pool,
        "%s @ %d "
        "elapsed: %.2lf cpu: %.2lf(usr)/%.2lf(sys) "
        "pid: %d ip: %s host: %s uri: %s"
        "\n",
        id, time(NULL),
        time_elapsed, utime_elapsed, stime_elapsed,
        (int)getpid(), r->connection->remote_ip, r->hostname, r->uri
       );

    logsize = strlen(logbuf);
    rv = apr_file_write(conf->fd, logbuf, &logsize);
    if (rv != APR_SUCCESS ) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
            "couldn't write slow log %s", conf->filename);
        return DECLINED;
    }

    /* logslow id and time in apache notes */
    apr_table_setn(r->notes, "logslow-id", id);
    apr_table_setn(r->notes, "logslow-time", elapsed_s);

    return OK;
}

static void log_slow_register_hooks(apr_pool_t *p)
{
    static const char * const asz_succ[]={ "mod_log_config.c", NULL };
    ap_hook_open_logs(log_slow_open_logs,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_post_read_request(log_slow_post_read_request,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_log_transaction(log_slow_log_transaction, NULL, asz_succ, APR_HOOK_MIDDLE);
}

static const command_rec log_slow_cmds[] =
{
    AP_INIT_FLAG("LogSlowEnabled", set_enabled, NULL, RSRC_CONF,
            "set \"On\" to enable log_slow, \"Off\" to disable"),
    AP_INIT_TAKE1("LogSlowLongRequestTime", set_long_request_time, NULL, RSRC_CONF,
            "set the limit of request handling time in millisecond. Default \"0\""),
    AP_INIT_TAKE1("LogSlowFileName", set_filename, NULL, RSRC_CONF,
            "set the filename of the slow log"),

    {NULL}
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA log_slow_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                           /* create per-dir    config structures */
    NULL,                           /* merge  per-dir    config structures */
    log_slow_create_server_config,  /* create per-server config structures */
    log_slow_merge_server_config,   /* merge  per-server config structures */
    log_slow_cmds,                  /* table of config file commands       */
    log_slow_register_hooks         /* register hooks                      */
};

/*
 * vim:ts=4 et
 */
