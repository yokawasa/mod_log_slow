/*
 * mod_log_slow13.c - Logging Slow Request Module for Apache1.3
 *
 * Copyright (C) 2009 Yoichi Kawasaki All rights reserved.
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
#include "http_log.h"
#include "ap_config.h"
#include "multithread.h"
#include <sys/time.h>
#include <sys/resource.h>

#define MAX_LOG_SLOW_REQUEST     (1000*30)  //30sec
#define MIN_LOG_SLOW_REQUEST     (0)
#define DEFAULT_LOG_SLOW_REQUEST (1000*1)   //1sec
#define LOGBUF_SIZE                (512)
#define ALL_LOGBUF_INIT_ARRAY_SIZE (3)

module MODULE_VAR_EXPORT log_slow_module;

typedef struct st_log_slow_usage {
    struct timeval tv;
    struct rusage ru;
} log_slow_usage_t;

typedef struct st_log_slow_conf {
    int enabled;               /* engine is set to be on(1) or off(0) */
    long long_request_time;    /* log resource consumption only on slow request in msec */
    char *filename;      /* filename of slow log */
    char *timeformat;    /* time format of slow log */
    int fd;
} log_slow_config;

static APACHE_TLS next_id = 0;

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
        ap_log_error(APLOG_MARK, APLOG_ERR, NULL,
                "LogSlowLongRequestTime of %ld must be greater than %ld",
                val, (long)MIN_LOG_SLOW_REQUEST);
        return "LogSlowModule: Wrong param: LogSlowLongRequestTime";
    }
    if (val > MAX_LOG_SLOW_REQUEST ) {
        ap_log_error(APLOG_MARK, APLOG_ERR, NULL,
                "LogSlowLongRequestTime of %ld must not exceed %ld",
                val, (long)MAX_LOG_SLOW_REQUEST);
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

static const char *set_file_name(cmd_parms *parms,
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

static const char *set_time_format(cmd_parms *parms,
                                    void *mconfig, const char *arg)
{
    log_slow_config *conf =
        ap_get_module_config(parms->server->module_config, &log_slow_module);
    if (!conf){
        return "LogSlowModule: Failed to retrieve configuration for mod_log_slow";
    }
    conf->timeformat = (char*)arg;
    return NULL;
}

/* code from mod_log_config */
static const char *log_request_time(request_rec *r, char *a)
{
    int timz;
    struct tm *t;
    char tstr[MAX_STRING_LEN];

    t = ap_get_gmtoff(&timz);

    if (a && *a) {              /* Custom format */
        strftime(tstr, MAX_STRING_LEN, a, t);
    }
    else {                      /* CLF format */
        char sign = (timz < 0 ? '-' : '+');

        if (timz < 0) {
            timz = -timz;
        }
        ap_snprintf(tstr, sizeof(tstr), "[%02d/%s/%d:%02d:%02d:%02d %c%.2d%.2d]",
                t->tm_mday, ap_month_snames[t->tm_mon], t->tm_year+1900,
                t->tm_hour, t->tm_min, t->tm_sec,
                sign, timz / 60, timz % 60);
    }
    return ap_pstrdup(r->pool, tstr);
}

void set_default(log_slow_config *conf) {
    if (conf) {
        conf->enabled = 0;
        conf->long_request_time = DEFAULT_LOG_SLOW_REQUEST;
        conf->filename= NULL;
        conf->timeformat = NULL;
        conf->fd =  -1;
    }
}

static void* log_slow_create_server_config(pool * p, server_rec* s)
{
    log_slow_config* conf = ap_pcalloc(p, sizeof(*conf) );
    set_default(conf);
    return conf;
}

static void *log_slow_merge_server_config(pool *p,
                            void *parent_conf, void *new_conf)
{
    log_slow_config* conf = (log_slow_config *)ap_pcalloc(p, sizeof *conf);
    log_slow_config* pc = (log_slow_config *)parent_conf;
    log_slow_config* nc = (log_slow_config *)new_conf;

    conf->enabled = (nc->enabled ? nc->enabled : pc->enabled);
    conf->long_request_time = (nc->long_request_time!=DEFAULT_LOG_SLOW_REQUEST
                    ? nc->long_request_time : pc->long_request_time);
    conf->filename = ap_pstrdup(p, nc->filename ? nc->filename : pc->filename);
    conf->fd = -1;

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
    ap_log_error(APLOG_MARK, APLOG_NOTICE, r->server,
        "%s[%d] - time: %ld.%06ld  utime: %ld.%06ld stime: %ld.%06ld ",
        n, (int)getpid(),
        u->tv.tv_sec, u->tv.tv_usec,
        u->ru.ru_utime.tv_sec, u->ru.ru_utime.tv_usec,
        u->ru.ru_stime.tv_sec, u->ru.ru_stime.tv_usec);
}

static int log_slow_log_transaction(request_rec *r)
{
    log_slow_config *conf;
    double time_elapsed,utime_elapsed,stime_elapsed;
    char* logbuf;
    char *id;
    char *reqinfo;
    char *elapsed_s;
    //apr_size_t logsize;
    int logsize;
    int bytes_written;
//    apr_status_t rv;
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
    if (!(id = (char*)ap_table_get(r->subprocess_env, "UNIQUE_ID"))) {
        /* we make the assumption that we can't go through all the PIDs in
        under 1 second */
        /* NOT SUPPORT WIN32!!! */
#ifdef MULTITHREAD
        id = ap_psprintf(r->pool, "%x:%x:%lx:%x", getpid(), gettid(), time(NULL), next_id++);
#else
        id = ap_psprintf(r->pool, "%x:%lx:%x", getpid(), time(NULL), next_id++);
#endif
    }

    utime_elapsed =
        get_time_elapsed(&(usage_start.ru.ru_utime),&(usage_end.ru.ru_utime)),
    stime_elapsed =
        get_time_elapsed(&(usage_start.ru.ru_stime),&(usage_end.ru.ru_stime)),

    elapsed_s = (char*)ap_psprintf(r->pool, "%.2lf", time_elapsed);

    reqinfo = ap_escape_logitem(r->pool,
                 (r->parsed_uri.password) ? ap_pstrcat(r->pool, r->method, " ",
                     ap_unparse_uri_components(r->pool, &r->parsed_uri, 0),
                     r->assbackwards ? NULL : " ", r->protocol, NULL)
                    : r->the_request
                 );

    logbuf = (char*)ap_psprintf(r->pool,
        "%s %s "
        "elapsed: %.2lf cpu: %.2lf(usr)/%.2lf(sys) "
        "pid: %d ip: %s host: %s:%u reqinfo: %s"
        "\n",
        id, log_request_time(r, (char*)conf->timeformat),
        time_elapsed, utime_elapsed, stime_elapsed,
        (int)getpid(), r->connection->remote_ip, r->hostname,
        r->server->port ? r->server->port : ap_default_port(r), reqinfo
      );

    logsize = strlen(logbuf);
    bytes_written = write(conf->fd, logbuf, logsize);
    if (bytes_written < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
           "couldn't write slow log %s", conf->filename);
        return DECLINED;
    }

    /* logslow id and time in apache notes */
    ap_table_setn(r->notes, "logslow-id", id);
    ap_table_setn(r->notes, "logslow-time", elapsed_s);

    return OK;
}

/* code from mod_log_forensic, and modified a bit */
static int open_log(server_rec *s, pool *p)
{
    log_slow_config *conf = ap_get_module_config(s->module_config, &log_slow_module);

    if (!conf || !conf->filename || conf->fd > 0)
        return 1;

    if (*conf->filename == '|') {
        piped_log *pl;
        char *pname = ap_server_root_relative(p, conf->filename + 1);

        pl = ap_open_piped_log(p, pname);
        if (pl == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, s,
                         "couldn't spawn slow log pipe %s", conf->filename);
            exit(1);
        }
        conf->fd = ap_piped_log_write_fd(pl);
    }
    else {
        char *fname = ap_server_root_relative(p, conf->filename);
        if ((conf->fd = ap_popenf_ex(p, fname,O_WRONLY | O_APPEND | O_CREAT,
                                    0644, 1)) < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, s,
                         "could not open slow log file %s.", fname);
            exit(1);
        }
    }
    return 1;
}

static void log_slow_open_logs(server_rec *s, pool *p)
{
    for ( ; s ; s = s->next) {
        open_log(s, p);
    }
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

static const command_rec log_slow_cmds[] =
{
    {"LogSlowEnabled", set_enabled, NULL, RSRC_CONF, FLAG,
    "set \"On\" to enable log_slow, \"Off\" to disable"},
    {"LogSlowLongRequestTime", set_long_request_time, NULL, RSRC_CONF, TAKE1,
    "set the limit of request handling time in millisecond. Default \"0\""},
    {"LogSlowFileName", set_file_name, NULL, RSRC_CONF, TAKE1,
    "set the filename of the slow log"},
    {"LogSlowTimeFormat", set_time_format, NULL, RSRC_CONF, TAKE1,
    "set the filename of the slow log"},
    {NULL}
};

/* Dispatch list for API hooks */
module MODULE_VAR_EXPORT log_slow_module = {
    STANDARD_MODULE_STUFF,
    log_slow_open_logs,             /* module initializer                  */
    NULL,                           /* create per-dir    config structures */
    NULL,                           /* merge  per-dir    config structures */
    log_slow_create_server_config,  /* create per-server config structures */
    log_slow_merge_server_config,   /* merge  per-server config structures */
    log_slow_cmds,                  /* table of config file commands       */
    NULL,                           /* [#8] MIME-typed-dispatched handlers */
    NULL,                           /* [#1] URI to filename translation    */
    NULL,                           /* [#4] validate user id from request  */
    NULL,                           /* [#5] check if the user is ok _here_ */
    NULL,                           /* [#3] check access by host address   */
    NULL,                           /* [#6] determine MIME type            */
    NULL,                           /* [#7] pre-run fixups                 */
    log_slow_log_transaction,       /* [#9] log a transaction              */
    NULL,                           /* [#2] header parser                  */
    NULL,                           /* child_init                          */
    NULL,                           /* child_exit                          */
    log_slow_post_read_request      /* [#0] post read-request              */
};

/*
 * vim:ts=4 et
 */


