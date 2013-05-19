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
#include "util_time.h"
#include "ap_mpm.h"        // AP_MPMQ_MAX_THREADS
#include "ap_mmn.h"        // AP_MODULE_MAGIC_AT_LEAST
#include "apr_strings.h"
#include "apr_atomic.h"
#include "apr_anylock.h"
#include "apr_errno.h"
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>        // for getpid() 


#define MAX_LOG_SLOW_REQUEST       (1000*30)  //30sec
#define MIN_LOG_SLOW_REQUEST       (0)
#define DEFAULT_LOG_SLOW_REQUEST   (1000*1)   //1sec
#define LOGBUF_SIZE                (512)
#define ALL_LOGBUF_INIT_ARRAY_SIZE (3)

module AP_MODULE_DECLARE_DATA log_slow_module;

typedef struct st_log_slow_usage {
    struct timeval tv;
    struct rusage ru;
} log_slow_usage_t;

typedef struct {
    apr_file_t *fd;               /* this file handle pointer must be the same as log_slow_config's fd */
    apr_size_t outcnt;
    char outbuf[LOGBUF_SIZE];
    apr_anylock_t mutex;
} log_slow_buffer;

typedef struct st_log_slow_conf {
    int enabled;                  /* engine is set to be on(1) or off(0) */
    long long_request_time;       /* log resource consumption only on slow request in msec */
    const char *filename;         /* filename of slow log */
    const char *timeformat;       /* time format of slow log */
    int buffered_logs;            /* buffered_logs is set to be on(1) or off(0) */
    log_slow_buffer *log_buffer;  /* buffered_log buffer */
    apr_file_t *fd;
} log_slow_config;

static apr_uint32_t next_id;
static log_slow_usage_t usage_start;
static apr_array_header_t *all_log_buffer_arr = NULL;
/* no buffered_log by default. set 1 if at least one buffered_logs option is set to be on */
static int at_least_buffered_logs = 0;

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
                val, (long)MIN_LOG_SLOW_REQUEST);
        return "LogSlowModule: Wrong param: LogSlowLongRequestTime";
    }
    if (val > MAX_LOG_SLOW_REQUEST ) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
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

static const char *set_buffered_logs(cmd_parms *parms, void *mconfig, int arg)
{
    log_slow_config *conf =
        ap_get_module_config(parms->server->module_config, &log_slow_module);
    if (!conf){
        return "LogSlowModule: Failed to retrieve configuration for mod_log_slow";
    }
    conf->buffered_logs = arg;
    if (conf->buffered_logs) {
        at_least_buffered_logs = 1;
    }
    return NULL;
}

/* code from mod_log_config */
static const char *log_request_time_custom(request_rec *r, char *a,
                                           apr_time_exp_t *xt)
{
    apr_size_t retcode;
    char tstr[MAX_STRING_LEN];
    apr_strftime(tstr, &retcode, sizeof(tstr), a, xt);
    return apr_pstrdup(r->pool, tstr);
}

/* code from mod_log_config */
#define DEFAULT_REQUEST_TIME_SIZE 32
typedef struct {
    unsigned t;
    char timestr[DEFAULT_REQUEST_TIME_SIZE];
    unsigned t_validate;
} cached_request_time;

#define TIME_CACHE_SIZE 4
#define TIME_CACHE_MASK 3
static cached_request_time request_time_cache[TIME_CACHE_SIZE];

/* code from mod_log_config, and modified a bit */
static const char *log_request_time(request_rec *r, char *a)
{
    apr_time_exp_t xt;
    apr_time_t request_time = r->request_time;
    /* ###  I think getting the time again at the end of the request
     * just for logging is dumb.  i know it's "required" for CLF.
     * folks writing log parsing tools don't realise that out of order
     * times have always been possible (consider what happens if one
     * process calculates the time to log, but then there's a context
     * switch before it writes and before that process is run again the
     * log rotation occurs) and they should just fix their tools rather
     * than force the server to pay extra cpu cycles.  if you've got
     * a problem with this, you can set the define.  -djg
     */
    if (a && *a) {              /* Custom format */
        /* The custom time formatting uses a very large temp buffer
         * on the stack.  To avoid using so much stack space in the
         * common case where we're not using a custom format, the code
         * for the custom format in a separate function.  (That's why
         * log_request_time_custom is not inlined right here.)
         */
        ap_explode_recent_localtime(&xt, request_time);
        return log_request_time_custom(r, a, &xt);
    }
    else {                      /* CLF format */
        /* This code uses the same technique as ap_explode_recent_localtime():
         * optimistic caching with logic to detect and correct race conditions.
         * See the comments in server/util_time.c for more information.
         */
        cached_request_time* cached_time = apr_palloc(r->pool,
                                                      sizeof(*cached_time));
        unsigned t_seconds = (unsigned)apr_time_sec(request_time);
        unsigned i = t_seconds & TIME_CACHE_MASK;
        *cached_time = request_time_cache[i];
        if ((t_seconds != cached_time->t) ||
            (t_seconds != cached_time->t_validate)) {

            /* Invalid or old snapshot, so compute the proper time string
             * and store it in the cache
             */
            char sign;
            int timz;

            ap_explode_recent_localtime(&xt, request_time);
            timz = xt.tm_gmtoff;
            if (timz < 0) {
                timz = -timz;
                sign = '-';
            }
            else {
                sign = '+';
            }
            cached_time->t = t_seconds;
            apr_snprintf(cached_time->timestr, DEFAULT_REQUEST_TIME_SIZE,
                         "[%02d/%s/%d:%02d:%02d:%02d %c%.2d%.2d]",
                         xt.tm_mday, apr_month_snames[xt.tm_mon],
                         xt.tm_year+1900, xt.tm_hour, xt.tm_min, xt.tm_sec,
                         sign, timz / (60*60), (timz % (60*60)) / 60);
            cached_time->t_validate = t_seconds;
            request_time_cache[i] = *cached_time;
        }
        return cached_time->timestr;
    }
}

void set_default(log_slow_config *conf) {
    if (conf) {
        conf->enabled = 0;
        conf->long_request_time = DEFAULT_LOG_SLOW_REQUEST;
        conf->filename= NULL;
        conf->timeformat= NULL;
        conf->buffered_logs= 0;
        conf->log_buffer= NULL;
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
    conf->timeformat = apr_pstrdup(p, nc->timeformat ? nc->timeformat : pc->timeformat);
    conf->buffered_logs = (nc->buffered_logs ? nc->buffered_logs : pc->buffered_logs);
    conf->log_buffer = (nc->log_buffer ? nc->log_buffer : pc->log_buffer);
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

static void flush_log(log_slow_buffer *buf)
{
    if (buf->outcnt && buf->fd != NULL) {
        apr_file_write(buf->fd, buf->outbuf, &buf->outcnt);
        buf->outcnt = 0;
    }
}

static apr_status_t flush_all_logs(void *dummy)
{
    int i;
    log_slow_buffer **array = (log_slow_buffer **)all_log_buffer_arr->elts;
    for (i = 0; i < all_log_buffer_arr->nelts; i++) {
        log_slow_buffer *buf = array[i];
        flush_log(buf);
    }
    return APR_SUCCESS;
}

/* code from mod_log_config, and modified a bit */
static void log_slow_child_init(apr_pool_t *p, server_rec *s)
{
    int mpm_threads;
    ap_mpm_query(AP_MPMQ_MAX_THREADS, &mpm_threads);

    /* Now register the last buffer flush with the cleanup engine */
    if (at_least_buffered_logs) {
        int i;
        log_slow_buffer **array = (log_slow_buffer **)all_log_buffer_arr->elts;

        apr_pool_cleanup_register(p, s, flush_all_logs, flush_all_logs);

        for (i = 0; i < all_log_buffer_arr->nelts; i++) {
            log_slow_buffer *this = array[i];

#if APR_HAS_THREADS
            if (mpm_threads > 1) {
                apr_status_t rv;

                this->mutex.type = apr_anylock_threadmutex;
                rv = apr_thread_mutex_create(&this->mutex.lock.tm,
                                             APR_THREAD_MUTEX_DEFAULT,
                                             p);
                if (rv != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                                 "could not initialize buffered log mutex, "
                                 "transfer log may become corrupted");
                    this->mutex.type = apr_anylock_none;
                }
            }
            else
#endif
            {
                this->mutex.type = apr_anylock_none;
            }
        }
    }
}

/* code partly from mod_log_forensic */
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
    // init each buffered_logs
    if (conf->buffered_logs) {
        conf->log_buffer = apr_pcalloc(p, sizeof(log_slow_buffer));
        conf->log_buffer->fd = conf->fd;
        conf->log_buffer->outcnt = 0;
        memset(conf->log_buffer->outbuf, 0, strlen(conf->log_buffer->outbuf) );
        // initialize log_buffer's mutex in init child func
        //conf->log_buffer->mutex = ...

        // push log_buffer pointer to all_log_buffer_arr
        *(log_slow_buffer **)apr_array_push(all_log_buffer_arr) = conf->log_buffer;
    }
    return 1;
}

static int log_slow_open_logs(apr_pool_t *pc, apr_pool_t *p, apr_pool_t *pt, server_rec *s)
{
    // First init the buffered logs array, which is needed when opening the logs.
    if (at_least_buffered_logs) {
        all_log_buffer_arr = apr_array_make(p, ALL_LOGBUF_INIT_ARRAY_SIZE, sizeof(log_slow_buffer *));
    }
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

static apr_status_t log_slow_file_write(request_rec *r,
                                           log_slow_config *conf,
                                           const char *log,
                                           apr_size_t loglen)
{
    apr_status_t rv;
    char* str;

    if (!conf) {
        return APR_BADARG;
    }
    if (!conf->buffered_logs) {
        rv = apr_file_write(conf->fd, log, &loglen);
    }
    else{
        log_slow_buffer *buf = conf->log_buffer;
        if ((rv = APR_ANYLOCK_LOCK(&buf->mutex)) != APR_SUCCESS) {
            return rv;
        }
        if (loglen + buf->outcnt > LOGBUF_SIZE) {
            flush_log(buf);
        }
        if (loglen >= LOGBUF_SIZE ) {
            rv = apr_file_write(conf->fd, log, &loglen);
        }
        else {
            memcpy(&buf->outbuf[buf->outcnt], log, loglen);
            buf->outcnt +=loglen;
            rv = APR_SUCCESS;
        }
        APR_ANYLOCK_UNLOCK(&buf->mutex);
    }
    return rv;
}

static int log_slow_log_transaction(request_rec *r)
{
    log_slow_config *conf;
    double time_elapsed,utime_elapsed,stime_elapsed;
    char* logbuf;
    char *id;
    char *reqinfo;
    char *elapsed_s;
    char *remoteip;
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

#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
    remoteip = r->connection->client_ip;
#else
    remoteip = r->connection->remote_ip;
#endif

    reqinfo = ap_escape_logitem(r->pool,
                             (r->parsed_uri.password)
                               ? apr_pstrcat(r->pool, r->method, " ",
                                             apr_uri_unparse(r->pool,
                                                             &r->parsed_uri, 0),
                                             r->assbackwards ? NULL : " ",
                                             r->protocol, NULL)
                               : r->the_request);

    logbuf = (char*)apr_psprintf(r->pool,
           "%s %s "
           "elapsed: %.2lf cpu: %.2lf(usr)/%.2lf(sys) "
           "pid: %d ip: %s host: %s:%u reqinfo: %s"
           "\n",
           id, log_request_time(r, (char*)conf->timeformat),
           time_elapsed, utime_elapsed, stime_elapsed,
           (int)getpid(), remoteip, r->hostname,
           r->server->port ? r->server->port : ap_default_port(r), reqinfo
        );

    logsize = strlen(logbuf);
    rv  = log_slow_file_write(r, conf, logbuf, logsize);
    if (rv != APR_SUCCESS ) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
            "couldn't write slow log %s", conf->filename);
        return DECLINED;
    }

    /* store logslow id and time in apache notes */
    apr_table_setn(r->notes, "logslow-id", id);
    apr_table_setn(r->notes, "logslow-time", elapsed_s);

    return OK;
}

static void log_slow_register_hooks(apr_pool_t *p)
{
    static const char * const asz_succ[]={ "mod_log_config.c", NULL };
    ap_hook_child_init(log_slow_child_init,NULL,NULL,APR_HOOK_MIDDLE);
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
    AP_INIT_TAKE1("LogSlowFileName", set_file_name, NULL, RSRC_CONF,
            "set the filename of the slow log"),
    AP_INIT_TAKE1("LogSlowTimeFormat", set_time_format, NULL, RSRC_CONF,
            "set time string format of the slow log"),
    AP_INIT_FLAG("LogSlowBufferedLogs", set_buffered_logs, NULL, RSRC_CONF,
            "set \"On\" to enable buffered_logs, \"Off\" to disable"),
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
