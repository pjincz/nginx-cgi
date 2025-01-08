
/*
 * Copyright (C) Chizhong Jin
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_flag_t enabled;
} ngx_http_cgi_loc_conf_t;


static ngx_int_t ngx_http_cgi_handler(ngx_http_request_t *r);
static void *ngx_http_cgi_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_cgi_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);


static ngx_command_t  ngx_http_cgi_commands[] = {

    { ngx_string("cgi"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cgi_loc_conf_t, enabled),
      NULL },

    // TODO: add following symbolic link?
    // TODO: add cgi_interpreter
    // TODO: add cgi_x_only
    // TODO: add cgi_index to generate content for directory?

      ngx_null_command
};


static ngx_http_module_t  ngx_http_cgi_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_cgi_create_loc_conf,          /* create location configuration */
    ngx_http_cgi_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_cgi_module = {
    NGX_MODULE_V1,
    &ngx_http_cgi_module_ctx,              /* module context */
    ngx_http_cgi_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_hello_world_text = ngx_string("Hello, world!\n");


static ngx_int_t
ngx_http_cgi_handler(ngx_http_request_t *r)
{
    ngx_buf_t                 *b;
    ngx_int_t                  rc;
    ngx_chain_t                out;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_str_t                  spath;
    size_t                     strip_prefix;
    ngx_file_info_t            script_info;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cgi handler");

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uri: %V, alias: %d, root: %V", &r->uri,
                   clcf->alias, &clcf->root);

    spath.data = ngx_palloc(r->pool, clcf->root.len + 1 + r->uri.len + 1);
    ngx_memcpy(spath.data, clcf->root.data, clcf->root.len);
    spath.len = clcf->root.len;

    // append a tail / here, if clcf->root doesn't contains one
    if (spath.data[spath.len - 1] != '/') {
        spath.data[spath.len] = '/';
        spath.len += 1;
    }

    strip_prefix = clcf->alias;
    if (strip_prefix > r->uri.len) {
        // this should not happens
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    // remove leading /s in uri
    while (r->uri.data[strip_prefix] == '/') {
        strip_prefix += 1;
    }

    // append uri to script path
    memcpy(spath.data + spath.len, r->uri.data + strip_prefix, r->uri.len - strip_prefix);
    spath.len += r->uri.len - strip_prefix;

    // convert string to c string
    spath.data[spath.len] = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "script path: %V", &spath);

    if (ngx_file_info(spath.data, &script_info) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "run cgi \"%V\" failed", &spath);
        if (ngx_errno == EACCES) {
            return NGX_HTTP_FORBIDDEN;
        }
        if (ngx_errno == ENOENT) {
            return NGX_HTTP_NOT_FOUND;
        }
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!ngx_is_file(&script_info)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "run cgi \"%V\" failed, not regular file", &spath);
        return NGX_HTTP_NOT_FOUND;
    }

    if (access((char*)spath.data, X_OK) != 0) {
        // no execute permission
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "run cgi \"%V\" failed, no x permission", &spath);
        return NGX_HTTP_FORBIDDEN;
    }

    /* ignore client request body if any */
    if (ngx_http_discard_request_body(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* send header */

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = ngx_http_hello_world_text.len;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    /* send body */

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->pos = ngx_http_hello_world_text.data;
    b->last = ngx_http_hello_world_text.data + ngx_http_hello_world_text.len;
    b->memory = 1;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static void *
ngx_http_cgi_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_cgi_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cgi_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_cgi_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_cgi_loc_conf_t *prev = parent;
    ngx_http_cgi_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);

    if (conf->enabled) {
        ngx_http_core_loc_conf_t  *clcf;

        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

        // TODO: stop `location /cgi-bin` be set here, it will be a security
        // vulnerability

        clcf->handler = ngx_http_cgi_handler;
    }

    return NGX_CONF_OK;
}
