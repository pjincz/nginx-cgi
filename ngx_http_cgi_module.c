
/*
 * Copyright (C) Chizhong Jin
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_cgi_handler(ngx_http_request_t *r);
static char *ngx_http_cgi(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_cgi_commands[] = {

    { ngx_string("cgi"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_cgi,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_cgi_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
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
    ngx_buf_t    *b;
    ngx_int_t     rc;
    ngx_chain_t   out;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cgi handler");

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


static char *
ngx_http_cgi(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_cgi_handler;

    return NGX_CONF_OK;
}
