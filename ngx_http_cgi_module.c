
/*
 * Copyright (C) Chizhong Jin
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define STACK_SIZE                4096
#define CHILD_PROCESS_VFORK_ERROR 1
#define CHILD_PROCESS_EXEC_ERROR  2

#define PIPE_READ_END 0
#define PIPE_WRITE_END 1


typedef int pipe_pair_t[2];


typedef struct {
    ngx_flag_t enabled;
} ngx_http_cgi_loc_conf_t;


typedef struct {
    ngx_http_request_t *r;
    ngx_str_t           script;
    pipe_pair_t         pipe_stdout;
    // ngx_connection_t    c_stdin;
    ngx_connection_t   *c_stdout;
    // ngx_connection_t    c_stderr;
} ngx_http_cgi_ctx_t;


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


static void
ngx_http_cgi_ctx_cleanup(void *data) {
    ngx_http_cgi_ctx_t *ctx = data;
    if (ctx->pipe_stdout[0] != -1) {
        close(ctx->pipe_stdout[0]);
    }
    if (ctx->pipe_stdout[1] != -1) {
        close(ctx->pipe_stdout[1]);
    }
    if (ctx->c_stdout && !ctx->c_stdout->close) {
        ngx_close_connection(ctx->c_stdout);
    }
}


static ngx_http_cgi_ctx_t *
ngx_http_cgi_ctx_create(ngx_pool_t *pool) {
    ngx_http_cgi_ctx_t *ctx;
    ngx_pool_cleanup_t *cln;

    cln = ngx_pool_cleanup_add(pool, sizeof(ngx_http_cgi_module_ctx));
    if (cln == NULL) {
        return NULL;
    }

    ctx = cln->data;
    ngx_memzero(ctx, sizeof(ngx_http_cgi_module_ctx));

    cln->handler = ngx_http_cgi_ctx_cleanup;

    ctx->pipe_stdout[0] = -1;
    ctx->pipe_stdout[1] = -1;

    return ctx;
}


static int ngx_http_cgi_child_proc(void *arg) {
    ngx_http_cgi_ctx_t *ctx = arg;
    char *child_argv[] = {NULL};
    pid_t pid;

    close(0);
    close(1);
    close(2);
    dup2(ctx->pipe_stdout[PIPE_WRITE_END], 1);
    close(ctx->pipe_stdout[PIPE_READ_END]);

    // fork again to detch
    pid = vfork();
    if (pid == -1) {
        _exit(CHILD_PROCESS_VFORK_ERROR);
    }

    if (pid == 0) {
        // grandson process
        if (execvp((char*)ctx->script.data, child_argv) == -1) {
            _exit(CHILD_PROCESS_EXEC_ERROR);
        }

        // never reaches here, just for elimating compiler warning
        return 0;
    } else {
        // child process
        // TODO: report pid to parent process via pipe
        _exit(0);
    }
}


static ngx_int_t
ngx_http_cgi_spawn_child_process(ngx_http_cgi_ctx_t *ctx) {
    char *stack = NULL;
    pid_t child_pid = 0;
    int wstatus = 0;
    ngx_int_t rc = NGX_OK;

    if (pipe(ctx->pipe_stdout) == -1) {
        ngx_log_error(NGX_LOG_ERR, ctx->r->connection->log, ngx_errno, "pipe");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }

    stack = malloc(STACK_SIZE);
    if (!stack) {
        ngx_log_error(NGX_LOG_ERR, ctx->r->connection->log, ngx_errno,
                     "malloc");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }

    // use clone instead of fork/vfork to avoid SIGCHLD be sent to nginx here
    child_pid = clone(ngx_http_cgi_child_proc, stack + STACK_SIZE,
                           CLONE_VM | CLONE_VFORK, ctx);
    if (child_pid == -1) {
        ngx_log_error(NGX_LOG_ERR, ctx->r->connection->log, ngx_errno,
                      "run cgi \"%V\" failed", &ctx->script);
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }

    // child process will exit immediately after forking grandson
    //  __WCLONE is required to wait cloned process
    if (waitpid(child_pid, &wstatus, __WCLONE) == -1) {
        ngx_log_error(NGX_LOG_ERR, ctx->r->connection->log, ngx_errno,
                      "failed to clean child process");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }

    if (WEXITSTATUS(wstatus) != 0) {
        switch (WEXITSTATUS(wstatus)) {
        case CHILD_PROCESS_VFORK_ERROR:
            ngx_log_error(NGX_LOG_ERR, ctx->r->connection->log, 0,
                        "spawn process vfork failed");
            break;
        case CHILD_PROCESS_EXEC_ERROR:
            ngx_log_error(NGX_LOG_ERR, ctx->r->connection->log, 0,
                        "spawn process exec failed");
            break;
        default:
            ngx_log_error(NGX_LOG_ERR, ctx->r->connection->log, 0,
                        "spawn process unknown error");
            break;
        }
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }

    close(ctx->pipe_stdout[PIPE_WRITE_END]);
    ctx->pipe_stdout[PIPE_WRITE_END] = -1;

cleanup:
    if (stack) {
        free(stack);
    }
    return rc;
}


static void
ngx_http_cgi_stdout_data_handler(ngx_event_t *ev) {
    ngx_connection_t   *c = ev->data;
    ngx_http_cgi_ctx_t *ctx = c->data;
    ngx_http_request_t *r = ctx->r;
    ngx_buf_t          *tmp;
    ngx_chain_t        *head = NULL;
    ngx_chain_t        *tail = NULL;
    ngx_int_t           rc = NGX_OK;

    char buf[65536];
    int nread;

    for (;;) {
        nread = read(c->fd, buf, sizeof(buf));
        if (nread > 0) {
            tmp = ngx_create_temp_buf(r->pool, nread);
            if (tmp == NULL) {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                goto error;
            }

            tmp->last = ngx_cpymem(tmp->pos, buf, nread);
            tmp->flush = 1;

            if (tail) {
                tail->next = ngx_alloc_chain_link(r->pool);
                tail = tail->next;
            } else {
                head = tail = ngx_alloc_chain_link(r->pool);
            }
            if (!tail) {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                goto error;
            }

            tail->buf = tmp;
            tail->next = NULL;
        } else if (nread == 0) {
            // end of file
            if (!tail) {
                // alloc an empty buf, if there's nothing remain
                head = tail = ngx_alloc_chain_link(r->pool);
                tmp = ngx_calloc_buf(r->pool);
                if (tmp == NULL) {
                    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                    goto error;
                }
                tail->buf = tmp;
                tail->next = NULL;
            }
            tail->buf->last_in_chain = 1;
            tail->buf->last_buf = 1;
            ngx_http_finalize_request(r, ngx_http_output_filter(r, head));
            return;
        } else {
            if (ngx_errno == EAGAIN) {
                // wait for more data
                if (tail) {
                    tail->buf->last_in_chain = 1;
                    rc = ngx_http_output_filter(r, head);
                    if (rc == NGX_ERROR || rc > NGX_OK) {
                        goto error;
                    }
                }
                rc = ngx_handle_read_event(ctx->c_stdout->read, 0);
                if (rc == NGX_ERROR || rc > NGX_OK) {
                    goto error;
                }
                return;
            } else {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                goto error;
            }
        }
    }

error:
    ngx_http_finalize_request(r, rc);
    return;
}


static ngx_int_t
ngx_http_cgi_handler(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_cgi_ctx_t        *ctx;
    size_t                     strip_prefix;
    ngx_file_info_t            script_info;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cgi handler");

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uri: %V, alias: %d, root: %V", &r->uri,
                   clcf->alias, &clcf->root);

    ctx = ngx_http_get_module_ctx(r, ngx_http_cgi_module);
    if (ctx == NULL) {
        ctx = ngx_http_cgi_ctx_create(r->pool);
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_cgi_module);
    }

    ctx->r = r;

    ctx->script.data = ngx_palloc(r->pool, clcf->root.len + 1 + r->uri.len + 1);
    ngx_memcpy(ctx->script.data, clcf->root.data, clcf->root.len);
    ctx->script.len = clcf->root.len;

    // append a tail / here, if clcf->root doesn't contains one
    if (ctx->script.data[ctx->script.len - 1] != '/') {
        ctx->script.data[ctx->script.len] = '/';
        ctx->script.len += 1;
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
    memcpy(ctx->script.data + ctx->script.len, r->uri.data + strip_prefix,
           r->uri.len - strip_prefix);
    ctx->script.len += r->uri.len - strip_prefix;

    // convert string to c string
    ctx->script.data[ctx->script.len] = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "script path: %V", &ctx->script);

    if (ngx_file_info(ctx->script.data, &script_info) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "run cgi \"%V\" failed", &ctx->script);
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
                "run cgi \"%V\" failed, not regular file", &ctx->script);
        return NGX_HTTP_NOT_FOUND;
    }

    if (access((char*)ctx->script.data, X_OK) != 0) {
        // no execute permission
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "run cgi \"%V\" failed, no x permission", &ctx->script);
        return NGX_HTTP_FORBIDDEN;
    }

    // TODO: grab request body, and sent to CGI script
    if (ngx_http_discard_request_body(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // TODO: send real CGI header response
    r->headers_out.status = NGX_HTTP_OK;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    rc = ngx_http_cgi_spawn_child_process(ctx);
    if (rc != NGX_OK) {
        return rc;
    }

    if (ngx_nonblocking(ctx->pipe_stdout[PIPE_READ_END]) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                "ngx_nonblocking");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ctx->c_stdout = ngx_get_connection(ctx->pipe_stdout[PIPE_READ_END],
                                       r->connection->log);
    if (ctx->c_stdout) {
        ctx->pipe_stdout[PIPE_READ_END] = -1;
    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                "ngx_get_connection");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->c_stdout->data = ctx;
    ctx->c_stdout->type = SOCK_STREAM;

    ctx->c_stdout->read->handler = ngx_http_cgi_stdout_data_handler;
    ctx->c_stdout->read->log = r->connection->log;
    if (ngx_handle_read_event(ctx->c_stdout->read, 0) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->main->count += 1;
    return NGX_DONE;
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
