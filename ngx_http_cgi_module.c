
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
    // TODO: remove useless fields
    u_char     *pos;
    u_char     *end;

    ngx_uint_t  state;

    ngx_uint_t  header_hash;
    ngx_uint_t  lowcase_index;
    u_char      lowcase_header[NGX_HTTP_LC_HEADER_LEN];

    u_char     *header_name_start;
    u_char     *header_name_end;
    u_char     *header_start;
    u_char     *header_end;

    unsigned    invalid_header : 1;
} ngx_http_cgi_header_scan_t;


typedef struct {
    ngx_http_request_t            *r;
    ngx_str_t                      script;
    pipe_pair_t                    pipe_stdout;
    ngx_connection_t              *c_stdout;

    ngx_buf_t                      header_buf;
    ngx_http_cgi_header_scan_t     header_scan;
    ngx_flag_t                     header_ready;

    ngx_chain_t                   *cache;  // body sending cache
    ngx_chain_t                   *cache_tail;  // body sending cache
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

    cln = ngx_pool_cleanup_add(pool, sizeof(ngx_http_cgi_ctx_t));
    if (cln == NULL) {
        return NULL;
    }

    ctx = cln->data;
    ngx_memzero(ctx, sizeof(ngx_http_cgi_ctx_t));

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


// This function is copied from ngx_http_parse_header_line
// The original version needs ngx_http_request_t, that's a trouble to use
// it for other purpose. So I forked it here.
ngx_int_t
ngx_http_cgi_scan_header_line(ngx_http_cgi_header_scan_t *ctx,
    ngx_uint_t allow_underscores)
{
    u_char      c, ch, *p;
    ngx_uint_t  hash, i;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_ignore_line,
        sw_almost_done,
        sw_header_almost_done
    } state;

    /* the last '\0' is not needed because string is zero terminated */

    static u_char  lowcase[] =
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0-\0\0" "0123456789\0\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    state = ctx->state;
    hash = ctx->header_hash;
    i = ctx->lowcase_index;

    for (p = ctx->pos; p < ctx->end; p++) {
        ch = *p;

        switch (state) {

        /* first char */
        case sw_start:
            ctx->header_name_start = p;
            ctx->invalid_header = 0;

            switch (ch) {
            case CR:
                ctx->header_end = p;
                state = sw_header_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto header_done;
            default:
                state = sw_name;

                c = lowcase[ch];

                if (c) {
                    hash = ngx_hash(0, c);
                    ctx->lowcase_header[0] = c;
                    i = 1;
                    break;
                }

                if (ch == '_') {
                    if (allow_underscores) {
                        hash = ngx_hash(0, ch);
                        ctx->lowcase_header[0] = ch;
                        i = 1;

                    } else {
                        hash = 0;
                        i = 0;
                        ctx->invalid_header = 1;
                    }

                    break;
                }

                if (ch <= 0x20 || ch == 0x7f || ch == ':') {
                    ctx->header_end = p;
                    return NGX_HTTP_PARSE_INVALID_HEADER;
                }

                hash = 0;
                i = 0;
                ctx->invalid_header = 1;

                break;

            }
            break;

        /* header name */
        case sw_name:
            c = lowcase[ch];

            if (c) {
                hash = ngx_hash(hash, c);
                ctx->lowcase_header[i++] = c;
                i &= (NGX_HTTP_LC_HEADER_LEN - 1);
                break;
            }

            if (ch == '_') {
                if (allow_underscores) {
                    hash = ngx_hash(hash, ch);
                    ctx->lowcase_header[i++] = ch;
                    i &= (NGX_HTTP_LC_HEADER_LEN - 1);

                } else {
                    ctx->invalid_header = 1;
                }

                break;
            }

            if (ch == ':') {
                ctx->header_name_end = p;
                state = sw_space_before_value;
                break;
            }

            if (ch == CR) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            }

            if (ch <= 0x20 || ch == 0x7f) {
                ctx->header_end = p;
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }

            ctx->invalid_header = 1;

            break;

        /* space* before header value */
        case sw_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            case '\0':
                ctx->header_end = p;
                return NGX_HTTP_PARSE_INVALID_HEADER;
            default:
                ctx->header_start = p;
                state = sw_value;
                break;
            }
            break;

        /* header value */
        case sw_value:
            switch (ch) {
            case ' ':
                ctx->header_end = p;
                state = sw_space_after_value;
                break;
            case CR:
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto done;
            case '\0':
                ctx->header_end = p;
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }
            break;

        /* space* before end of header line */
        case sw_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            case '\0':
                ctx->header_end = p;
                return NGX_HTTP_PARSE_INVALID_HEADER;
            default:
                state = sw_value;
                break;
            }
            break;

        /* ignore header line */
        case sw_ignore_line:
            switch (ch) {
            case LF:
                state = sw_start;
                break;
            default:
                break;
            }
            break;

        /* end of header line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            case CR:
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }
            break;

        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }
        }
    }

    ctx->pos = p;
    ctx->state = state;
    ctx->header_hash = hash;
    ctx->lowcase_index = i;

    return NGX_AGAIN;

done:

    ctx->pos = p + 1;
    ctx->state = sw_start;
    ctx->header_hash = hash;
    ctx->lowcase_index = i;

    return NGX_OK;

header_done:

    ctx->pos = p + 1;
    ctx->state = sw_start;

    return NGX_HTTP_PARSE_HEADER_DONE;
}


static ngx_int_t
ngx_http_cgi_scan_header(ngx_http_cgi_ctx_t *ctx) {
    // TODO: impl this
    ctx->header_ready = 1;
    return NGX_OK;
}


static ngx_int_t
ngx_http_cgi_append_to_header_buf(ngx_http_cgi_ctx_t *ctx,
    u_char *buf, u_char *buf_end)
{
    size_t    buf_size;
    size_t    old_size;
    size_t    old_cap;
    size_t    new_cap;
    u_char   *new_buf;

    buf_size = buf_end - buf;
    if (buf_size == 0) {
        return NGX_OK;
    }

    if (ctx->header_buf.last + buf_size > ctx->header_buf.end) {
        old_size = ctx->header_buf.last - ctx->header_buf.start;
        old_cap = ctx->header_buf.end - ctx->header_buf.start;
        new_cap = old_cap ? old_cap * 2 : 1024;
        while (new_cap < old_size + buf_size) {
            new_cap *= 2;
        }
        new_buf = ngx_palloc(ctx->r->pool, new_cap);
        if (!new_buf) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (ctx->header_buf.start) {
            ngx_memcpy(new_buf, ctx->header_buf.start, old_size);
            ngx_pfree(ctx->r->pool, ctx->header_buf.start);
        }
        ctx->header_buf.start = ctx->header_buf.pos = new_buf;
        ctx->header_buf.last = ctx->header_buf.start + old_size;
        ctx->header_buf.end = ctx->header_buf.start + new_cap;
    }

    ctx->header_buf.last = ngx_cpymem(ctx->header_buf.last, buf, buf_size);
    return NGX_OK;
}


static ngx_int_t
ngx_http_cgi_append_body(ngx_http_cgi_ctx_t *ctx, u_char *buf, u_char *buf_end)
{
    ngx_http_request_t *r = ctx->r;
    ngx_buf_t          *tmp;

    if (buf_end == buf) {
        return NGX_OK;
    }

    tmp = ngx_create_temp_buf(r->pool, buf_end - buf);
    if (tmp == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    tmp->last = ngx_cpymem(tmp->pos, buf, buf_end - buf);

    if (ctx->cache_tail) {
        ctx->cache_tail->next = ngx_alloc_chain_link(r->pool);
        ctx->cache_tail = ctx->cache_tail->next;
    } else {
        ctx->cache = ctx->cache_tail = ngx_alloc_chain_link(r->pool);
    }
    if (!ctx->cache_tail) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->cache_tail->buf = tmp;
    ctx->cache_tail->next = NULL;
    return NGX_OK;
}


static ngx_int_t
ngx_http_cgi_add_output(ngx_http_cgi_ctx_t *ctx,
                        u_char *buf, u_char *buf_end) {
    ngx_int_t rc;

    if (buf_end == buf) {
        return NGX_OK;
    }

    if (!ctx->header_ready) {
        ctx->header_scan.pos = buf;
        ctx->header_scan.end = buf_end;
        for (;;) {
            rc = ngx_http_cgi_scan_header_line(&ctx->header_scan, 0);
            if (rc == NGX_AGAIN) {
                // we need more data, append current buf to header buf
                // and wait more
                rc = ngx_http_cgi_append_to_header_buf(ctx, buf, buf_end);
                if (rc != NGX_OK) {
                    return rc;
                }
                return NGX_OK;
            } else if (rc == NGX_OK) {
                // got a header line
                // we discard the result for now, because buf address may
                // changed when more data come in.
                continue;
            } else if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
                // we got the whole header
                // append part of buf to header buf
                rc = ngx_http_cgi_append_to_header_buf(
                        ctx, buf, ctx->header_scan.pos);
                if (rc != NGX_OK) {
                    return rc;
                }
                rc = ngx_http_cgi_scan_header(ctx);
                if (rc != NGX_OK) {
                    return rc;
                }
                // move the remain data from header to body
                return ngx_http_cgi_append_body(
                        ctx,
                        ctx->header_scan.pos,
                        buf_end);
            } else {
                return rc;
            }
        }
    } else {
        return ngx_http_cgi_append_body(ctx, buf, buf_end);
    }
}


static ngx_int_t
ngx_http_cgi_flush(ngx_http_cgi_ctx_t *ctx, ngx_flag_t eof) {
    ngx_buf_t   *tmp;
    ngx_chain_t *it;

    if (eof && !ctx->cache) {
        // alloc an empty buf, if there's nothing remain
        ctx->cache = ctx->cache_tail = ngx_alloc_chain_link(ctx->r->pool);
        tmp = ngx_calloc_buf(ctx->r->pool);
        if (tmp == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ctx->cache_tail->buf = tmp;
        ctx->cache_tail->next = NULL;
    }

    if (!ctx->cache) {
        return NGX_OK;
    }

    ctx->cache_tail->buf->last_in_chain = 1;
    ctx->cache_tail->buf->last_buf = eof;
    for (it = ctx->cache; it; it = it->next) {
        it->buf->flush = 1;
    }
    it = ctx->cache;
    ctx->cache = ctx->cache_tail = NULL;
    return ngx_http_output_filter(ctx->r, it);
}


static void
ngx_http_cgi_stdout_data_handler(ngx_event_t *ev) {
    ngx_connection_t   *c = ev->data;
    ngx_http_cgi_ctx_t *ctx = c->data;
    ngx_http_request_t *r = ctx->r;
    ngx_int_t           rc = NGX_OK;

    u_char buf[65536];
    int nread;

    for (;;) {
        nread = read(c->fd, buf, sizeof(buf));
        if (nread > 0) {
            rc = ngx_http_cgi_add_output(ctx, buf, buf + nread);
            if (rc != NGX_OK) {
                goto error;
            }
        } else if (nread == 0) {
            // end of file
            ngx_http_finalize_request(r, ngx_http_cgi_flush(ctx, 1));
            return;
        } else {
            if (ngx_errno == EAGAIN) {
                // wait for more data
                rc = ngx_http_cgi_flush(ctx, 0);
                if (rc != NGX_OK) {
                    goto error;
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
        // ngx_http_set_ctx(r, ctx, ngx_http_cgi_module);
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
