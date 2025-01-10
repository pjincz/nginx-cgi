
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


#define _strieq(str, exp) \
    (ngx_strncasecmp((str).data, (u_char*)(exp), (str).len) == 0)


typedef int pipe_pair_t[2];


typedef struct {
    ngx_flag_t enabled;
    ngx_str_t  path;
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
    ngx_array_t                   *script_env;

    pipe_pair_t                    pipe_stdout;
    ngx_connection_t              *c_stdout;

    ngx_buf_t                      header_buf;
    ngx_http_cgi_header_scan_t     header_scan;
    ngx_flag_t                     header_ready;
    ngx_flag_t                     header_sent;

    ngx_flag_t                     has_body;
    ngx_chain_t                   *cache;  // body sending cache
    ngx_chain_t                   *cache_tail;  // body sending cache
} ngx_http_cgi_ctx_t;


static ngx_int_t ngx_http_cgi_handler(ngx_http_request_t *r);
static void *ngx_http_cgi_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_cgi_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);


static ngx_command_t  ngx_http_cgi_commands[] = {

    { ngx_string("cgi"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cgi_loc_conf_t, enabled),
      NULL },

    { ngx_string("cgi_path"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cgi_loc_conf_t, path),
      NULL },

    // TODO: add following symbolic link?
    // TODO: add cgi_interpreter
    // TODO: add cgi_x_only
    // TODO: add cgi_index to generate content for directory?
    // TODO: add cgi_detailed_error_page?

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
        // Do not use `p` version here, to avoid security issue
        if (execve((char*)ctx->script.data, child_argv,
                ctx->script_env->elts) == -1) {
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
ngx_http_cgi_locate_script(ngx_http_cgi_ctx_t *ctx) {
    ngx_http_request_t        *r = ctx->r;
    ngx_http_core_loc_conf_t  *clcf;
    size_t                     strip_prefix;
    ngx_file_info_t            script_info;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uri: %V, alias: %d, root: %V", &r->uri,
                   clcf->alias, &clcf->root);

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
                   "cgi script path: %V", &ctx->script);

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

    return NGX_OK;
}


#define _add_env_const(ctx, name, val) *(char**)ngx_array_push(ctx->script_env) = (name "=" val)
static void _add_env_str(ngx_http_cgi_ctx_t *ctx, const char *name, const char *val, int val_len) {
    char *line;
    char *p;

    int name_len = ngx_strlen(name);

    if (val_len == -1) {
        val_len = ngx_strlen(val);
    }

    p = line = ngx_palloc(ctx->r->pool, name_len + 1 + val_len + 1);

    p = (char*)ngx_cpymem(p, name, name_len);
    *p++ = '=';
    p = (char*)ngx_cpymem(p, val, val_len);
    *p = 0;

    *(char**)ngx_array_push(ctx->script_env) = line;
}
static inline void _add_env_nstr(ngx_http_cgi_ctx_t *ctx, const char *name, ngx_str_t *str) {
    _add_env_str(ctx, name, (char*)str->data, str->len);
}
static inline void _add_env_int(ngx_http_cgi_ctx_t *ctx, const char *name, int val) {
    // int takes 11 characters at most
    char buf[16];
    sprintf(buf, "%d", val);
    _add_env_str(ctx, name, buf, -1);
}
static inline void _add_env_addr(ngx_http_cgi_ctx_t *ctx, const char *name, struct sockaddr * sa, socklen_t socklen) {
    ngx_int_t addr_len;
    // max ipv6 is 39 bytes
    // max sun_path is 108 bytes
    u_char addr[128];

    addr_len = ngx_sock_ntop(sa, socklen, addr, sizeof(addr), 0);
    _add_env_str(ctx, name, (char*)addr, addr_len);
}
static inline ngx_flag_t _add_env_port(ngx_http_cgi_ctx_t *ctx, const char *name, struct sockaddr * sa) {
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)sa;
        int port = ntohs(addr_in->sin_port);
        _add_env_int(ctx, name, port);
        return 1;
    } else if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)sa;
        int port = ntohs(addr_in6->sin6_port);
        _add_env_int(ctx, name, port);
        return 1;
    }
    return 0;
}


static ngx_int_t
ngx_http_cgi_prepare_env(ngx_http_cgi_ctx_t *ctx) {
    // there's 17 standard vars in rfc 3875
    // apache2 exports 24 vars by default
    // 32 is a good choose, can fit all envs without resize in most cases
    const int                  init_array_size = 32;
    ngx_http_request_t        *r = ctx->r;
    ngx_connection_t          *con = r->connection;
    ngx_http_cgi_loc_conf_t   *cgi_lcf;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *srcf;

    ngx_list_part_t           *part;
    ngx_uint_t                 i;
    ngx_table_elt_t           *v;

    cgi_lcf = ngx_http_get_module_loc_conf(r, ngx_http_cgi_module);
    if (cgi_lcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    srcf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    if (srcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->script_env = ngx_array_create(
            ctx->r->pool, init_array_size, sizeof(char*));
    if (ctx->script_env == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    _add_env_const(ctx, "GATEWAY_INTERFACE", "CGI/1.1");

    _add_env_nstr(ctx, "PATH", &cgi_lcf->path);

    // TODO: should we convert DOCUMENT_ROOT to abs path here?
    _add_env_nstr(ctx, "DOCUMENT_ROOT", &clcf->root);

    _add_env_nstr(ctx, "QUERY_STRING", &r->args);

    _add_env_addr(ctx, "REMOTE_ADDR", con->sockaddr, con->socklen);
    _add_env_port(ctx, "REMOTE_PORT", con->sockaddr);

    _add_env_nstr(ctx, "REQUEST_METHOD", &r->method_name);

    // TODO: need verify
    if (r->http_connection->ssl) {
        _add_env_const(ctx, "REQUEST_SCHEME", "https");
    } else {
        _add_env_const(ctx, "REQUEST_SCHEME", "http");
    }

    // TODO: check whether `r->uri` changed by rewrite plugin
    _add_env_nstr(ctx, "REQUEST_URI", &r->uri);
    _add_env_nstr(ctx, "SCRIPT_NAME", &r->uri);

    // TODO: should we convert SCRIPT_FILENAME to abs path here?
    _add_env_nstr(ctx, "SCRIPT_FILENAME", &ctx->script);

    {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        if (getsockname(con->fd, (struct sockaddr *)&addr, &addr_len) != -1) {
            _add_env_addr(ctx, "SERVER_ADDR", (void*)&addr, addr_len);
            _add_env_port(ctx, "SERVER_PORT", (void*)&addr);
        }
    }

    // TODO: SERVER_NAME not work
    _add_env_nstr(ctx, "SERVER_NAME", &srcf->server_name);

    _add_env_nstr(ctx, "SERVER_PROTOCOL", &r->http_protocol);

    _add_env_const(ctx, "SERVER_SOFTWARE", "nginx/" NGINX_VERSION);

    // go through incoming headers, and convert add them to env
    part = &r->headers_in.headers.part;
    v = part->elts;
    for (i = 0;; ++i) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            v = part->elts;
            i = 0;
        }

        if (_strieq(v[i].key, "Accept")) {
            _add_env_nstr(ctx, "HTTP_ACCEPT", &v[i].value);
        } else if (_strieq(v[i].key, "Host")) {
            _add_env_nstr(ctx, "HTTP_HOST", &v[i].value);
        } else if (_strieq(v[i].key, "User-Agent")) {
            _add_env_nstr(ctx, "HTTP_USER_AGENT", &v[i].value);
        } else if ((v[i].key.data[0] == 'X' || v[i].key.data[0] == 'x')
                   && v[i].key.data[1] == '-') {
            // extension headers
            u_char *name = ngx_palloc(r->pool, v[i].key.len + 1);
            ngx_memcpy(name, v[i].key.data, v[i].key.len);
            name[v[i].key.len] = 0;

            // replace `-` with `_`, and convert to uppercase
            for (size_t i = 0; i < v[i].key.len; ++i) {
                name[i] = ngx_toupper(name[i]);
                if (name[i] == '-') {
                    name[i] = '_';
                }
            }

            _add_env_nstr(ctx, (char*)name, &v[i].value);
        }
    }

    return NGX_OK;
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
    ngx_http_cgi_header_scan_t *scan = &ctx->header_scan;
    ngx_http_request_t         *r = ctx->r;
    ngx_int_t                   rc;
    ngx_str_t                   name;
    ngx_str_t                   line;
    ngx_table_elt_t            *h;

    // reset scaning ctx, and scan again
    ngx_memzero(scan, sizeof(*scan));
    scan->pos = ctx->header_buf.pos;
    scan->end = ctx->header_buf.end;

    for (;;) {
        rc = ngx_http_cgi_scan_header_line(scan, 0);

        if (rc == NGX_OK) {
            name.data = scan->header_name_start;
            name.len = scan->header_name_end - scan->header_name_start;
            line.data = scan->header_name_start;
            line.len = scan->header_end - scan->header_name_start;

            if (_strieq(name, "Keep-Alive") ||
                _strieq(name, "Transfer-Encoding") ||
                _strieq(name, "TE") ||
                _strieq(name, "Connection") ||
                _strieq(name, "Trailer") ||
                _strieq(name, "Upgrade")) {
                ngx_log_error(NGX_LOG_ERR, ctx->r->connection->log, 0,
                        "hop-by-hop header is not avalid in cgi response: %V",
                        &line);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            } else if (_strieq(name, "Status")) {
                r->headers_out.status_line.len =
                        scan->header_end - scan->header_start;
                r->headers_out.status_line.data = ngx_palloc(
                        r->pool, r->headers_out.status_line.len);
                if (r->headers_out.status_line.data == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                ngx_memcpy(r->headers_out.status_line.data, scan->header_start,
                        r->headers_out.status_line.len);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                            "cgi status line: \"%V\"",
                            &r->headers_out.status_line);
            } else if (_strieq(name, "Content-Length")) {
                r->headers_out.content_length_n = ngx_atoi(scan->header_start,
                        scan->header_end - scan->header_start);
                if (r->headers_out.content_length_n == NGX_ERROR) {
                    ngx_log_error(NGX_LOG_ERR, ctx->r->connection->log, 0,
                            "invalid cgi head line: %V", &line);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            } else {
                // forward other headers
                h = ngx_list_push(&r->headers_out.headers);
                if (h == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                h->hash = scan->header_hash;

                h->key.len = scan->header_name_end - scan->header_name_start;
                h->value.len = scan->header_end - scan->header_start;

                h->key.data = ngx_pnalloc(r->pool,
                                h->key.len + 1 + h->value.len + 1 + h->key.len);
                if (h->key.data == NULL) {
                    h->hash = 0;
                    return NGX_ERROR;
                }

                h->value.data = h->key.data + h->key.len + 1;
                h->lowcase_key = h->key.data + h->key.len + 1
                                + h->value.len + 1;

                ngx_memcpy(h->key.data, scan->header_name_start, h->key.len);
                h->key.data[h->key.len] = '\0';
                ngx_memcpy(h->value.data, scan->header_start, h->value.len);
                h->value.data[h->value.len] = '\0';

                if (h->key.len == scan->lowcase_index) {
                    ngx_memcpy(h->lowcase_key, scan->lowcase_header,
                            h->key.len);
                } else {
                    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
                }

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                            "http cgi header: \"%V: %V\"",
                            &h->key, &h->value);
            }
        } else if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            break;
        } else {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    // default status is 200, if cgi reponse not sepcified one
    if (r->headers_out.status_line.data == NULL) {
        r->headers_out.status = 200;
    }
    
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
    ctx->has_body = 1;
    return NGX_OK;
}


static ngx_int_t
ngx_http_cgi_add_output(ngx_http_cgi_ctx_t *ctx,
                        u_char *buf, u_char *buf_end) {
    ngx_int_t   rc;
    ngx_str_t   str;
    u_char     *tmp_ptr;

    if (buf_end == buf) {
        return NGX_OK;
    }

    if (!ctx->header_ready) {
        ctx->header_scan.pos = buf;
        ctx->header_scan.end = buf_end;
        for (;;) {
            rc = ngx_http_cgi_scan_header_line(&ctx->header_scan, 0);
            if (ctx->header_scan.invalid_header) {
                rc = NGX_HTTP_PARSE_INVALID_HEADER;
            }
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
                // ctx will be reset in ngx_http_cgi_scan_header
                // save ctx->header_scan.pos for later use
                tmp_ptr = ctx->header_scan.pos;
                rc = ngx_http_cgi_scan_header(ctx);
                if (rc != NGX_OK) {
                    return rc;
                }
                // move the remain data from header to body
                return ngx_http_cgi_append_body(ctx, tmp_ptr, buf_end);
            } else if (rc == NGX_HTTP_PARSE_INVALID_HEADER) {
                str.data = ctx->header_scan.header_name_start;
                str.len = ctx->header_scan.header_end -
                          ctx->header_scan.header_name_start;
                ngx_log_error(NGX_LOG_ERR, ctx->r->connection->log, 0,
                      "cgi invalid header: %V", &str);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            } else {
                return rc;
            }
        }
    } else {
        return ngx_http_cgi_append_body(ctx, buf, buf_end);
    }
}


static ngx_int_t
ngx_http_cgi_calc_content_length(ngx_http_cgi_ctx_t *ctx) {
    ngx_chain_t *it;
    ngx_int_t    len = 0;
    
    for (it = ctx->cache; it; it = it->next) {
        len += it->buf->end - it->buf->start;
    }

    return len;
}

static ngx_int_t
ngx_http_cgi_flush(ngx_http_cgi_ctx_t *ctx, ngx_flag_t eof) {
    ngx_buf_t   *tmp;
    ngx_chain_t *it;
    ngx_int_t    rc = NGX_OK;

    // do nothing, if no pending cache and not finish
    if (!ctx->cache && !eof) {
        return NGX_OK;
    }

    if (!ctx->header_sent) {
        if (eof) {
            // we didn't send out header yet, but we reaches the eof
            // we can caculate the content length directly to avoid chunk mode
            ctx->r->headers_out.content_length_n = \
                    ngx_http_cgi_calc_content_length(ctx);
            if (ctx->r->headers_out.content_length_n == 0) {
                ctx->r->header_only = 1;
            }
        }
        rc = ngx_http_send_header(ctx->r);
        if (rc == NGX_ERROR || rc > NGX_OK) {
            return rc;
        }
        ctx->header_sent = 1;
    }

    if (ctx->has_body && !ctx->cache && eof) {
        // we have body before, but there's no pending cache here.
        // in this case, we need to send an empty package.
        ctx->cache = ctx->cache_tail = ngx_alloc_chain_link(ctx->r->pool);
        tmp = ngx_calloc_buf(ctx->r->pool);
        if (tmp == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ctx->cache_tail->buf = tmp;
        ctx->cache_tail->next = NULL;
    }

    if (ctx->cache) {
        ctx->cache_tail->buf->last_in_chain = 1;
        ctx->cache_tail->buf->last_buf = eof;
        for (it = ctx->cache; it; it = it->next) {
            it->buf->flush = 1;
        }
        it = ctx->cache;
        ctx->cache = ctx->cache_tail = NULL;
        rc = ngx_http_output_filter(ctx->r, it);
    }

    return rc;
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
    ngx_http_cgi_ctx_t        *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cgi handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_cgi_module);
    if (ctx == NULL) {
        ctx = ngx_http_cgi_ctx_create(r->pool);
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        // ngx_http_set_ctx(r, ctx, ngx_http_cgi_module);
    }

    ctx->r = r;

    rc = ngx_http_cgi_locate_script(ctx);
    if (rc != NGX_OK) {
        return rc;
    }

    // TODO: grab request body, and sent to CGI script
    if (ngx_http_discard_request_body(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_cgi_prepare_env(ctx);
    if (rc != NGX_OK) {
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
    ngx_conf_merge_str_value(conf->path, prev->path,
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");

    if (conf->enabled) {
        ngx_http_core_loc_conf_t  *clcf;

        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

        // TODO: stop `location /cgi-bin` be set here, it will be a security
        // vulnerability

        clcf->handler = ngx_http_cgi_handler;
    }

    return NGX_CONF_OK;
}
