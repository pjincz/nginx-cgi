
/*
 * Copyright (C) Chizhong Jin
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <assert.h>


#define STACK_SIZE                  4096

#define PIPE_READ_END      0
#define PIPE_WRITE_END     1

#define CGI_STDERR_UNSET  -1
#define CGI_STDERR_PIPE   -2

#define CGI_RDNS_OFF       0
#define CGI_RDNS_ON        1
#define CGI_RDNS_DOUBLE    2

#define CGI_DNS_TIMEOUT    30000  // 30 seconds


#define _strieq(str, exp) \
    (ngx_strncasecmp((str).data, (u_char*)(exp), (str).len) == 0)
#define _ngx_str_last_ch(nstr) \
    ((nstr).len > 0 ? (nstr).data[(nstr).len - 1] : 0)


typedef int pipe_pair_t[2];


typedef struct {
    ngx_flag_t     enabled;
    ngx_str_t      path;
    ngx_flag_t     strict_mode;
    ngx_array_t   *interpreter;  // array<char *>
    ngx_flag_t     x_only;
    ngx_fd_t       cgi_stderr;
    ngx_int_t      rdns;
} ngx_http_cgi_loc_conf_t;


typedef struct {
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
    ngx_http_core_loc_conf_t      *clcf;
    ngx_http_cgi_loc_conf_t       *conf;

    // script: path to cgi script
    // path_info: subpath under script, see rfc3875 4.1.5
    // path_translated: translated subpath, see rfc3875 4.1.6
    ngx_str_t                      script;      // c compatible
    ngx_str_t                      path_info;
    ngx_str_t                      path_translated;
    ngx_str_t                      remote_host;

    ngx_array_t                   *cmd;         // array<char*> with tail null
    ngx_array_t                   *env;         // array<char*> with tail null

    pipe_pair_t                    pipe_stdin;
    pipe_pair_t                    pipe_stdout;
    pipe_pair_t                    pipe_stderr;

    ngx_connection_t              *c_stdin;
    ngx_connection_t              *c_stdout;
    ngx_connection_t              *c_stderr;

    ngx_buf_t                      header_buf;
    ngx_http_cgi_header_scan_t     header_scan;
    ngx_flag_t                     header_ready;
    ngx_flag_t                     header_sent;

    ngx_flag_t                     has_body;
    ngx_chain_t                   *cache;  // body sending cache
    ngx_chain_t                   *cache_tail;  // body sending cache
} ngx_http_cgi_ctx_t;


typedef struct {
    ngx_http_cgi_ctx_t *ctx;
    char               *child_stack;
    char               *grandchild_stack;

    pid_t               grandchild_pid;

    const char         *descendant_error;
    ngx_int_t           descendant_errno;
} ngx_http_cgi_spawn_shared_ctx_t;


static ngx_int_t ngx_http_cgi_handler_1(ngx_http_request_t *r);
static void *ngx_http_cgi_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_cgi_merge_loc_conf(
    ngx_conf_t *cf, void *parent, void *child);
static char * ngx_http_cgi_set_interpreter(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_cgi_set_stderr(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_cgi_set_rdns(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_cgi_commands[] = {

    // Enable or disable cgi module on giving location block
    // Default: off
    {
        ngx_string("cgi"),
        NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_cgi_loc_conf_t, enabled),
        NULL
    },

    // Change cgi script PATH environment variable
    // Default: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    {
        ngx_string("cgi_path"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_cgi_loc_conf_t, path),
        NULL
    },

    // Enable or disable strict mode
    // When strict mode turns on, bad cgi header will cause 500 error
    // When strict mode turns off, bad cgi header be forward as it is
    // Default: on
    {
        ngx_string("cgi_strict"),
        NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_cgi_loc_conf_t, strict_mode),
        NULL
    },

    // Set interpreter and interpreter args for cgi script
    // When this option is not empty, cgi script will be run be giving
    // interpreter. Otherwise, script will be executed directly.
    // Default: empty
    {
        ngx_string("cgi_interpreter"),
        NGX_HTTP_LOC_CONF | NGX_CONF_ANY,
        ngx_http_cgi_set_interpreter,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_cgi_loc_conf_t, interpreter),
        NULL
    },

    // Enable or disable x-only mode
    // When this option turns on, only file with x perm will be treated as cgi
    // script. Otherwise 403 will be returned. If this option turns off, the cgi
    // plugin will try to execute the script no matter whther x perm exists.
    // Note: this option only meanful if `cgi_interpreter` is set.
    // Default: on
    {
        ngx_string("cgi_x_only"),
        NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_cgi_loc_conf_t, x_only),
        NULL
    },

    // Redirect cgi stderr to giving file
    // By default, nginx-cgi grab cgi script's stderr output and dump it to
    // nginx log. But this action is somewhat expensive, because it need to
    // create an extra connection to listen stderr output. If you want to avoid
    // this, you can use this option to redirect cgi script's stderr output to a
    // file. Or you can even discard all stderr output by redirect to
    // `/dev/null`. Also you can use this to redirect all stderr output to
    // nginx's stderr by set it as `/dev/stderr`.
    {
        ngx_string("cgi_stderr"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_http_cgi_set_stderr,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_cgi_loc_conf_t, cgi_stderr),
        NULL
    },

    // Enable or disable reverse dns
    // cgi_rdns <off|on|double>
    // off: disable rdns feature
    // on: run reverse dns before launching cgi script, and pass rdns to cgi
    //     script via `REMOTE_HOST` environment variable.
    // double: after reverse dns, do a forward dns again to check the rdns
    //         result. it result matches, pass result as `REMOTE_HOST`.
    // In order to use this, you need to setup a `resolver` in nginx too.
    //
    // author notes: do not enable this option, it will makes every request
    //               slower. this feature can be easily implemented by `dig -x`
    //               or `nslookup` in script when need. the only reason I impled
    //               this is just to make the module fully compliant with the
    //               rfc3874 standard.
    {
        ngx_string("cgi_rdns"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_http_cgi_set_rdns,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_cgi_loc_conf_t, rdns),
        NULL
    },


    // TODO: add an option to disable following symbolic link?
    // TODO: add an option to report cgi error to client side?

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
    if (ctx->pipe_stdin[0] != -1) {
        close(ctx->pipe_stdin[0]);
    }
    if (ctx->pipe_stdin[1] != -1) {
        close(ctx->pipe_stdin[1]);
    }
    if (ctx->pipe_stdout[0] != -1) {
        close(ctx->pipe_stdout[0]);
    }
    if (ctx->pipe_stdout[1] != -1) {
        close(ctx->pipe_stdout[1]);
    }
    if (ctx->pipe_stderr[0] != -1) {
        close(ctx->pipe_stderr[0]);
    }
    if (ctx->pipe_stderr[1] != -1) {
        close(ctx->pipe_stderr[1]);
    }

    if (ctx->c_stdin) {
        ngx_close_connection(ctx->c_stdin);
    }
    if (ctx->c_stdout) {
        ngx_close_connection(ctx->c_stdout);
    }
    if (ctx->c_stderr) {
        ngx_close_connection(ctx->c_stderr);
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

    ctx->pipe_stdin[0] = -1;
    ctx->pipe_stdin[1] = -1;
    ctx->pipe_stdout[0] = -1;
    ctx->pipe_stdout[1] = -1;
    ctx->pipe_stderr[0] = -1;
    ctx->pipe_stderr[1] = -1;

    return ctx;
}


static int ngx_http_cgi_grandchild_proc(void *arg) {
    ngx_http_cgi_spawn_shared_ctx_t *spawn_ctx = arg;
    ngx_http_cgi_ctx_t *ctx = spawn_ctx->ctx;
    char **cmd = ctx->cmd->elts;
    char **env = ctx->env->elts;

    // Do not use `p` version here, to avoid security issue
    if (execve(cmd[0], cmd, env) == -1) {
        spawn_ctx->descendant_error = "execve";
        spawn_ctx->descendant_errno = errno;
        _exit(0);
    }

    // never reaches here, just for elimating compiler warning
    return 0;
}


static int ngx_http_cgi_child_proc(void *arg) {
    ngx_http_cgi_spawn_shared_ctx_t *spawn_ctx = arg;
    ngx_http_cgi_ctx_t *ctx = spawn_ctx->ctx;
    int wstatus = 0;
    int rc = 0;

    close(0);
    close(1);
    close(2);

    // if there's no body, pipe_stdin will not created for saving fd
    if (ctx->pipe_stdin[PIPE_READ_END] != -1) {
        dup2(ctx->pipe_stdin[PIPE_READ_END], 0);
    }

    dup2(ctx->pipe_stdout[PIPE_WRITE_END], 1);

    if (ctx->conf->cgi_stderr >= 0) {
        dup2(ctx->conf->cgi_stderr, 2);
    } else if (ctx->pipe_stderr[PIPE_WRITE_END] >= 0) {
        dup2(ctx->pipe_stderr[PIPE_WRITE_END], 2);
    }

    // close all fds >= 3 to prevent inherit connection from nginx
    // this is important, because nginx doesn't mark all connections with
    // O_CLOEXEC. as a result, a long run cgi script will take ownship
    // of connections it closed by nginx, and causes client hangs.
    closefrom(3);

    // fork again to detch
    // again we cannot use fork/vfork here. The forked child process still
    // has signal handler for SIGCHLD
    spawn_ctx->grandchild_pid = clone(ngx_http_cgi_grandchild_proc,
            spawn_ctx->grandchild_stack + STACK_SIZE,
            CLONE_VM | CLONE_VFORK, spawn_ctx);

    if (spawn_ctx->grandchild_pid == -1) {
        spawn_ctx->descendant_error = "clone";
        spawn_ctx->descendant_errno = errno;
        _exit(0);
    }

    // clone returns after _exit or exec, if it failed, we can get the error
    // immediently.
    //  __WCLONE is required to wait cloned process
    rc = waitpid(spawn_ctx->grandchild_pid, &wstatus, WNOHANG | __WCLONE);
    if (rc > 0) {
        // grandchild exec failed, forward exit code
        _exit(WEXITSTATUS(wstatus));
    } else if (rc == 0) {
        // grandchild is running, that's good!
        _exit(0);
    } else {
        // error happens on waitpid, that's not important, just quit
        _exit(0);
    }
}


static ngx_int_t
ngx_http_cgi_locate_script(ngx_http_cgi_ctx_t *ctx) {
    ngx_http_request_t        *r = ctx->r;
    ngx_file_info_t            script_info;
    int                        uri_remaining = 0;
    size_t                     root_len;
    ngx_str_t                  orig_uri;

    ngx_flag_t                 regular_location;

#if (NGX_PCRE)
    regular_location = !ctx->clcf->named && !ctx->clcf->regex;
#else
    regular_location = !ctx->clcf->named;
#endif

    if (regular_location) {
        if (_ngx_str_last_ch(ctx->clcf->name) != '/') {
            // dangerous location, not finished with `/`
            if (r->uri.len > ctx->clcf->name.len &&
                r->uri.data[ctx->clcf->name.len] != '/')
            {
                // if you have a location `/cgi-bin` with cgi turns on,
                // /cgi-bin-something.sh should not be considered as a cgi
                // script for security reason
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "trying access file beyond location dir");
                return NGX_HTTP_FORBIDDEN;
            }
        }
    }

    if (!ngx_http_map_uri_to_path(r, &ctx->script, &root_len, 0))
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    // ngx_http_map_uri_to_path returns contains an extra `0` for c compatiblity
    // let's remove it here
    if (ctx->script.len > 0 && ctx->script.data[ctx->script.len - 1] == 0) {
        ctx->script.len -= 1;
    }

    for (;;) {
        // convert string to c string
        ctx->script.data[ctx->script.len] = 0;

        if (ngx_file_info(ctx->script.data, &script_info) == -1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                        "stat \"%V\" failed", &ctx->script);
            if (ngx_errno == EACCES) {
                return NGX_HTTP_FORBIDDEN;
            } else if (ngx_errno == ENOTDIR) {
                // remove a level from script path
                while (_ngx_str_last_ch(ctx->script) != '/') {
                    ctx->script.len -= 1;
                    uri_remaining += 1;
                }
                while (_ngx_str_last_ch(ctx->script) == '/') {
                    ctx->script.len -= 1;
                    uri_remaining += 1;
                }
                if (ctx->script.len <= root_len) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                } else {
                    continue;
                }
            } else if (ngx_errno == ENOENT) {
                return NGX_HTTP_NOT_FOUND;
            }
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        } else {
            break;
        }
    }

    if (uri_remaining > 0) {
        ctx->path_info.data = r->uri.data + r->uri.len - uri_remaining;
        ctx->path_info.len = uri_remaining;

        // fake r->uri, and change it back later
        orig_uri = r->uri;
        r->uri = ctx->path_info;
        if (!ngx_http_map_uri_to_path(r, &ctx->path_translated, &root_len, 0))
        {
            r->uri = orig_uri;
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        r->uri = orig_uri;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cgi script path: %V, path_info: %V",
                   &ctx->script, &ctx->path_info);

    if (!ngx_is_file(&script_info)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "run cgi \"%V\" failed, not regular file", &ctx->script);
        return NGX_HTTP_NOT_FOUND;
    }

    if (ctx->conf->x_only && access((char*)ctx->script.data, X_OK) != 0) {
        // no execute permission
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "run cgi \"%V\" failed, no x permission", &ctx->script);
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_cgi_prepare_cmd(ngx_http_cgi_ctx_t *ctx) {
    int cmd_list_size = ctx->conf->interpreter ?
            ctx->conf->interpreter->nelts + 2 : 2;

    ctx->cmd = ngx_array_create(ctx->r->pool, cmd_list_size, sizeof(char*));
    if (ctx->cmd == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ctx->conf->interpreter) {
        ngx_memcpy(
            ngx_array_push_n(ctx->cmd, ctx->conf->interpreter->nelts),
            ctx->conf->interpreter->elts,
            sizeof(char *) * ctx->conf->interpreter->nelts);
    }

    *(u_char**)ngx_array_push(ctx->cmd) = ctx->script.data;

    // an extra NULL string, required by exec
    *(u_char**)ngx_array_push(ctx->cmd) = NULL;

    return NGX_OK;
}


#define _add_env_const(ctx, name, val) *(char**)ngx_array_push(ctx->env) = (name "=" val)
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

    *(char**)ngx_array_push(ctx->env) = line;
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
    // there's 17 standard vars in rfc3875
    // apache2 exports 24 vars by default
    // 32 is a good choose, can fit all envs without resize in most cases
    const int                  init_array_size = 32;
    ngx_http_request_t        *r = ctx->r;
    ngx_connection_t          *con = r->connection;
    ngx_http_core_srv_conf_t  *srcf;

    struct sockaddr_storage    local_addr;
    socklen_t                  local_addr_len;

    ngx_list_part_t           *part;
    ngx_uint_t                 i;
    ngx_table_elt_t           *v;

    srcf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    if (srcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    local_addr_len = sizeof(local_addr);
    if (getsockname(con->fd, (void *)&local_addr, &local_addr_len) == -1) {
        local_addr_len = 0;
    }

    ctx->env = ngx_array_create(
            ctx->r->pool, init_array_size, sizeof(char*));
    if (ctx->env == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    _add_env_const(ctx, "GATEWAY_INTERFACE", "CGI/1.1");

    _add_env_nstr(ctx, "PATH", &ctx->conf->path);

    _add_env_nstr(ctx, "DOCUMENT_ROOT", &ctx->clcf->root);

    _add_env_nstr(ctx, "QUERY_STRING", &r->args);

    _add_env_addr(ctx, "REMOTE_ADDR", con->sockaddr, con->socklen);
    _add_env_port(ctx, "REMOTE_PORT", con->sockaddr);
    if (ctx->remote_host.len > 0) {
        _add_env_nstr(ctx, "REMOTE_HOST", &ctx->remote_host);
    }

    _add_env_nstr(ctx, "REQUEST_METHOD", &r->method_name);

    if (r->http_connection->ssl) {
        _add_env_const(ctx, "REQUEST_SCHEME", "https");
    } else {
        _add_env_const(ctx, "REQUEST_SCHEME", "http");
    }

    // unparsed_uri stores uri before rewriting
    // uri stores uri after rewriting
    _add_env_nstr(ctx, "REQUEST_URI", &r->unparsed_uri);
    _add_env_str(ctx, "SCRIPT_NAME",
                 (char*)r->uri.data, r->uri.len - ctx->path_info.len);

    _add_env_nstr(ctx, "SCRIPT_FILENAME", &ctx->script);

    if (local_addr_len > 0) {
        _add_env_addr(ctx, "SERVER_ADDR", (void*)&local_addr, local_addr_len);
        _add_env_port(ctx, "SERVER_PORT", (void*)&local_addr);
    }

    if (srcf->server_name.len > 0) {
        _add_env_nstr(ctx, "SERVER_NAME", &srcf->server_name);
    } else if (local_addr_len > 0) {
        _add_env_addr(ctx, "SERVER_NAME", (void*)&local_addr, local_addr_len);
    }

    _add_env_nstr(ctx, "SERVER_PROTOCOL", &r->http_protocol);

    _add_env_const(ctx, "SERVER_SOFTWARE", "nginx/" NGINX_VERSION);

    if (ctx->path_info.len > 0) {
        _add_env_nstr(ctx, "PATH_INFO", &ctx->path_info);
    }
    if (ctx->path_translated.len > 0) {
        _add_env_nstr(ctx, "PATH_TRANSLATED", &ctx->path_translated);
    }

    // this field appears only if an auth module has been setup, and runs before
    // cgi module. that's good, it has the same behaviour with apache2.
    if (ctx->r->headers_in.user.len) {
        _add_env_nstr(ctx, "REMOTE_USER", &ctx->r->headers_in.user);

        if (ctx->r->headers_in.authorization) {
            ngx_str_t auth_type = ctx->r->headers_in.authorization->value;
            for (size_t i = 0; i < auth_type.len; ++i) {
                if (auth_type.data[i] == ' ') {
                    auth_type.len = i;
                    break;
                }
            }
            _add_env_nstr(ctx, "AUTH_TYPE", &auth_type);
        }
    }

    // other rfc3875 vars:
    //   REMOTE_IDENT: no plan to support, due to security reason

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

        if (_strieq(v[i].key, "Content-Length")) {
            _add_env_nstr(ctx, "CONTENT_LENGTH", &v[i].value);
        } else if (_strieq(v[i].key, "Content-Type")) {
            _add_env_nstr(ctx, "CONTENT_TYPE", &v[i].value);
        } else if (_strieq(v[i].key, "Authorization")) {
            // Authorization should not be forwarded
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
        } else {
            // protocal headers
            // do we need to whitelist known http headers here?
            u_char *name = ngx_palloc(r->pool, 5 + v[i].key.len + 1);
            ngx_memcpy(name, "HTTP_", 5);
            ngx_memcpy(name + 5, v[i].key.data, v[i].key.len);
            name[5 + v[i].key.len] = 0;

            // replace `-` with `_`, and convert to uppercase
            for (u_char *p = name; *p; ++p) {
                *p = ngx_toupper(*p);
                if (*p == '-') {
                    *p = '_';
                }
            }

            _add_env_nstr(ctx, (char*)name, &v[i].value);
        }
    }

    // an extra null string, required by exec
    *(char**)ngx_array_push(ctx->env) = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_cgi_spawn_child_process(ngx_http_cgi_ctx_t *ctx) {
    ngx_http_cgi_spawn_shared_ctx_t *spawn_ctx = 0;
    pid_t                            child_pid = 0;
    int                              wstatus = 0;
    ngx_int_t                        rc = NGX_OK;
    ngx_http_request_t              *r = ctx->r;

    // don't create stdin pipe if there's no body to save connections
    if ((r->request_body && r->request_body->bufs) || r->reading_body) {
        if (pipe(ctx->pipe_stdin) == -1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                    "pipe");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto cleanup;
        }
    }

    if (pipe(ctx->pipe_stdout) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno, "pipe");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }

    if (ctx->conf->cgi_stderr == CGI_STDERR_PIPE) {
        if (pipe(ctx->pipe_stderr) == -1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno, "pipe");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto cleanup;
        }
    }

    spawn_ctx = mmap(NULL, sizeof(*spawn_ctx),
            PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!spawn_ctx) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno, "mmap");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }
    ngx_memzero(spawn_ctx, sizeof(*spawn_ctx));

    spawn_ctx->ctx = ctx;
    spawn_ctx->child_stack = malloc(STACK_SIZE);
    spawn_ctx->grandchild_stack = malloc(STACK_SIZE);
    if (!spawn_ctx->child_stack || !spawn_ctx->grandchild_stack) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno, "malloc");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }

    // use clone instead of fork/vfork to avoid SIGCHLD be sent to nginx here
    child_pid = clone(ngx_http_cgi_child_proc,
            spawn_ctx->child_stack + STACK_SIZE,
            CLONE_VM | CLONE_VFORK, spawn_ctx);
    if (child_pid == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "run cgi \"%V\" failed", &ctx->script);
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }
    if (spawn_ctx->descendant_error) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log,
                      spawn_ctx->descendant_errno, spawn_ctx->descendant_error);
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "cgi process: %d", spawn_ctx->grandchild_pid);

    // child process will exit immediately after forking grandchild
    //  __WCLONE is required to wait cloned process
    waitpid(child_pid, &wstatus, WNOHANG | __WCLONE);

    if (ctx->pipe_stdin[PIPE_READ_END] != -1) {
        close(ctx->pipe_stdin[PIPE_READ_END]);
        ctx->pipe_stdin[PIPE_READ_END] = -1;
    }
    if (ctx->pipe_stdout[PIPE_WRITE_END] != -1) {
        close(ctx->pipe_stdout[PIPE_WRITE_END]);
        ctx->pipe_stdout[PIPE_WRITE_END] = -1;
    }
    if (ctx->pipe_stderr[PIPE_WRITE_END] != -1) {
        close(ctx->pipe_stderr[PIPE_WRITE_END]);
        ctx->pipe_stderr[PIPE_WRITE_END] = -1;
    }

cleanup:
    if (spawn_ctx) {
        if (spawn_ctx->child_stack) {
            free(spawn_ctx->child_stack);
        }
        if (spawn_ctx->grandchild_stack) {
            free(spawn_ctx->grandchild_stack);
        }
        munmap(spawn_ctx, sizeof(*spawn_ctx));
    }
    return rc;
}


// This function is copied from ngx_http_parse_header_line
// The original version needs ngx_http_request_t, that's a trouble to use
// it for other purpose. So I forked it here.
ngx_int_t
ngx_http_cgi_scan_header_line(ngx_http_cgi_header_scan_t *ctx)
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
        rc = ngx_http_cgi_scan_header_line(scan);

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

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "header ready");
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
            rc = ngx_http_cgi_scan_header_line(&ctx->header_scan);
            if (ctx->header_scan.invalid_header && ctx->conf->strict_mode) {
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
        if (!ctx->header_ready) {
            // header is not ready, the cgi output is malformed
            ngx_log_error(NGX_LOG_ERR, ctx->r->connection->log, 0,
                    "cgi header not existing or not finished");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

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
ngx_http_cgi_stdin_data_handler(ngx_event_t *ev) {
    ngx_connection_t   *c = ev->data;
    ngx_http_cgi_ctx_t *ctx = c->data;
    ngx_http_request_t *r = ctx->r;
    ngx_chain_t        *chain;
    ngx_buf_t          *buf;
    ngx_flag_t          pipe_broken = 0;
    ngx_flag_t          io_error = 0;

    int nwrite;

    while (r->request_body && r->request_body->bufs) {
        chain = r->request_body->bufs;
        buf = chain->buf;

        nwrite = write(c->fd, buf->pos, buf->last - buf->pos);

        if (nwrite >= 0) {
            buf->pos += nwrite;
            if (buf->pos == buf->last) {
                if (buf->temporary) {
                    ngx_pfree(r->pool, buf);
                }

                r->request_body->bufs = chain->next;
                ngx_pfree(r->pool, chain);
            }
        } else {
            if (ngx_errno == EAGAIN) {
                // io buf is full
                break;
            } else if (ngx_errno == EPIPE) {
                // peer closed
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log,
                        ngx_errno, "stdin closed");
                pipe_broken = 1;
                break;
            } else {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                        "stdin write");
                io_error = 1;
                break;
            }
        }
    }

    if (!r->request_body->bufs && !r->reading_body) {
        // passed all request body
        ngx_close_connection(c);
        ctx->c_stdin = NULL;
    } else if (pipe_broken || io_error) {
        // cgi close stdin or io error
        ngx_close_connection(c);
        ctx->c_stdin = NULL;
    }

    if (!c->close && r->request_body->bufs) {
        // still more data need to be wrote
        ngx_handle_write_event(ctx->c_stdin->write, 0);
    }
}


static void
ngx_http_cgi_request_body_handler(ngx_http_request_t *r) {
    // async request body handler, when invoked, more data comes in
    ngx_http_cgi_ctx_t *ctx;
    ngx_int_t           rc;
    
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_cgi_request_body_handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_cgi_module);
    if (ctx == NULL) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto error;
    }

    rc = ngx_http_read_unbuffered_request_body(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        goto error;
    }

    if (ctx->c_stdin->write->ready) {
        ngx_http_cgi_stdin_data_handler(ctx->c_stdin->write);
    }
    return;

error:
    ngx_http_finalize_request(r, rc);
    return;
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
            ngx_close_connection(ctx->c_stdout);
            ctx->c_stdout = NULL;
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


static void
ngx_http_cgi_stderr_data_handler(ngx_event_t *ev) {
    ngx_connection_t   *c = ev->data;
    ngx_http_cgi_ctx_t *ctx = c->data;
    ngx_http_request_t *r = ctx->r;

    u_char buf[65536];
    int nread;

    for (;;) {
        nread = read(c->fd, buf, sizeof(buf));
        if (nread > 0) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                    "cgi stderr: %*s", nread, buf);
        } else if (nread == 0) {
            // end of file
            ngx_close_connection(ctx->c_stderr);
            ctx->c_stderr = NULL;
            return;
        } else {
            if (ngx_errno == EAGAIN) {
                // wait for more data
                ngx_handle_read_event(ctx->c_stderr->read, 0);
                return;
            } else {
                return;
            }
        }
    }
}


void
ngx_http_cgi_handler_3(ngx_http_cgi_ctx_t *ctx) {
    ngx_int_t                  rc;
    ngx_http_request_t        *r = ctx->r;

    rc = ngx_http_cgi_prepare_cmd(ctx);
    if (rc != NGX_OK) {
        goto error;
    }

    rc = ngx_http_cgi_prepare_env(ctx);
    if (rc != NGX_OK) {
        goto error;
    }

    rc = ngx_http_cgi_spawn_child_process(ctx);
    if (rc != NGX_OK) {
        goto error;
    }

    // setup stdin handler
    if (ctx->pipe_stdin[PIPE_WRITE_END] != -1) {
        if (ngx_nonblocking(ctx->pipe_stdin[PIPE_WRITE_END]) == -1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                    "ngx_nonblocking");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto error;
        }
        ctx->c_stdin = ngx_get_connection(ctx->pipe_stdin[PIPE_WRITE_END],
                                          r->connection->log);
        if (ctx->c_stdin) {
            ctx->pipe_stdin[PIPE_WRITE_END] = -1;
        } else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                    "ngx_get_connection");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto error;
        }

        ctx->c_stdin->data = ctx;
        ctx->c_stdin->type = SOCK_STREAM;

        ctx->c_stdin->write->handler = ngx_http_cgi_stdin_data_handler;
        ctx->c_stdin->write->log = r->connection->log;
        if (ngx_handle_write_event(ctx->c_stdin->write, 0) != NGX_OK) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto error;
        }
    }

    // setup stdout handler
    if (ctx->pipe_stdout[PIPE_READ_END] != -1) {
        if (ngx_nonblocking(ctx->pipe_stdout[PIPE_READ_END]) == -1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                    "ngx_nonblocking");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto error;
        }
        ctx->c_stdout = ngx_get_connection(ctx->pipe_stdout[PIPE_READ_END],
                                        r->connection->log);
        if (ctx->c_stdout) {
            ctx->pipe_stdout[PIPE_READ_END] = -1;
        } else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                    "ngx_get_connection");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto error;
        }

        ctx->c_stdout->data = ctx;
        ctx->c_stdout->type = SOCK_STREAM;

        ctx->c_stdout->read->handler = ngx_http_cgi_stdout_data_handler;
        ctx->c_stdout->read->log = r->connection->log;
        if (ngx_handle_read_event(ctx->c_stdout->read, 0) != NGX_OK) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto error;
        }
    }

    // setup stderr handler
    if (ctx->pipe_stderr[PIPE_READ_END] != -1) {
        if (ngx_nonblocking(ctx->pipe_stderr[PIPE_READ_END]) == -1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                    "ngx_nonblocking");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto error;
        }
        ctx->c_stderr = ngx_get_connection(ctx->pipe_stderr[PIPE_READ_END],
                                        r->connection->log);
        if (ctx->c_stderr) {
            ctx->pipe_stderr[PIPE_READ_END] = -1;
        } else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                    "ngx_get_connection");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto error;
        }

        ctx->c_stderr->data = ctx;
        ctx->c_stderr->type = SOCK_STREAM;

        ctx->c_stderr->read->handler = ngx_http_cgi_stderr_data_handler;
        ctx->c_stderr->read->log = r->connection->log;
        if (ngx_handle_read_event(ctx->c_stderr->read, 0) != NGX_OK) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto error;
        }
    }

    return;

error:
    ngx_http_finalize_request(r, rc);
    return;
}


static ngx_flag_t
_is_same_addr(const struct sockaddr *addr1, const struct sockaddr *addr2) {
    if (addr1->sa_family != addr2->sa_family) {
        return 0;
    }

    if (addr1->sa_family == AF_INET) { // IPv4
        struct sockaddr_in *a1 = (struct sockaddr_in *)addr1;
        struct sockaddr_in *a2 = (struct sockaddr_in *)addr2;

        return a1->sin_addr.s_addr == a2->sin_addr.s_addr;
    } else if (addr1->sa_family == AF_INET6) { // IPv6
        struct sockaddr_in6 *a1 = (struct sockaddr_in6 *)addr1;
        struct sockaddr_in6 *a2 = (struct sockaddr_in6 *)addr2;

        return memcmp(&a1->sin6_addr, &a2->sin6_addr,
                      sizeof(struct in6_addr)) == 0;
    }

    return 0;
}


static void
ngx_http_cgi_rdns_confirm_done(ngx_resolver_ctx_t *rctx) {
    ngx_http_cgi_ctx_t        *ctx = rctx->data;
    ngx_http_request_t        *r = ctx->r;
    ngx_flag_t                 confirmed = 0;

    if (rctx->state == 0) {
        for (size_t i = 0; i < rctx->naddrs; ++i) {
            if (_is_same_addr(rctx->addrs[i].sockaddr,
                    r->connection->sockaddr))
            {
                confirmed = 1;
            }
        }
    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &r->connection->addr_text, rctx->state,
                      ngx_resolver_strerror(rctx->state));
    }
    ngx_resolve_name_done(rctx);

    if (!confirmed) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "RDNS confirming error, re-resolve result doesn't match "
                      "client ip, remove remote_host field %V",
                      &ctx->remote_host);
        ctx->remote_host.data = 0;
        ctx->remote_host.len = 0;
    }

    ngx_http_cgi_handler_3(ctx);
    return;
}


static void
ngx_http_cgi_rdns_done(ngx_resolver_ctx_t *rctx) {
    ngx_http_cgi_ctx_t        *ctx = rctx->data;
    ngx_http_request_t        *r = ctx->r;
    ngx_int_t                  rc = NGX_OK;

    if (rctx->state == 0) {
        ctx->remote_host.data = ngx_pstrdup(r->pool, &rctx->name);
        if (ctx->remote_host.data == NULL) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto error;
        }
        ctx->remote_host.len = rctx->name.len;
    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &r->connection->addr_text, rctx->state,
                      ngx_resolver_strerror(rctx->state));
    }
    ngx_resolve_addr_done(rctx);

    if (ctx->remote_host.len > 0 && ctx->conf->rdns >= CGI_RDNS_DOUBLE) {
        rctx = ngx_resolve_start(ctx->clcf->resolver, NULL);
        if (rctx == NGX_NO_RESOLVER) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "no resolver defined to resolve");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto error;
        } else if (rctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_resolve_start");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto error;
        }

        rctx->name = ctx->remote_host;
        rctx->handler = ngx_http_cgi_rdns_confirm_done;
        rctx->data = ctx;
        rctx->timeout = CGI_DNS_TIMEOUT;

        rc = ngx_resolve_name(rctx);
        if (rc != NGX_OK) {
            goto error;
        }
    } else {
        ngx_http_cgi_handler_3(ctx);
    }

    return;

error:
    ngx_http_finalize_request(r, rc);
    return;
}


void
ngx_http_cgi_handler_2(ngx_http_request_t *r) {
    ngx_int_t                  rc;
    ngx_http_cgi_ctx_t        *ctx;
    ngx_resolver_ctx_t        *rctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cgi handle init");

    ctx = ngx_http_get_module_ctx(r, ngx_http_cgi_module);
    if (ctx == NULL) {
        ctx = ngx_http_cgi_ctx_create(r->pool);
        if (ctx == NULL) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto error;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_cgi_module);
    }

    ctx->r = r;

    ctx->clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (!ctx->clcf) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "get ngx_http_core_module loc conf failed");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto error;
    }

    ctx->conf = ngx_http_get_module_loc_conf(r, ngx_http_cgi_module);
    if (ctx->conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "get ngx_http_cgi_module loc conf failed");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto error;
    }

    rc = ngx_http_cgi_locate_script(ctx);
    if (rc != NGX_OK) {
        goto error;
    }

    // setup request body handler
    if (r->reading_body) {
        r->read_event_handler = ngx_http_cgi_request_body_handler;
    }

    if (ctx->conf->rdns >= CGI_RDNS_ON) {
        rctx = ngx_resolve_start(ctx->clcf->resolver, NULL);
        if (rctx == NGX_NO_RESOLVER) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "no resolver defined to resolve");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto error;
        } else if (rctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_resolve_start");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto error;
        }

        rctx->addr.sockaddr = r->connection->sockaddr;
        rctx->addr.socklen = r->connection->socklen;
        rctx->handler = ngx_http_cgi_rdns_done;
        rctx->data = ctx;
        rctx->timeout = CGI_DNS_TIMEOUT;

        rc = ngx_resolve_addr(rctx);
        if (rc != NGX_OK) {
            goto error;
        }
    } else {
        ngx_http_cgi_handler_3(ctx);
    }

    return;

error:
    ngx_http_finalize_request(r, rc);
    return;
}


static ngx_int_t
ngx_http_cgi_handler_1(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    r->request_body_no_buffering = 1;
    rc = ngx_http_read_client_request_body(r, ngx_http_cgi_handler_2);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static char *
ngx_http_cgi_set_interpreter(ngx_conf_t *cf, ngx_command_t *cmd, void *c) {
    ngx_http_cgi_loc_conf_t  *conf = c;
    ngx_str_t                *args = cf->args->elts;

    if (conf->interpreter != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    conf->interpreter = ngx_array_create(
            cf->pool, cf->args->nelts - 1, sizeof(char *));
    if (conf->interpreter == NULL) {
        return NGX_CONF_ERROR;
    }

    for (uint i = 1; i < cf->args->nelts; ++i) {
        u_char **pstr = (u_char**)ngx_array_push(conf->interpreter);
        if (pstr == NULL) {
            return NGX_CONF_ERROR;
        }

        *pstr = ngx_palloc(cf->pool, args[i].len + 1);
        if (*pstr == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memcpy(*pstr, args[i].data, args[i].len);
        (*pstr)[args[i].len] = 0;
    }

    return NGX_CONF_OK;
}


static void
ngx_http_cgi_close_fd(void *data) {
    close((ngx_int_t)data);
}


static char *
ngx_http_cgi_set_stderr(ngx_conf_t *cf, ngx_command_t *cmd, void *c) {
    ngx_http_cgi_loc_conf_t  *conf = c;
    ngx_str_t                *args = cf->args->elts;
    char                     *fpath;
    ngx_pool_cleanup_t       *cln;

    if (conf->cgi_stderr != CGI_STDERR_UNSET) {
        return "is duplicate";
    }

    assert(cf->args->nelts == 2);
    if (args[1].len == 0) {
        conf->cgi_stderr = CGI_STDERR_PIPE;
    } else {
        fpath = strndup((char*)args[1].data, args[1].len);
        conf->cgi_stderr = open(fpath, O_WRONLY | O_APPEND | O_CREAT, 0644);
        if (conf->cgi_stderr == -1) {
            free(fpath);
            return "fail to open file";
        }

        // I'm not 100% sure whether following code works.
        // Because when I wrote it, the latest nginx version has issue with
        // old cycle cleanup, and can never cleanup old cycle.
        // so I can't test it, may god bless you
        cln = ngx_pool_cleanup_add(cf->pool, 0);
        cln->data = (void*)(ngx_int_t)conf->cgi_stderr;
        cln->handler = ngx_http_cgi_close_fd;

        free(fpath);
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_cgi_set_rdns(ngx_conf_t *cf, ngx_command_t *cmd, void *c) {
    ngx_http_cgi_loc_conf_t  *conf = c;
    ngx_str_t                *args = cf->args->elts;

    if (conf->rdns != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    assert(cf->args->nelts == 2);
    if (_strieq(args[1], "off")) {
        conf->rdns = CGI_RDNS_OFF;
    } else if (_strieq(args[1], "on")) {
        conf->rdns = CGI_RDNS_ON;
    } else if (_strieq(args[1], "double")) {
        conf->rdns = CGI_RDNS_DOUBLE;
    } else {
        return "contains bad value. available values: off | on | double";
    }

    return NGX_CONF_OK;
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
    // conf->path is initialized by ngx_pcalloc
    conf->strict_mode = NGX_CONF_UNSET;
    conf->interpreter = NGX_CONF_UNSET_PTR;
    conf->x_only = NGX_CONF_UNSET;
    conf->cgi_stderr = CGI_STDERR_UNSET;
    conf->rdns = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_cgi_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_cgi_loc_conf_t  *prev = parent;
    ngx_http_cgi_loc_conf_t  *conf = child;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_str_value(conf->path, prev->path,
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    ngx_conf_merge_value(conf->strict_mode, prev->strict_mode, 1);
    ngx_conf_merge_ptr_value(conf->interpreter, prev->interpreter, NULL);
    ngx_conf_merge_value(conf->x_only, prev->x_only, 1);
    ngx_conf_merge_value(conf->cgi_stderr, prev->cgi_stderr, CGI_STDERR_PIPE);
    ngx_conf_merge_value(conf->rdns, prev->rdns, CGI_RDNS_OFF);

    if (conf->enabled) {
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        if (clcf == NULL) {
            return NGX_CONF_ERROR;
        }

        clcf->handler = ngx_http_cgi_handler_1;
    }

    return NGX_CONF_OK;
}
