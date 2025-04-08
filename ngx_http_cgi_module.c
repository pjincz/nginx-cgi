
/*
 * Copyright (C) Chizhong Jin
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <assert.h>

////////////////////////////////////////////////////////////////////////////////
// const && macros

#define PIPE_READ_END      0
#define PIPE_WRITE_END     1

#define CGI_STDERR_UNSET  -1
#define CGI_STDERR_PIPE   -2

#define CGI_RDNS_OFF       0
#define CGI_RDNS_ON        1
#define CGI_RDNS_DOUBLE    2
#define CGI_RDNS_REQUIRED  4

#define CGI_DNS_TIMEOUT    30000  // 30 seconds

static const char *_ngx_http_cgi_hopbyhop_hdrs[] = {
    "Keep-Alive",
    "Transfer-Encoding",
    "TE",
    "Connection",
    "Trailer",
    "Upgrade",
    // I should parse Connection header, and ignore all headers list in
    // Connection. But I'm too lazy to this...
    "HTTP2-Settings"
};


#define _strieq(str, exp) \
    (ngx_strncasecmp((str).data, (u_char*)(exp), (str).len) == 0)
#define _ngx_str_last_ch(nstr) \
    ((nstr).len > 0 ? (nstr).data[(nstr).len - 1] : 0)
#define _countof(a) (sizeof(a)/sizeof(a[0]))

static const char * _ngx_str_to_cstr(ngx_pool_t *pool, ngx_str_t *nstr) {
    if (nstr->data[nstr->len] == 0) {
        return (char *)nstr->data;
    } else {
        char *cstr = ngx_pnalloc(pool, nstr->len + 1);
        if (cstr) {
            *ngx_cpymem(cstr, nstr->data, nstr->len) = 0;
        }
        return cstr;
    }
}


////////////////////////////////////////////////////////////////////////////////
// types

typedef int pipe_pair_t[2];


typedef struct {
    ngx_str_t                        name;
    ngx_http_complex_value_t         combine;  // name=value
} ngx_http_cgi_ext_var_t;


typedef struct ngx_http_cgi_loc_conf_s {
    ngx_flag_t                enabled;
    ngx_http_complex_value_t *script;
    ngx_array_t              *interpreter;  // array<ngx_http_complex_value_t>
    ngx_http_complex_value_t *working_dir;
    ngx_str_t                 path;
    ngx_flag_t                strict_mode;
    ngx_fd_t                  cgi_stderr;
    ngx_int_t                 rdns;

    ngx_array_t              *ext_vars;  // array<ngx_http_cgi_ext_var_t>
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


typedef struct ngx_http_cgi_process_s {
    pid_t                          pid;

    ngx_flag_t                     spawn_successful;
    ngx_int_t                      refs;
    ngx_flag_t                     sigchld_handled;
    ngx_flag_t                     zombie_cleaned;
    int                            wstatus;

    struct ngx_http_cgi_process_s *next;
} ngx_http_cgi_process_t;


typedef struct ngx_http_cgi_ctx_s {
    ngx_http_request_t            *r;
    ngx_http_core_loc_conf_t      *clcf;
    ngx_http_cgi_loc_conf_t       *conf;

    // script: path to cgi script
    // path_info: subpath under script, see rfc3875 4.1.5
    // path_translated: translated subpath, see rfc3875 4.1.6
    ngx_str_t                      script;      // c compatible
    ngx_str_t                      path_info;
    ngx_str_t                      remote_host;

    ngx_array_t                   *cmd;         // array<char*> with tail null
    ngx_array_t                   *env;         // array<char*> with tail null
    ngx_str_t                      working_dir;

    pipe_pair_t                    pipe_stdin;
    pipe_pair_t                    pipe_stdout;
    pipe_pair_t                    pipe_stderr;

    int                            pid;

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


////////////////////////////////////////////////////////////////////////////////
// module configuration


static ngx_int_t ngx_http_cgi_handler_init(ngx_http_request_t *r);
static void *ngx_http_cgi_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_cgi_merge_loc_conf(
    ngx_conf_t *cf, void *parent, void *child);
static char * ngx_http_cgi_set_cgi(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_cgi_set_interpreter(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_cgi_set_stderr(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_cgi_set_rdns(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_cgi_add_var(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_cgi_commands[] = {

    // Enable or disable cgi module on giving location block
    // Default: off
    {
        ngx_string("cgi"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE12,
        ngx_http_cgi_set_cgi,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    // Alias of `cgi pass`
    {
        ngx_string("cgi_pass"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_http_cgi_set_cgi,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    // Set interpreter and interpreter args for cgi script
    // When this option is not empty, cgi script will be run with giving
    // interpreter. Otherwise, script will be executed directly.
    // Default: empty
    {
        ngx_string("cgi_interpreter"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_ANY,
        ngx_http_cgi_set_interpreter,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_cgi_loc_conf_t, interpreter),
        NULL
    },

    // Set cgi working directory
    // If this is set to a non-empty value, the CGI script will be launched with
    // giving directory.
    {
        ngx_string("cgi_working_dir"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_http_set_complex_value_zero_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_cgi_loc_conf_t, working_dir),
        NULL
    },

    // Change cgi script PATH environment variable
    // Default: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    {
        ngx_string("cgi_path"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
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
        NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_cgi_loc_conf_t, strict_mode),
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
        NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_http_cgi_set_stderr,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_cgi_loc_conf_t, cgi_stderr),
        NULL
    },

    // Enable or disable reverse dns
    // cgi_rdns <off|on|double> [required]
    // off: disable rdns feature
    // on: run reverse dns before launching cgi script, and pass rdns to cgi
    //     script via `REMOTE_HOST` environment variable.
    // double: after reverse dns, do a forward dns again to check the rdns
    //         result. it result matches, pass result as `REMOTE_HOST`.
    // required: If rdns failed, 403, 503 or 500 returns to the client. Depends
    //           on the failure reason of rdns.
    // In order to use this, you need to setup a `resolver` in nginx too.
    //
    // author notes: do not enable this option, it will makes every request
    //               slower. this feature can be easily implemented by `dig -x`
    //               or `nslookup` in script when need. the only reason I impled
    //               this is just to make the module fully compliant with the
    //               rfc3874 standard.
    {
        ngx_string("cgi_rdns"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE12,
        ngx_http_cgi_set_rdns,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_cgi_loc_conf_t, rdns),
        NULL
    },

    // cgi_set_var <name> <expr>
    // Pass extra environment variables to CGI script.
    {
        ngx_string("cgi_set_var"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE2,
        ngx_http_cgi_add_var,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_cgi_loc_conf_t, ext_vars),
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


////////////////////////////////////////////////////////////////////////////////
// child process management


static struct sigaction * _gs_ngx_cgi_orig_sigchld_sa = NULL;
static struct ngx_http_cgi_process_s * _gs_http_cgi_processes = NULL;


static void ngx_http_cgi_block_sigchld() {
    sigset_t new_sigset;

    sigemptyset(&new_sigset);
    sigaddset(&new_sigset, SIGCHLD);
    sigprocmask(SIG_BLOCK, &new_sigset, NULL);
}


static void ngx_http_cgi_unblock_sigchld() {
    sigset_t new_sigset;

    sigemptyset(&new_sigset);
    sigaddset(&new_sigset, SIGCHLD);
    sigprocmask(SIG_UNBLOCK, &new_sigset, NULL);
}


// **invoking of this method should protected by ngx_http_cgi_block_sigchld**
static ngx_flag_t
_ngx_http_cgi_find_process(
    int pid, ngx_http_cgi_process_t **pprev, ngx_http_cgi_process_t **pcur)
{
    ngx_http_cgi_process_t *prev = NULL;
    ngx_http_cgi_process_t *cur = _gs_http_cgi_processes;

    for (; cur != NULL; prev = cur, cur = prev->next) {
        if (cur->pid == pid) {
            *pprev = prev;
            *pcur = cur;
            return 1;
        }
    }

    return 0;
}


// **invoking of this method should protected by ngx_http_cgi_block_sigchld**
static void
_ngx_http_cgi_try_clean_process_node(
    ngx_http_cgi_process_t *prev, ngx_http_cgi_process_t *cur)
{
    if (cur->refs > 0 || !cur->sigchld_handled || !cur->zombie_cleaned) {
        return;
    }

    if (prev) {
        prev->next = cur->next;
    } else {
        _gs_http_cgi_processes = cur->next;
    }

    free(cur);
}


// dereference of a process
// returns:
//   0-127: process exit code
//   128-255: process killed by signal
//   -1: process still alive
//   -2: process not managed by nginx-cgi
//   -999: unknown error
static int
ngx_http_cgi_deref_process(int pid) {
    int status = -999;

    ngx_http_cgi_block_sigchld();

    ngx_http_cgi_process_t *prev = NULL;
    ngx_http_cgi_process_t *cur = NULL;

    if (_ngx_http_cgi_find_process(pid, &prev, &cur)) {
        if (cur->refs > 0) {
            cur->refs -= 1;
        }

        if (!cur->zombie_cleaned) {
            if (waitpid(cur->pid, &cur->wstatus, WNOHANG) > 0) {
                cur->zombie_cleaned = 1;
            }
        }

        if (cur->zombie_cleaned) {
            if (WIFEXITED(cur->wstatus)) {
                status = WEXITSTATUS(cur->wstatus);
            } else if (WIFSIGNALED(cur->wstatus)) {
                status = WTERMSIG(cur->wstatus) + 128;
            }
        } else {
            status = -1;
        }

        _ngx_http_cgi_try_clean_process_node(prev, cur);
    } else {
        status = -2;
    }

    ngx_http_cgi_unblock_sigchld();
    return status;
}


static void
ngx_http_cgi_sigchld_handler(int sid, siginfo_t *sinfo, void *ucontext) {
    ngx_http_cgi_process_t *prev = NULL;
    ngx_http_cgi_process_t *cur = NULL;
    
    if (_ngx_http_cgi_find_process(sinfo->si_pid, &prev, &cur)) {
        cur->sigchld_handled = 1;

        if (waitpid(cur->pid, &cur->wstatus, WNOHANG) > 0) {
            cur->zombie_cleaned = 1;
        }

        // it looks this if stmt is unnecessary here, god knows
        if (cur->zombie_cleaned) {
            if (cur->spawn_successful) {
                if (WIFEXITED(cur->wstatus)) {
                    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                        "cgi process %d quits with status %d",
                        cur->pid, WEXITSTATUS(cur->wstatus));
                } else if (WIFSIGNALED(cur->wstatus)) {
                    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                        "cgi process %d was killed by signal %d",
                        cur->pid, WTERMSIG(cur->wstatus));
                }
            }
        }

        _ngx_http_cgi_try_clean_process_node(prev, cur);
    } else {
        // forward signal to orig handler
        if (_gs_ngx_cgi_orig_sigchld_sa->sa_flags & SA_SIGINFO) {
            _gs_ngx_cgi_orig_sigchld_sa->sa_sigaction(sid, sinfo, ucontext);
        } else if (_gs_ngx_cgi_orig_sigchld_sa->sa_handler != SIG_DFL &&
                   _gs_ngx_cgi_orig_sigchld_sa->sa_handler != SIG_IGN)
        {
            _gs_ngx_cgi_orig_sigchld_sa->sa_handler(sid);
        }
    }
}


static void
ngx_http_cgi_ensure_sigchld_hook() {
    if (_gs_ngx_cgi_orig_sigchld_sa) {
        return;
    }

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
            "http cgi: install SIGCHLD handler");

    static struct sigaction s_sigaction = {0};
    _gs_ngx_cgi_orig_sigchld_sa = &s_sigaction;

    struct sigaction newact = {0};
    newact.sa_flags = SA_SIGINFO;
    newact.sa_sigaction = ngx_http_cgi_sigchld_handler;
    sigemptyset(&newact.sa_mask);
    sigaction(SIGCHLD, &newact, _gs_ngx_cgi_orig_sigchld_sa);
}


#if (NGX_DARWIN)
    #define NO_VFORK 1
#endif


typedef struct ngx_http_cgi_creating_process_ctx_s {
    int (*proc)(struct ngx_http_cgi_creating_process_ctx_s *, int);
    void *data;

    int pid;
    const char * err_msg;
    int err_code;
} ngx_http_cgi_creating_process_ctx_t;


static void
ngx_http_cgi_create_process(ngx_http_cgi_creating_process_ctx_t *ctx) {
    ngx_http_cgi_process_t *pp = NULL;
    volatile ngx_flag_t pp_on_chain = 0;
    ngx_http_cgi_creating_process_ctx_t *shared_ctx = NULL;

    ngx_http_cgi_block_sigchld();

    // allocate process in advance, to avoid error in critical steps
    pp = malloc(sizeof(*pp));
    if (!pp) {
        ctx->err_msg = "malloc";
        ctx->err_code = ngx_errno;
        goto done;
    }
    ngx_memzero(pp, sizeof(*pp));

    // copy ctx to shared memory
    shared_ctx = mmap(NULL, sizeof(*shared_ctx),
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!shared_ctx) {
        ctx->err_msg = "mmap";
        ctx->err_code = ngx_errno;
        goto done;
    }
    *shared_ctx = *ctx;

    // do vfork/fork
    #if (NO_VFORK)
        int notify_fd_pair[2];
        if (pipe(notify_fd_pair) == -1) {
            ctx->err_msg = "pipe";
            ctx->err_code = ngx_errno;
            goto done;
        }

        int child_pid = fork();
        if (child_pid == -1) {
            ctx->err_msg = "fork";
            ctx->err_code = ngx_errno;
            goto done;
        }
    #else
        int child_pid = vfork();
        if (child_pid == -1) {
            ctx->err_msg = "vfork";
            ctx->err_code = ngx_errno;
            goto done;
        }
    #endif

    if (child_pid == 0) {
        // child process
        shared_ctx->pid = getpid();

        #if (NO_VFORK)
            _exit(shared_ctx->proc(shared_ctx, notify_fd_pair[1]));
        #else
            _exit(shared_ctx->proc(shared_ctx, -1));
        #endif
    } else {
        #if (NO_VFORK)
            char buf[4];
            close(notify_fd_pair[1]);
            // read action will be blocked until notify_fd_pair[1] closed
            ssize_t unused = read(notify_fd_pair[0], buf, 1);
            (void) unused;
            close(notify_fd_pair[0]);
        #endif

        // copy shared_ctx back to ctx
        *ctx = *shared_ctx;

        if (ctx->pid > 0) {
            // child process is created by vfork. no matter it succeed to exec
            // or failed, we need insert the node to the chain.
            pp->pid = ctx->pid;
            pp->spawn_successful = !ctx->err_msg;
            pp->next = _gs_http_cgi_processes;
            _gs_http_cgi_processes = pp;
            pp_on_chain = 1;

            // ensure hook is installed
            ngx_http_cgi_ensure_sigchld_hook();
        }

        if (pp->spawn_successful) {
            pp->refs += 1;
        }
    }

done:
    if (shared_ctx) {
        munmap(shared_ctx, sizeof(*shared_ctx));
    }
    if (pp && !pp_on_chain) {
        free(pp);
    }

    if (ctx->err_msg && ctx->err_code == 0) {
        ctx->err_code = NGX_ERROR;
    }

    ngx_http_cgi_unblock_sigchld();
}


////////////////////////////////////////////////////////////////////////////////
// implementation


static void
_quick_close_fd(int *pfd) {
    if (pfd && *pfd >= 0) {
        close(*pfd);
        *pfd = -1;
    }
}


static void
ngx_http_cgi_ctx_cleanup(void *data) {
    ngx_http_cgi_ctx_t *ctx = data;

    _quick_close_fd(&ctx->pipe_stdin[PIPE_READ_END]);
    _quick_close_fd(&ctx->pipe_stdin[PIPE_WRITE_END]);
    _quick_close_fd(&ctx->pipe_stdout[PIPE_READ_END]);
    _quick_close_fd(&ctx->pipe_stdout[PIPE_WRITE_END]);
    _quick_close_fd(&ctx->pipe_stderr[PIPE_READ_END]);
    _quick_close_fd(&ctx->pipe_stderr[PIPE_WRITE_END]);

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

    ctx = ngx_palloc(pool, sizeof(ngx_http_cgi_ctx_t));
    if (!ctx) {
        return ctx;
    }

    ngx_memzero(ctx, sizeof(ngx_http_cgi_ctx_t));

    ctx->pipe_stdin[0] = -1;
    ctx->pipe_stdin[1] = -1;
    ctx->pipe_stdout[0] = -1;
    ctx->pipe_stdout[1] = -1;
    ctx->pipe_stderr[0] = -1;
    ctx->pipe_stderr[1] = -1;

    return ctx;
}


// Polyfill:
//   * Mac OS doesn't have `closefrom`
//   * glibc < 2.34 doesn't have `closefrom`
#if (NGX_DARWIN) || ((NGX_LINUX) && (__GLIBC__ * 100 + __GLIBC_MINOR__ < 234))
static void closefrom(int lowfd) {
    int maxfd = getdtablesize();
    if (maxfd == -1) {
        perror("getdtablesize");
        return;
    }

    for (int i = lowfd; i < maxfd; i++) {
        close(i);
    }
}
#endif


static int
ngx_http_cgi_child_proc(
    ngx_http_cgi_creating_process_ctx_t *cpctx, int notify_fd)
{
    ngx_http_cgi_ctx_t *ctx = cpctx->data;

    // each CGI process leads a process group
    if (setpgid(0, 0) == -1) {
        cpctx->err_msg = "create process group";
        cpctx->err_code = errno;
        return 1;
    }

    char **cmd = ctx->cmd->elts;
    char **env = ctx->env->elts;

    char buf[PATH_MAX];
    char *exec_path = cmd[0];

    // if comming binary is related path, convert it to abs path
    if (cmd[0][0] != '/') {
        if (getcwd(buf, sizeof(buf)) == NULL) {
            cpctx->err_msg = "get current working dir";
            cpctx->err_code = errno;
            return 1;
        }
        size_t cwd_len = strlen(buf);
        size_t cmd_len = strlen(cmd[0]);
        if (cwd_len + 1 + cmd_len + 1 >= sizeof(buf)) {
            cpctx->err_msg = "relpath to abspath";
            cpctx->err_code = ENAMETOOLONG;
            return 1;
        }
        buf[cwd_len] = '/';
        strcpy(buf + cwd_len + 1, cmd[0]);
        exec_path = buf;
    }

    // do chdir if wanted
    if (ctx->working_dir.len) {
        if (chdir((char *)ctx->working_dir.data) == -1) {
            cpctx->err_msg = "change working dir";
            cpctx->err_code = errno;
            return 1;
        }
    }

    // remap stdin, stdout and stderr
    // if there's no body, pipe_stdin will not created for saving fd
    if (ctx->pipe_stdin[PIPE_READ_END] != -1) {
        dup2(ctx->pipe_stdin[PIPE_READ_END], 0);
    } else {
        dup2(open("/dev/null", O_RDONLY), 0);
    }

    dup2(ctx->pipe_stdout[PIPE_WRITE_END], 1);

    if (ctx->conf->cgi_stderr >= 0) {
        dup2(ctx->conf->cgi_stderr, 2);
    } else if (ctx->pipe_stderr[PIPE_WRITE_END] >= 0) {
        dup2(ctx->pipe_stderr[PIPE_WRITE_END], 2);
    }

    // close all fds >= 3 (or 4) to prevent inherit connection from nginx
    // this is important, because nginx doesn't mark all connections with
    // O_CLOEXEC. as a result, a long run cgi script will take ownship
    // of connections it closed by nginx, and causes client hangs.
    if (notify_fd != -1) {
        // notify_fd != -1, keep it, and mark as CLOEXEC, it will be closed
        // when exec succeed, we can use this to notify parent process exec
        // has been executed.
        dup2(notify_fd, 3);
        fcntl(3, F_SETFD, fcntl(3, F_GETFD) | FD_CLOEXEC);
        closefrom(4);
    } else {
        closefrom(3);
    }

    // exec to final binary
    if (execve(exec_path, cmd, env) == -1) {
        cpctx->err_msg = "exec";
        cpctx->err_code = errno;
        // 126 means cannot executing binary in POSIX system.
        return 126;
    }

    return 0;
}


static ngx_int_t
ngx_http_cgi_locate_script(ngx_http_cgi_ctx_t *ctx) {
    ngx_http_request_t        *r = ctx->r;
    ngx_file_info_t            script_info;
    int                        uri_remaining = 0;
    size_t                     root_len;

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
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cgi script path: %V, path_info: %V",
                   &ctx->script, &ctx->path_info);

    if (!ngx_is_file(&script_info)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "run cgi \"%V\" failed, not regular file", &ctx->script);
        return NGX_HTTP_NOT_FOUND;
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
        ngx_http_complex_value_t *args = ctx->conf->interpreter->elts;

        for (size_t i = 0; i < ctx->conf->interpreter->nelts; ++i) {
            ngx_str_t arg;
            if (ngx_http_complex_value(ctx->r, &args[i], &arg) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, ctx->r->connection->log, 0,
                    "failed to generate command line");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            *(u_char**)ngx_array_push(ctx->cmd) = arg.data;
        }
    }

    *(u_char**)ngx_array_push(ctx->cmd) = ctx->script.data;

    // an extra NULL string, required by exec
    *(u_char**)ngx_array_push(ctx->cmd) = NULL;

    return NGX_OK;
}


static void _add_env_line(ngx_http_cgi_ctx_t *ctx, char *line, int name_len) {
    char **envs = ctx->env->elts;
    size_t i;

    for (i = 0; i < ctx->env->nelts; ++i) {
        if (ngx_strncmp(envs[i], line, name_len + 1) == 0) {
            envs[i] = line;
            return;
        }
    }
    *(char**)ngx_array_push(ctx->env) = line;
}
#define _add_env_const(ctx, name, val) _add_env_line(ctx, (name "=" val), strlen(name))
#define _add_env_combine(ctx, combine) _add_env_line(ctx, combine, strchr(combine, '=') - combine)
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

    _add_env_line(ctx, line, name_len);
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
static inline void _add_env_addr(ngx_http_cgi_ctx_t *ctx, const char *name, struct sockaddr * sa, socklen_t socklen, ngx_flag_t bracket_ipv6) {
    ngx_int_t addr_len;
    // max ipv6 is 39 bytes
    // max sun_path is 108 bytes
    u_char addr[128];

    if (sa->sa_family == AF_INET6 && bracket_ipv6) {
        addr[0] = '[';
        addr_len = ngx_sock_ntop(sa, socklen, addr + 1, sizeof(addr) - 2, 0);
        addr[1 + addr_len] = ']';
        addr[1 + addr_len + 1] = 0;
        addr_len = addr_len + 2;
    } else {
        addr_len = ngx_sock_ntop(sa, socklen, addr, sizeof(addr), 0);
    }
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


static ngx_str_t
ngx_http_cgi_server_name_from_host_header(ngx_table_elt_t *host) {
    ngx_str_t empty = ngx_null_string;
    ngx_str_t result;

    ngx_int_t name_start = -1;
    ngx_int_t name_end = -1;
    ngx_int_t status = 0;

    enum {
        s_start = 0,
        s_ipv6,
        s_domain_or_ipv4,
        s_ipv6_end,
        s_port,
        s_done
    };

    if (!host || host->value.len == 0) {
        return empty;
    }

    for (size_t i = 0; i <= host->value.len; ++i) {
        char ch = i < host->value.len ? host->value.data[i] : 0;

        switch (status) {
            case s_start:
                if (ch == '[') {
                    status = s_ipv6;
                    name_start = i;
                } else if (isalnum(ch) || ch =='.' || ch == '-') {
                    status = s_domain_or_ipv4;
                    name_start = i;
                } else {
                    // bad input
                    return empty;
                }
                break;
            case s_ipv6:
                if (isxdigit(ch) || ch == ':') {
                    // continue
                } else if (ch == ']') {
                    status = s_ipv6_end;
                } else {
                    // bad input
                    return empty;
                }
                break;
            case s_domain_or_ipv4:
                if (isalnum(ch) || ch == '.' || ch == '-') {
                    // continue
                } else if (ch == ':') {
                    status = s_port;
                    name_end = i;
                } else if (ch == 0) {
                    status = s_done;
                    name_end = i;
                } else {
                    // bad input
                    return empty;
                }
                break;
            case s_ipv6_end:
                if (ch == ':') {
                    status = s_port;
                    name_end = i;
                } else if (ch == 0) {
                    status = s_done;
                } else {
                    // bad input
                    return empty;
                }
                break;
            case s_port:
                if (isdigit(ch)) {
                    // conttinue
                } else if (ch == 0) {
                    status = s_done;
                } else {
                    // bad input
                    return empty;
                }
                break;
            default:
                return empty;
        }
    }

    if (status != s_done) {
        return empty;
    }

    result.data = host->value.data + name_start;
    result.len = name_end - name_start;
    return result;
}


static ngx_int_t
ngx_http_cgi_add_custom_vars(
    ngx_http_cgi_ctx_t *ctx, ngx_http_cgi_loc_conf_t *conf)
{
    size_t                  nvar;
    ngx_http_cgi_ext_var_t *vars;

    if (!conf->ext_vars) {
        return NGX_OK;
    }

    nvar = conf->ext_vars->nelts;
    vars = conf->ext_vars->elts;

    for (size_t i = 0; i < nvar; ++i) {
        ngx_str_t combine;

        if (ngx_http_complex_value(
                ctx->r, &vars[i].combine, &combine) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        _add_env_combine(ctx, (char*)combine.data);
    }

    return NGX_OK;
}


// Nginx discards original URI after rewriting.
// That's really a bad news for us.
// We have 2 ways to solve this problem:
//   * Install a handler before rewring phase, and save uri before rewriting.
//     That's bad for our senario. We will make every request slower, even if
//     CGI module is not enabled on those locations.
//   * Re-constructs URI when CGI module is enabled.
//     That's also a bad idea. Because nginx may change the way to parse URI.
//     And they didn't mark those methods as public in their document.
// After comparing of aboving ways. Maybe the 2nd one is a bit better.
// The deep reason is CGI module is for slow senarios, we don't care to make it
// slower more.
// So we made this function to reconstruct original URI here.
static ngx_int_t
ngx_http_cgi_get_original_uri(ngx_http_request_t *r, ngx_str_t *uri) {
    // The impl is mostly copied from: ngx_http_process_request_uri
    ngx_http_core_srv_conf_t  *cscf;

    size_t uri_len = r->args_start ? r->args_start - 1 - r->uri_start
                                   : r->uri_end - r->uri_start;

    if (r->complex_uri || r->quoted_uri || r->empty_path_in_uri) {
        // mock ngx_http_request_t
        ngx_http_request_t sr = *r;

        if (r->empty_path_in_uri) {
            uri_len += 1;
        }

        sr.uri.len = uri_len;
        sr.uri.data = ngx_pnalloc(r->pool, uri_len);
        if (!sr.uri.data) {
            return NGX_ERROR;
        }

        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        ngx_int_t rc = ngx_http_parse_complex_uri(r, cscf->merge_slashes);
        if (rc == NGX_OK) {
            *uri = sr.uri;
        }
        return rc;
    } else {
        uri->data = r->uri_start;
        uri->len = uri_len;
        return NGX_OK;
    }
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
    ngx_int_t                  rc;

    struct sockaddr_storage    local_addr;
    socklen_t                  local_addr_len;

    ngx_str_t                  server_name;

    ngx_list_part_t           *part;
    ngx_uint_t                 i, j;
    ngx_table_elt_t           *v;
    ngx_flag_t                 hop_by_hop_hdr;

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

    _add_env_addr(ctx, "REMOTE_ADDR", con->sockaddr, con->socklen, 0);
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

    ngx_str_t original_uri;
    if (ngx_http_cgi_get_original_uri(r, &original_uri) == NGX_OK) {
        _add_env_nstr(ctx, "REQUEST_URI", &original_uri);
    }
    _add_env_str(ctx, "SCRIPT_NAME",
                 (char*)r->uri.data, r->uri.len - ctx->path_info.len);

    _add_env_nstr(ctx, "SCRIPT_FILENAME", &ctx->script);

    if (local_addr_len > 0) {
        _add_env_addr(
            ctx, "SERVER_ADDR", (void*)&local_addr, local_addr_len, 0);
        _add_env_port(ctx, "SERVER_PORT", (void*)&local_addr);
    }

    server_name = ngx_http_cgi_server_name_from_host_header(r->headers_in.host);
    if (server_name.len > 0) {
        _add_env_nstr(ctx, "SERVER_NAME", &server_name);
    } else {
        // If Host header doesn't present or doesn't contains server name, use
        // reflict server ip.
        _add_env_addr(
            ctx, "SERVER_NAME", (void*)&local_addr, local_addr_len, 1);
    }

    _add_env_nstr(ctx, "SERVER_PROTOCOL", &r->http_protocol);

    _add_env_const(ctx, "SERVER_SOFTWARE", "nginx/" NGINX_VERSION);

    if (ctx->path_info.len > 0) {
        _add_env_nstr(ctx, "PATH_INFO", &ctx->path_info);

        // hack request, and run ngx_http_map_uri_to_path
        ngx_str_t orig_uri = r->uri;
        size_t root_len = 0;
        ngx_str_t path_translated;

        r->uri = ctx->path_info;
        if (ngx_http_map_uri_to_path(r, &path_translated, &root_len, 0))
        {
            _add_env_nstr(ctx, "PATH_TRANSLATED", &path_translated);
        }
        r->uri = orig_uri;
    }

    // this field appears only if an auth module has been setup, and runs before
    // cgi module. that's good, it has the same behaviour with apache2.
    if (ctx->r->headers_in.user.len) {
        _add_env_nstr(ctx, "REMOTE_USER", &ctx->r->headers_in.user);

        if (ctx->r->headers_in.authorization) {
            ngx_str_t auth_type = ctx->r->headers_in.authorization->value;
            for (i = 0; i < auth_type.len; ++i) {
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

        hop_by_hop_hdr = 0;
        for (j = 0; j < _countof(_ngx_http_cgi_hopbyhop_hdrs); ++j) {
            if (_strieq(v[i].key, _ngx_http_cgi_hopbyhop_hdrs[j])) {
                // hop-by-hop header should not forward to cgi script
                hop_by_hop_hdr = 1;
                break;
            }
        }
        if (hop_by_hop_hdr) {
            continue;
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
            for (u_char *p = name; *p; ++p) {
                *p = ngx_toupper(*p);
                if (*p == '-') {
                    *p = '_';
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

    rc = ngx_http_cgi_add_custom_vars(ctx, ctx->conf);
    if (rc != NGX_OK) {
        return rc;
    }

    // an extra null string, required by exec
    *(char**)ngx_array_push(ctx->env) = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_cgi_spawn_cgi_process(ngx_http_cgi_ctx_t *ctx) {
    ngx_int_t           rc = NGX_OK;
    ngx_http_request_t *r = ctx->r;

    // don't create stdin pipe if there's no body to save connections
    if ((r->request_body && r->request_body->bufs) || r->reading_body) {
        if (pipe(ctx->pipe_stdin) == -1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                    "pipe");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }
    }

    if (pipe(ctx->pipe_stdout) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno, "pipe");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    if (ctx->conf->cgi_stderr == CGI_STDERR_PIPE) {
        if (pipe(ctx->pipe_stderr) == -1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno, "pipe");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }
    }

    ngx_http_cgi_creating_process_ctx_t cpctx = {
        .proc = ngx_http_cgi_child_proc,
        .data = ctx,
    };
    ngx_http_cgi_create_process(&cpctx);

    if (cpctx.err_code == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "spawned cgi process: %d", cpctx.pid);
        ctx->pid = cpctx.pid;
    } else {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, cpctx.err_code,
            "failed to spawn CGI process: %s", cpctx.err_msg);

        if (cpctx.err_code == EACCES) {
            rc = NGX_HTTP_FORBIDDEN;
        } else if (cpctx.err_code == ENOENT) {
            rc = NGX_HTTP_NOT_FOUND;
        } else {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

done:
    if (rc == NGX_OK) {
        // close unused pipe ends
        _quick_close_fd(&ctx->pipe_stdin[PIPE_READ_END]);
        _quick_close_fd(&ctx->pipe_stdout[PIPE_WRITE_END]);
        _quick_close_fd(&ctx->pipe_stderr[PIPE_WRITE_END]);
    } else {
        // close all pipe ends
        _quick_close_fd(&ctx->pipe_stdin[PIPE_READ_END]);
        _quick_close_fd(&ctx->pipe_stdin[PIPE_WRITE_END]);
        _quick_close_fd(&ctx->pipe_stdout[PIPE_READ_END]);
        _quick_close_fd(&ctx->pipe_stdout[PIPE_WRITE_END]);
        _quick_close_fd(&ctx->pipe_stderr[PIPE_READ_END]);
        _quick_close_fd(&ctx->pipe_stderr[PIPE_WRITE_END]);
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

            for (size_t i = 0; i < _countof(_ngx_http_cgi_hopbyhop_hdrs); ++i) {
                if (_strieq(name, _ngx_http_cgi_hopbyhop_hdrs[i])) {
                    ngx_log_error(NGX_LOG_ERR, ctx->r->connection->log, 0,
                            "hop-by-hop header is not avalid in cgi response: %V",
                            &line);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            }

            if (_strieq(name, "Status")) {
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
ngx_http_cgi_terminate_request(ngx_http_cgi_ctx_t *ctx, int status) {
    if (!ctx->header_sent) {
        int rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        // 126 and 127 have special meaning in POSIX shell
        if (status == 127) {
            rc = NGX_HTTP_NOT_FOUND;
        } else if (status == 126) {
            rc = NGX_HTTP_FORBIDDEN;
        }
        ngx_http_finalize_request(ctx->r, rc);
    } else {
        // For http 1.1 and above, protocol has way to describe errors in middle
        // of streaming.
        // But for http 1.0, we can only causes a hard TCP RST here.
        if (ctx->r->http_version == NGX_HTTP_VERSION_10) {
            struct linger linger;
            linger.l_onoff = 1;
            linger.l_linger = 0;
            if (setsockopt(ctx->r->connection->fd, SOL_SOCKET, SO_LINGER,
                    (void *) &linger, sizeof(struct linger)) == -1)
            {
                ngx_log_error(NGX_LOG_ALERT, ctx->r->connection->log, ngx_errno,
                            "setsockopt(SO_LINGER) failed");
            }
        }
        ngx_http_finalize_request(ctx->r, NGX_ERROR);
    }

    ngx_http_run_posted_requests(ctx->r->connection);
}


static void
ngx_http_cgi_stdin_handler(ngx_event_t *ev) {
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

    if (ctx->c_stdin && r->request_body->bufs) {
        // still more data need to be wrote
        ctx->c_stdin->write->ready = 0;
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

    if (ctx->c_stdin) {
        if (ctx->c_stdin->write->ready) {
            ngx_http_cgi_stdin_handler(ctx->c_stdin->write);
        }
    } else {
        // cgi script has closed the stdin, discard remain data
        // it's not necessary to free buffers here, but it can help to reduce
        // memory usage during a long connection
        while (r->request_body && r->request_body->bufs) {
            ngx_chain_t * next = r->request_body->bufs->next;
            if (r->request_body->bufs->buf) {
                ngx_pfree(r->pool, r->request_body->bufs->buf);
            }
            ngx_pfree(r->pool, r->request_body->bufs);
            r->request_body->bufs = next;
        }
    }
    return;

error:
    ngx_http_finalize_request(r, rc);
    return;
}


static void
ngx_http_cgi_stdout_handler(ngx_event_t *ev) {
    ngx_connection_t   *c = ev->data;
    ngx_http_cgi_ctx_t *ctx = c->data;
    ngx_http_request_t *r = ctx->r;
    ngx_int_t           rc = NGX_OK;

    u_char buf[65536];
    int total_read = 0, nread = 0;
    ngx_flag_t eof = 0;

    for (;;) {
        nread = read(c->fd, buf, sizeof(buf));
        if (nread > 0) {
            rc = ngx_http_cgi_add_output(ctx, buf, buf + nread);
            if (rc != NGX_OK) {
                goto error;
            }
            total_read += nread;
        } else if (nread == 0) {
#if (NGX_SOLARIS)
            // On Solaris, nread == 0 doesn't means eof
#else
            eof = 1;
#endif
            break;
        } else {
            if (ngx_errno == EAGAIN) {
                // wait for more data, also do nothing here
                break;
            } else {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                goto error;
            }
        }
    }

#if (NGX_SOLARIS)
    if (total_read == 0) {
        eof = 1;
    }
#else
    // Suppress compiler warnings
    (void)total_read;
#endif

    if (!eof) {
        rc = ngx_http_cgi_flush(ctx, 0);
        if (rc != NGX_OK) {
            goto error;
        }
        ctx->c_stdout->read->ready = 0;
        rc = ngx_handle_read_event(ctx->c_stdout->read, 0);
        if (rc == NGX_ERROR || rc > NGX_OK) {
            goto error;
        }
    } else {
        ngx_close_connection(ctx->c_stdout);
        ctx->c_stdout = NULL;

        int status = ngx_http_cgi_deref_process(ctx->pid);
        if (status == -1 || status == 0) {
            // process manually closed stdout or exited with code 0
            ngx_http_finalize_request(r, ngx_http_cgi_flush(ctx, 1));
        } else if (status > 0) {
            // process exited abnormal
            ngx_http_cgi_terminate_request(ctx, status);
        } else {
            // should not happen
            ngx_http_cgi_terminate_request(ctx, status);
        }
    }

    return;

error:
    ngx_http_finalize_request(r, rc);
    return;
}


static void
ngx_http_cgi_stderr_handler(ngx_event_t *ev) {
    ngx_connection_t   *c = ev->data;
    ngx_http_cgi_ctx_t *ctx = c->data;
    ngx_http_request_t *r = ctx->r;

    u_char buf[65536];
    int total_read = 0, nread = 0;
    ngx_flag_t eof = 0;

    for (;;) {
        nread = read(c->fd, buf, sizeof(buf));
        if (nread > 0) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                    "cgi stderr: %*s", nread, buf);
            total_read += nread;
        } else if (nread == 0) {
#if (NGX_SOLARIS)
            // On Solaris, nread == 0 doesn't means eof
#else
            eof = 1;
#endif
            break;
        } else {
            if (ngx_errno == EAGAIN) {
                // wait for more data, also do nothing here
                break;
            } else {
                return;
            }
        }
    }

#if (NGX_SOLARIS)
    if (total_read == 0) {
        eof = 1;
    }
#else
    // Suppress compiler warnings
    (void)total_read;
#endif

    if (!eof) {
        ctx->c_stderr->read->ready = 0;
        ngx_handle_read_event(ctx->c_stderr->read, 0);
    } else {
        ngx_close_connection(ctx->c_stderr);
        ctx->c_stderr = NULL;
    }
}


void
ngx_http_cgi_handler_real(ngx_http_cgi_ctx_t *ctx) {
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

    if (ctx->conf->working_dir) {
        rc = ngx_http_complex_value(
            ctx->r, ctx->conf->working_dir, &ctx->working_dir);
        if (rc != NGX_OK) {
            goto error;
        }
    }

    rc = ngx_http_cgi_spawn_cgi_process(ctx);
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

        ctx->c_stdin->write->handler = ngx_http_cgi_stdin_handler;
        ctx->c_stdin->write->log = r->connection->log;
        if (ngx_handle_write_event(ctx->c_stdin->write, 0) != NGX_OK) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto error;
        }

        if (r->reading_body) {
            r->read_event_handler = ngx_http_cgi_request_body_handler;
        }
    }

    // setup stdout handler
    if (ctx->pipe_stdout[PIPE_READ_END] != -1) {
        if (ngx_nonblocking(ctx->pipe_stdout[PIPE_READ_END]) == -1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                    "fcntl");
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

        ctx->c_stdout->read->handler = ngx_http_cgi_stdout_handler;
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

        ctx->c_stderr->read->handler = ngx_http_cgi_stderr_handler;
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

    if (ctx->remote_host.len == 0 && (ctx->conf->rdns & CGI_RDNS_REQUIRED)) {
        ngx_int_t rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        if (rctx->state == NGX_RESOLVE_TIMEDOUT) {
            rc = NGX_HTTP_SERVICE_UNAVAILABLE;
        } else if (rctx->state == NGX_RESOLVE_NXDOMAIN) {
            rc = NGX_HTTP_FORBIDDEN;
        }
        ngx_http_finalize_request(r, rc);
    } else {
        ngx_http_cgi_handler_real(ctx);
    }
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

    if (ctx->remote_host.len > 0 && (ctx->conf->rdns & CGI_RDNS_DOUBLE)) {
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
    } else if (ctx->remote_host.len == 0 &&
               (ctx->conf->rdns & CGI_RDNS_REQUIRED))
    {
        if (rctx->state == NGX_RESOLVE_TIMEDOUT) {
            rc = NGX_HTTP_SERVICE_UNAVAILABLE;
        } else if (rctx->state == NGX_RESOLVE_NXDOMAIN) {
            rc = NGX_HTTP_FORBIDDEN;
        } else {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        goto error;
    }else {
        ngx_http_cgi_handler_real(ctx);
    }

    return;

error:
    ngx_http_finalize_request(r, rc);
    return;
}


void
ngx_http_cgi_empty_body_handler(ngx_http_request_t *r) {
    // do nothing here
}


static ngx_int_t
ngx_http_cgi_handler_init(ngx_http_request_t *r)
{
    ngx_int_t            rc;
    ngx_http_cgi_ctx_t  *ctx;
    ngx_http_cleanup_t  *cln;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cgi handle init");

    ctx = ngx_http_get_module_ctx(r, ngx_http_cgi_module);
    if (ctx == NULL) {
        ctx = ngx_http_cgi_ctx_create(r->pool);
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        cln = ngx_pcalloc(r->pool, sizeof(*cln));
        cln->data = ctx;
        cln->handler = ngx_http_cgi_ctx_cleanup;
        cln->next = r->cleanup;
        r->cleanup = cln;

        ngx_http_set_ctx(r, ctx, ngx_http_cgi_module);
    }

    ctx->r = r;

    ctx->clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (!ctx->clcf) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "get ngx_http_core_module loc conf failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->conf = ngx_http_get_module_loc_conf(r, ngx_http_cgi_module);
    if (ctx->conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "get ngx_http_cgi_module loc conf failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ctx->conf->script) {
        rc = ngx_http_complex_value(ctx->r, ctx->conf->script, &ctx->script);
        if (rc == NGX_OK) {
            ctx->path_info = r->uri;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "cgi script path: %V, path_info: %V",
                &ctx->script, &ctx->path_info);
        }
    } else {
        rc = ngx_http_cgi_locate_script(ctx);
    }
    if (rc != NGX_OK) {
        ngx_http_discard_request_body(r);
        return rc;
    }

    r->request_body_no_buffering = 1;
    rc = ngx_http_read_client_request_body(r, ngx_http_cgi_empty_body_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    if (ctx->conf->rdns) {
        ngx_resolver_ctx_t *rctx = ngx_resolve_start(ctx->clcf->resolver, NULL);
        if (rctx == NGX_NO_RESOLVER) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "no resolver defined to resolve");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        } else if (rctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_resolve_start");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        rctx->addr.sockaddr = r->connection->sockaddr;
        rctx->addr.socklen = r->connection->socklen;
        rctx->handler = ngx_http_cgi_rdns_done;
        rctx->data = ctx;
        rctx->timeout = CGI_DNS_TIMEOUT;

        rc = ngx_resolve_addr(rctx);
        if (rc != NGX_OK) {
            return rc;
        }
    } else {
        ngx_http_cgi_handler_real(ctx);
    }

    return NGX_DONE;
}


static char *
ngx_http_cgi_set_cgi(ngx_conf_t *cf, ngx_command_t *cmd, void *c) {
    ngx_http_cgi_loc_conf_t  *conf = c;
    ngx_uint_t                narg = cf->args->nelts;
    ngx_str_t                *args = cf->args->elts;

    if (conf->enabled != NGX_CONF_UNSET) {
        return "is duplicated";
    }

    ngx_flag_t is_on = 0;
    ngx_flag_t is_off = 0;
    ngx_flag_t is_pass = 0;
    ngx_str_t script_path;

    if (ngx_strcasecmp(args[0].data, (u_char *)"cgi") == 0) {
        if (ngx_strcasecmp(args[1].data, (u_char *)"on") == 0) {
            if (narg != 2) { return NGX_CONF_ERROR; }
            is_on = 1;
        } else if (ngx_strcasecmp(args[1].data, (u_char *)"off") == 0) {
            if (narg != 2) { return NGX_CONF_ERROR; }
            is_off = 1;
        } else if (ngx_strcasecmp(args[1].data, (u_char *)"pass") == 0) {
            if (narg != 3) { return NGX_CONF_ERROR; }
            is_pass = 1;
            script_path = args[2];
        } else {
            return NGX_CONF_ERROR;
        }
    } else if (ngx_strcasecmp(args[0].data, (u_char *)"cgi_pass") == 0) {
        if (narg != 2) { return NGX_CONF_ERROR; }
        is_pass = 1;
        script_path = args[1];
    } else {
        return NGX_CONF_ERROR;
    }

    if (is_on || is_off) {
        conf->enabled = is_on;
    } else if (is_pass) {
        conf->enabled = 1;
        conf->script = ngx_palloc(cf->pool, sizeof(*conf->script));

        ngx_http_compile_complex_value_t ccv = {0};
        ccv.cf = cf;
        ccv.value = &script_path;
        ccv.complex_value = conf->script;
        ccv.zero = 1;
        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_cgi_set_interpreter(ngx_conf_t *cf, ngx_command_t *cmd, void *c) {
    ngx_http_cgi_loc_conf_t  *conf = c;
    ngx_str_t                *args = cf->args->elts;

    if (conf->interpreter != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    conf->interpreter = ngx_array_create(
            cf->pool, cf->args->nelts - 1, sizeof(ngx_http_complex_value_t));
    if (conf->interpreter == NULL) {
        return NGX_CONF_ERROR;
    }

    for (uint i = 1; i < cf->args->nelts; ++i) {
        ngx_http_complex_value_t *cv = ngx_array_push(conf->interpreter);
        if (cv == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_http_compile_complex_value_t ccv = {0};
        ccv.cf = cf;
        ccv.value = &args[i];
        ccv.complex_value = cv;
        ccv.zero = 1;  // indicate CC to generate C safe string

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
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
    const char               *fpath;
    ngx_pool_cleanup_t       *cln;

    if (conf->cgi_stderr != CGI_STDERR_UNSET) {
        return "is duplicate";
    }

    assert(cf->args->nelts == 2);
    if (args[1].len == 0) {
        conf->cgi_stderr = CGI_STDERR_PIPE;
    } else {
        fpath = _ngx_str_to_cstr(cf->pool, &args[1]);
        if (!fpath) {
            return "out of memory";
        }

        conf->cgi_stderr = open(fpath, O_WRONLY | O_APPEND | O_CREAT, 0644);
        if (conf->cgi_stderr == -1) {
            return "fail to open file";
        }

        // I'm not 100% sure whether following code works.
        // Because when I wrote it, the latest nginx version has issue with
        // old cycle cleanup, and can never cleanup old cycle.
        // so I can't test it, may god bless you
        cln = ngx_pool_cleanup_add(cf->pool, 0);
        cln->data = (void*)(ngx_int_t)conf->cgi_stderr;
        cln->handler = ngx_http_cgi_close_fd;
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

    assert(cf->args->nelts >= 2);
    if (_strieq(args[1], "off")) {
        conf->rdns = CGI_RDNS_OFF;
    } else if (_strieq(args[1], "on")) {
        conf->rdns = CGI_RDNS_ON;
    } else if (_strieq(args[1], "double")) {
        conf->rdns = CGI_RDNS_ON | CGI_RDNS_DOUBLE;
    } else {
        return "'s first argument can only be: off | on | double";
    }

    if (cf->args->nelts >= 3) {
        if (_strieq(args[2], "required")) {
            if (conf->rdns & CGI_RDNS_ON) {
                conf->rdns |= CGI_RDNS_REQUIRED;
            } else {
                return "required can only works with on|double";
            }
        } else {
            return "'s second argument can only be required";
        }
    }

    return NGX_CONF_OK;
}


static ngx_flag_t
ngx_http_cgi_is_valid_env_name(ngx_str_t *name) {
    if (name->len <= 0) {
        return 0;
    }

    if (!isalpha(name->data[0]) && name->data[0] != '_') {
        return 0;
    }

    for (size_t i = 1; i < name->len; ++i) {
        if (!isalnum(name->data[i]) && name->data[i] != '_') {
            return 0;
        }
    }

    return 1;
}


static char *
ngx_http_cgi_add_var(ngx_conf_t *cf, ngx_command_t *cmd, void *c) {
    ngx_http_cgi_loc_conf_t            *conf = c;
    ngx_str_t                          *args = cf->args->elts;
    ngx_str_t                           combine;
    ngx_http_compile_complex_value_t    ccv;

    if (!conf->ext_vars) {
        conf->ext_vars = ngx_array_create(
            cf->pool, 4, sizeof(ngx_http_cgi_ext_var_t));
        if (!conf->ext_vars) {
            return NGX_CONF_ERROR;
        }
    }

    ngx_http_cgi_ext_var_t *ext_var = ngx_array_push(conf->ext_vars);
    if (!ext_var) {
        return NGX_CONF_ERROR;
    }

    if (!ngx_http_cgi_is_valid_env_name(&args[1])) {
        return "invalid var name";
    }
    ext_var->name = args[1];

    combine.len = args[1].len + 1 + args[2].len;
    combine.data = ngx_palloc(cf->pool, combine.len);
    if (!combine.data) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(combine.data, args[1].data, args[1].len);
    combine.data[args[1].len] = '=';
    ngx_memcpy(combine.data + args[1].len + 1, args[2].data, args[2].len);

    ngx_memzero(&ccv, sizeof(ccv));
    ccv.cf = cf;
    ccv.value = &combine;
    ccv.complex_value = &ext_var->combine;
    ccv.zero = 1;  // indicate CC to generate C safe string
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    // keep combine var, it referenced by conf->combine

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
    conf->working_dir = NGX_CONF_UNSET_PTR;
    // conf->path is initialized by ngx_pcalloc
    conf->strict_mode = NGX_CONF_UNSET;
    conf->interpreter = NGX_CONF_UNSET_PTR;
    conf->cgi_stderr = CGI_STDERR_UNSET;
    conf->rdns = NGX_CONF_UNSET;
    conf->ext_vars = NULL;

    return conf;
}


static char *
ngx_http_cgi_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_cgi_loc_conf_t  *prev = parent;
    ngx_http_cgi_loc_conf_t  *conf = child;
    ngx_http_core_loc_conf_t  *clcf;

    if (conf->enabled == NGX_CONF_UNSET) {
        if (prev->enabled != NGX_CONF_UNSET) {
            conf->enabled = prev->enabled;
            conf->script = prev->script;
        } else {
            conf->enabled = 0;
        }
    }

    ngx_conf_merge_ptr_value(conf->working_dir, prev->working_dir, NULL);
    ngx_conf_merge_str_value(conf->path, prev->path,
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    ngx_conf_merge_value(conf->strict_mode, prev->strict_mode, 1);
    ngx_conf_merge_ptr_value(conf->interpreter, prev->interpreter, NULL);
    ngx_conf_merge_value(conf->cgi_stderr, prev->cgi_stderr, CGI_STDERR_PIPE);
    ngx_conf_merge_value(conf->rdns, prev->rdns, CGI_RDNS_OFF);
    ngx_conf_merge_ptr_value(conf->ext_vars, prev->ext_vars, NULL);

    if (conf->enabled) {
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        if (clcf == NULL) {
            return NGX_CONF_ERROR;
        }

        clcf->handler = ngx_http_cgi_handler_init;
    }

    return NGX_CONF_OK;
}
