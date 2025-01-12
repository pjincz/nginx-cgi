#!/usr/bin/perl

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->plan(19);
ok($t->has_module('cgi'), 'has cgi module');

###############################################################################

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /cgi-bin/ {
            cgi on;
        }
    }
}

EOF

$t->run();

###############################################################################

# basic
like(http_get('/cgi-bin/hello.sh'), qr/^hello$/m, 'hello');
like(http_get('/cgi-bin/not-exists.sh'), qr/404/m, 'not found');
like(http_get('/cgi-bin/no-perm.sh'), qr/403/m, 'no perm');
# TODO: test cgi status response
# TODO: test request body
# TODO: test alias
# TODO: test rewrite (try_files)

# vars from rfc3875
# TODO: AUTH_TYPE
# TODO: CONTENT_LENGTH
# TODO: CONTENT_TYPE
like(http_get('/cgi-bin/env.sh'), qr/^GATEWAY_INTERFACE="CGI\/1.1"$/m, 'GATEWAY_INTERFACE');
like(http_get('/cgi-bin/env.sh/aaa'), qr/^PATH_INFO="\/aaa"$/m, 'PATH_INFO');
# TODO: PATH_TRANSLATED
like(http_get('/cgi-bin/env.sh?a=1&b=2'), qr/^QUERY_STRING="a=1&b=2"$/m, 'QUERY_STRING');
like(http_get('/cgi-bin/env.sh'), qr/^REMOTE_ADDR="127.0.0.1"$/m, 'REMOTE_ADDR');
# TODO: REMOTE_HOST
# TODO: REMOTE_IDENT
# TODO: REMOTE_USER
like(http_get('/cgi-bin/env.sh'), qr/^REQUEST_METHOD="GET"$/m, 'REQUEST_METHOD');
like(http_get('/cgi-bin/env.sh'), qr/^SCRIPT_NAME="\/cgi-bin\/env.sh"$/m, 'SCRIPT_NAME');
like(http_get('/cgi-bin/env.sh'), qr/^SERVER_NAME="localhost"$/m, 'SERVER_NAME');
like(http_get('/cgi-bin/env.sh'), qr/^SERVER_PORT="8080"$/m, 'SERVER_PORT');
# TODO: SERVER_PROTOCOL
like(http_get('/cgi-bin/env.sh'), qr/^SERVER_SOFTWARE="nginx\/.*"$/m, 'SERVER_SOFTWARE');
# TODO: X_ vars

# vars from apache2
like(http_get('/cgi-bin/env.sh'), qr/^DOCUMENT_ROOT="$ENV{TEST_ROOT_DIR}"$/m, 'DOCUMENT_ROOT');
like(http_get('/cgi-bin/env.sh'), qr/^REMOTE_PORT=".*"$/m, 'REMOTE_PORT');
like(http_get('/cgi-bin/env.sh'), qr/^REQUEST_SCHEME="http"$/m, 'REQUEST_SCHEME');
like(http_get('/cgi-bin/env.sh'), qr/^REQUEST_URI="\/cgi-bin\/env.sh"$/m, 'REQUEST_URI');
like(http_get('/cgi-bin/env.sh'), qr/^SCRIPT_FILENAME="$ENV{TEST_ROOT_DIR}\/cgi-bin\/env.sh"$/m, 'SCRIPT_FILENAME');
like(http_get('/cgi-bin/env.sh'), qr/^SERVER_ADDR="127.0.0.1"$/m, 'SERVER_ADDR');
# TODO: HTTP_ACCEPT
# TODO: HTTP_HOST
# TODO: HTTP_USER_AGENT

# options
# TODO: test cgi_path
# TODO: test cgi_strict
# TODO: test cgi_interpreter
# TODO: test cgi_x_only
# TODO: test cgi_stderr

# extra features
# TODO: test http 1.1 chunked response

# security
# TODO: .. in path
# TODO: location tail / check
# TODO: document root always starts with / or .
# TODO: find correct script when tail / in root path
# TODO: hop-by-hop header not allow in cgi output

# warn http_get('/cgi-bin/env.sh');
