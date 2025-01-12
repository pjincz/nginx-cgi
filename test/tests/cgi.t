#!/usr/bin/perl

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->plan(30);
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

        location /cgi-bin {
            cgi on;
        }
    }
}

EOF

$t->run();

###############################################################################
# basic tests

like(http_get('/cgi-bin/hello.sh'), qr/^hello$/m, 'hello');
like(http_get('/cgi-bin/not-exists.sh'), qr/\HTTP\/1\.[01] 404/m, 'not found');
like(http_get('/cgi-bin/no-perm.sh'), qr/HTTP\/1\.[01] 403/m, 'no perm');
like(http_get('/cgi-bin/bad.sh'), qr/HTTP\/1\.[01] 500/m, 'bad cgi');
like(http_get('/cgi-bin/302.sh'), qr/HTTP\/1\.[01] 302/m, 'redirect');
like(http_get('/cgi-bin/no-shebang.sh'), qr/HTTP\/1\.[01] 500/m, 'no shebang');

like(http(<<EOF), qr/^a magic string$/m, 'request body');
GET /cgi-bin/cat.sh HTTP/1.0
Host: localhost
Content-Length: 14

a magic string
EOF

# security test: .. in uri should not go out of www dir
like(http_get('/../cgi-bin/hello.sh'), qr/\b400\b/m, 'hello');

# TODO: test rewrite (try_files)

###############################################################################
# environment var tests

# vars from rfc3875
# TODO: AUTH_TYPE
# TODO: CONTENT_LENGTH
# TODO: CONTENT_TYPE
like(http_get('/cgi-bin/env.sh'), qr/^GATEWAY_INTERFACE="CGI\/1.1"$/m, 'GATEWAY_INTERFACE');
like(http_get('/cgi-bin/env.sh/aaa'), qr/^PATH_INFO="\/aaa"$/m, 'PATH_INFO');
like(http_get('/cgi-bin/env.sh/aaa'), qr/^PATH_TRANSLATED="$ENV{TEST_ROOT_DIR}\/aaa"$/m, 'PATH_TRANSLATED');
like(http_get('/cgi-bin/env.sh?a=1&b=2'), qr/^QUERY_STRING="a=1&b=2"$/m, 'QUERY_STRING');
like(http_get('/cgi-bin/env.sh'), qr/^REMOTE_ADDR="127.0.0.1"$/m, 'REMOTE_ADDR');
# TODO: REMOTE_HOST
# TODO: REMOTE_IDENT
# TODO: REMOTE_USER
like(http_get('/cgi-bin/env.sh'), qr/^REQUEST_METHOD="GET"$/m, 'REQUEST_METHOD');
like(http_get('/cgi-bin/env.sh'), qr/^SCRIPT_NAME="\/cgi-bin\/env.sh"$/m, 'SCRIPT_NAME');
like(http_get('/cgi-bin/env.sh'), qr/^SERVER_NAME="localhost"$/m, 'SERVER_NAME');
like(http_get('/cgi-bin/env.sh'), qr/^SERVER_PORT="8080"$/m, 'SERVER_PORT');
like(http_get('/cgi-bin/env.sh'), qr/^SERVER_SOFTWARE="nginx\/.*"$/m, 'SERVER_SOFTWARE');

# SERVER_PROTOCOL
like(http(<<EOF), qr/^SERVER_PROTOCOL="HTTP\/1.0"$/m, 'SERVER_PROTOCOL 1.0');
GET /cgi-bin/env.sh HTTP/1.0
Host: localhost

EOF
like(http(<<EOF), qr/^SERVER_PROTOCOL="HTTP\/1.1"$/m, 'SERVER_PROTOCOL 1.1');
GET /cgi-bin/env.sh HTTP/1.1
Host: localhost
Connection: close

EOF

# HTTP_ vars
like(http(<<EOF), qr/^HTTP_ACCEPT="\*\/\*"$/m, 'HTTP_ACCEPT');
GET /cgi-bin/env.sh HTTP/1.0
Host: localhost
Accept: */*

EOF
like(http(<<EOF), qr/^HTTP_AAA="123"$/m, 'HTTP_AAA');
GET /cgi-bin/env.sh HTTP/1.0
Host: localhost
Aaa: 123

EOF
# security test: Authorization should not be exposed as environment
unlike(http(<<EOF), qr/HTTP_AUTHORIZATION/m, 'no HTTP_AUTHORIZATION');
GET /cgi-bin/env.sh HTTP/1.0
Host: localhost
Authorization: Basic dXNlcjpwYXNz

EOF

# vars from apache2
like(http_get('/cgi-bin/env.sh'), qr/^DOCUMENT_ROOT="$ENV{TEST_ROOT_DIR}"$/m, 'DOCUMENT_ROOT');
like(http_get('/cgi-bin/env.sh'), qr/^REMOTE_PORT=".*"$/m, 'REMOTE_PORT');
like(http_get('/cgi-bin/env.sh'), qr/^REQUEST_SCHEME="http"$/m, 'REQUEST_SCHEME');
like(http_get('/cgi-bin/env.sh'), qr/^REQUEST_URI="\/cgi-bin\/env.sh"$/m, 'REQUEST_URI');
like(http_get('/cgi-bin/env.sh'), qr/^SCRIPT_FILENAME="$ENV{TEST_ROOT_DIR}\/cgi-bin\/env.sh"$/m, 'SCRIPT_FILENAME');
like(http_get('/cgi-bin/env.sh'), qr/^SERVER_ADDR="127.0.0.1"$/m, 'SERVER_ADDR');

###############################################################################
# feature tests

# options
# TODO: test cgi_path
# TODO: test cgi_strict
# TODO: test cgi_interpreter
# TODO: test cgi_x_only
# TODO: test cgi_stderr

# extra features
# TODO: test http 1.1 chunked response

###############################################################################
# security tests

# TODO: location tail / check
# TODO: document root always starts with / or .
# TODO: find correct script when tail / in root path
# TODO: hop-by-hop header not allow in cgi output

# warn http_get('/cgi-bin/env.sh');
