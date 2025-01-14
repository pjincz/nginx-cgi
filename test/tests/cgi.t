#!/usr/bin/perl

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->plan(36);
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
like(http_get('/cgi-bin/not-exists.sh'), qr/HTTP\/1\.[01] 404/m, 'not found');
like(http_get('/cgi-bin/no-perm.sh'), qr/HTTP\/1\.[01] 403/m, 'no perm');
like(http_get('/cgi-bin/bad.sh'), qr/HTTP\/1\.[01] 500/m, 'bad cgi');
like(http_get('/cgi-bin/302.sh'), qr/HTTP\/1\.[01] 302/m, 'redirect');
like(http_get('/cgi-bin/no-shebang.sh'), qr/HTTP\/1\.[01] 500/m, 'no shebang');

# security test: not allowed to cross location directory boundary
like(http_get('/cgi-bin-shouldnot-work.sh'), qr/HTTP\/1\.[01] 403/m, 'no cross boundary');

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

# rfc3875 vars
like(http_get('/cgi-bin/env.sh'), qr/^GATEWAY_INTERFACE="CGI\/1.1"$/m, 'GATEWAY_INTERFACE');
like(http_get('/cgi-bin/env.sh/aaa'), qr/^PATH_INFO="\/aaa"$/m, 'PATH_INFO');
like(http_get('/cgi-bin/env.sh/aaa'), qr/^PATH_TRANSLATED="$ENV{TEST_ROOT_DIR}\/aaa"$/m, 'PATH_TRANSLATED');
like(http_get('/cgi-bin/env.sh?a=1&b=2'), qr/^QUERY_STRING="a=1&b=2"$/m, 'QUERY_STRING');
like(http_get('/cgi-bin/env.sh'), qr/^REMOTE_ADDR="127.0.0.1"$/m, 'REMOTE_ADDR');
# TODO: REMOTE_HOST
like(http_get('/cgi-bin/env.sh'), qr/^REQUEST_METHOD="GET"$/m, 'REQUEST_METHOD');
like(http_get('/cgi-bin/env.sh/asdf'), qr/^SCRIPT_NAME="\/cgi-bin\/env.sh"$/m, 'SCRIPT_NAME');
like(http_get('/cgi-bin/env.sh'), qr/^SERVER_NAME="localhost"$/m, 'SERVER_NAME');
like(http_get('/cgi-bin/env.sh'), qr/^SERVER_PORT="8080"$/m, 'SERVER_PORT');
like(http_get('/cgi-bin/env.sh'), qr/^SERVER_SOFTWARE="nginx\/.*"$/m, 'SERVER_SOFTWARE');

# CONTENT_LENGTH && CONTENT_TYPE
my $r = http(<<EOF);
GET /cgi-bin/env.sh HTTP/1.0
Host: localhost
Content-Length: 14
Content-Type: text/plain

a magic string
EOF
like($r, qr/^CONTENT_LENGTH="14"$/m, 'CONTENT_LENGTH');
like($r, qr/^CONTENT_TYPE="text\/plain"$/m, 'CONTENT_TYPE');

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

# REMOTE_USER and AUTH_TYPE
# Authorization header without auth enabled will not set auth related vars
$r = http(<<EOF);
GET /cgi-bin/env.sh HTTP/1.0
Host: localhost
Authorization: Basic YWFhOmJiYg==

EOF
unlike($r, qr/REMOTE_USER/m, 'no REMOTE_USER');
unlike($r, qr/AUTH_TYPE/m, 'no AUTH_TYPE');

# other rfc3875 vars:
#   REMOTE_IDENT: no plan to support, due to security reason

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
# TODO: test cgi_stderr

###############################################################################
# security tests

like(http_get('/cgi-bin/hop.sh'), qr/HTTP\/1\.[01] 500/m, 'hop-by-hop header not allowed');
