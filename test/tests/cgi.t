#!/usr/bin/perl

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->plan(4);
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
# TODO: alias support

# vars from rfc3875
# TODO: AUTH_TYPE
# TODO: CONTENT_LENGTH
# TODO: CONTENT_TYPE
# TODO: GATEWAY_INTERFACE
# TODO: PATH_INFO
# TODO: PATH_TRANSLATED
# TODO: QUERY_STRING
# TODO: REMOTE_ADDR
# TODO: REMOTE_HOST
# TODO: REMOTE_IDENT
# TODO: REMOTE_USER
# TODO: REQUEST_METHOD
# TODO: SCRIPT_NAME
# TODO: SERVER_NAME
# TODO: SERVER_PORT
# TODO: SERVER_PROTOCOL
# TODO: SERVER_SOFTWARE
# TODO: X_ vars

# vars from apache2
# TODO: DOCUMENT_ROOT
# TODO: REMOTE_PORT
# TODO: REQUEST_SCHEME
# TODO: REQUEST_URI
# TODO: SCRIPT_FILENAME
# TODO: SERVER_ADDR
# TODO: HTTP_ACCEPT
# TODO: HTTP_HOST
# TODO: HTTP_USER_AGENT
# TODO: CONTENT_LENGTH
# TODO: CONTENT_TYPE

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
