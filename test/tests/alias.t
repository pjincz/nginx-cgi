#!/usr/bin/perl

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->plan(7);
ok($t->has_module('cgi'), 'has cgi module');

###############################################################################

$t->write_file_expand('nginx.conf', <<EOF);

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /cgi {
            alias $ENV{TEST_ROOT_DIR}/cgi-bin;
            cgi on;
        }
    }
}

EOF

$t->run();

###############################################################################

like(http_get('/cgi/hello.sh'), qr/^hello$/m, 'hello');

like(http_get('/cgi/env.sh'), qr/^SCRIPT_NAME=\/cgi\/env.sh$/m, 'SCRIPT_NAME');
like(http_get('/cgi/env.sh/aaa'), qr/^PATH_INFO=\/aaa$/m, 'PATH_INFO');
# FIXME: PATH_TRANSLATED not correct
# like(http_get('/cgi/env.sh/aaa'), qr/^PATH_TRANSLATED="$ENV{TEST_ROOT_DIR}\/aaa"$/m, 'PATH_TRANSLATED');

like(http_get('/cgi/env.sh'), qr/^DOCUMENT_ROOT=$ENV{TEST_ROOT_DIR}\/cgi-bin$/m, 'DOCUMENT_ROOT');
like(http_get('/cgi/env.sh'), qr/^REQUEST_URI=\/cgi\/env.sh$/m, 'REQUEST_URI');
like(http_get('/cgi/env.sh'), qr/^SCRIPT_FILENAME=$ENV{TEST_ROOT_DIR}\/cgi-bin\/env.sh$/m, 'REQUEST_URI');
