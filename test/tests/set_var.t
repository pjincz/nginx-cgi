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

        location /cgi-bin {
            cgi on;
            cgi_set_var XXX "123";
            cgi_set_var YYY "$remote_addr";
            cgi_set_var QUERY_STRING "123";
        }
    }
}

EOF

$t->run();

my $r = http_get('/cgi-bin/env.sh');
like($r, qr/XXX="123"/, 'custom var x');
like($r, qr/YYY="127.0.0.1"/, 'custom var y');
like($r, qr/QUERY_STRING="123"/, 'replace QUERY_STRING');
