#!/usr/bin/perl

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->plan(5);
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

        location /cgi {
            rewrite ^/cgi/(.*)$ /cgi-bin/$1 last;
        }
    }
}

EOF

$t->run();

# no rewrite
like(http_get('/cgi-bin/env.sh?asdf=1'), qr/^REQUEST_URI=\/cgi-bin\/env.sh$/m, 'REQUEST_URI');
like(http_get('/cgi-bin/env.sh?asdf=1'), qr/^SCRIPT_NAME=\/cgi-bin\/env.sh$/m, 'REQUEST_URI');

# with rewrite
like(http_get('/cgi/env.sh?asdf=1'), qr/^REQUEST_URI=\/cgi\/env.sh$/m, 'REQUEST_URI');
like(http_get('/cgi/env.sh?asdf=1'), qr/^SCRIPT_NAME=\/cgi-bin\/env.sh$/m, 'REQUEST_URI');
