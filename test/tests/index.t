#!/usr/bin/perl

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->plan(3);
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

        if (-d $document_root$uri) {
            rewrite ^ /cgi-bin/ls.sh$uri last;
        }

        location /cgi-bin {
            cgi on;
        }
    }
}

EOF

$t->run();

like(http_get('/'), qr/cgi-bin/, 'test cgi for indexing dir');
like(http_get('/cgi-bin'), qr/hello.sh/, 'test cgi for indexing dir 2');
