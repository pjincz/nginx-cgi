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

        location /cgi-bin {
            cgi on;
            cgi_set_var TMPDIR /tmp;
        }
    }
}

EOF

$t->run();

my $r = http_get('/cgi-bin/tmpdir.py');
like($r, qr/^HTTP\/1\.[01] 200 /, 'tmpdir script succeeds');
my (undef, $body) = split(/\r\n\r\n/, $r // '', 2);
is($body, "hex(\$TMPDIR): 2f746d70\n", 'TMPDIR is exactly /tmp');
