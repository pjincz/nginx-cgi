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
# Http 1.0
# for http 1.0, crashing of cgi should triggers TCP RST

my $r = http(<<EOF);
GET /cgi-bin/crash-in-middle.sh HTTP/1.0
Host: localhost

EOF

is($r, undef, 'http 1.0 crash causes TCP RST');

$r = http(<<EOF);
GET /cgi-bin/kill-in-middle.sh HTTP/1.0
Host: localhost

EOF

is($r, undef, 'http 1.0 kill causes TCP RST');

###############################################################################
# Http 1.1
# for http 1.1, crashing of cgi will cause missing tail chunk

$r = http(<<EOF);
GET /cgi-bin/crash-in-middle.sh HTTP/1.1
Host: localhost

EOF

like($r, qr/chunk/, 'http 1.1 streaming works in chunk mode');
unlike($r, qr/\n0\r\n/, 'http 1.1 crash causes mssing tail chunk');

$r = http(<<EOF);
GET /cgi-bin/kill-in-middle.sh HTTP/1.1
Host: localhost

EOF

like($r, qr/chunk/, 'http 1.1 streaming works in chunk mode');
unlike($r, qr/\n0\r\n/, 'http 1.1 kill causes mssing tail chunk');
