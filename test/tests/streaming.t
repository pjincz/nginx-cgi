#!/usr/bin/perl

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->plan(11);
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

        location /cgi-bin {
            cgi on;
        }
    }
}

EOF

$t->run();

###############################################################################
# down streaming

my $r = http(<<EOF);
GET /cgi-bin/delay.sh HTTP/1.0
Host: localhost

EOF
like($r, qr/^delayed hello$/m, 'http 1.0 output');
unlike($r, qr/chunked/m, 'http 1.0 do not support chunked');


$r = http(<<EOF);
GET /cgi-bin/delay.sh HTTP/1.1
Host: localhost
Connection: close

EOF
like($r, qr/^delayed hello$/m, 'http 1.1 output');
like($r, qr/chunked/m, 'http 1.1 support chunked');
like($r, qr/\ne\r\n/, 'chunk size 14 in hex');
like($r, qr/\n0\r\n/, 'tail chunk size 0 in hex');

###############################################################################
# up streaming

# http 1.0 does not support upstreaming

my $s = Test::Nginx::http_start(<<EOF, start=>1);
POST /cgi-bin/cat.sh HTTP/1.1
Host: localhost
Connection: close
Content-Type: plain/text
Transfer-Encoding: chunked

EOF

sleep(1);
$s->print("4\r\nping\r\n0\r\n\r\n");
$r = Test::Nginx::http_end($s);

like($r, qr/\nping\r\n/m, 'cat output');
like($r, qr/chunked/m, 'cat chunked');
like($r, qr/\n4\r\n/, 'chunk size 4 in hex');
like($r, qr/\n0\r\n/, 'tail chunk size 0 in hex');
