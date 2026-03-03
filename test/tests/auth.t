#!/usr/bin/perl

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->plan(6);
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

        auth_basic "private area";
        auth_basic_user_file passwd;

        location /cgi-bin {
            cgi on;
            cgi_set_var AUTH_TYPE "Basic";
            cgi_set_var REMOTE_USER "$remote_user";
            cgi_set_var MY_AUTHORIZATION "$http_authorization";
        }
    }
}

EOF

$t->write_file_expand('passwd', <<'EOF');
aaa:$apr1$AZoU8XMC$iaMZBrzLJi16fvlpzhiAB/
EOF

$t->run();

###############################################################################

# REMOTE_USER and AUTH_TYPE
my $r = http(<<EOF);
GET /cgi-bin/env.sh HTTP/1.0
Host: localhost
Authorization: Basic YWFhOmJiYg==

EOF
like($r, qr/REMOTE_USER=aaa/m, 'REMOTE_USER');
like($r, qr/AUTH_TYPE=Basic/m, 'AUTH_TYPE');
unlike($r, qr/HTTP_AUTHORIZATION/m, 'no HTTP_AUTHORIZATION');
like($r, qr/MY_AUTHORIZATION=Basic YWFhOmJiYg==/m, 'MY_AUTHORIZATION');


# bad password
$r = http(<<EOF);
GET /cgi-bin/env.sh HTTP/1.0
Host: localhost
Authorization: Basic YWFhOmJi

EOF
like($r, qr/HTTP\/1\.[01] 401/m, 'bad password');
