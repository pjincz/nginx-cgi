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

        auth_basic "private area";
        auth_basic_user_file passwd;

        location /cgi-bin {
            cgi on;
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
# Authorization header without auth enabled will not set auth related vars
my $r = http(<<EOF);
GET /cgi-bin/env.sh HTTP/1.0
Host: localhost
Authorization: Basic YWFhOmJiYg==

EOF
like($r, qr/REMOTE_USER="aaa"/m, 'REMOTE_USER');
like($r, qr/AUTH_TYPE="Basic"/m, 'AUTH_TYPE');
