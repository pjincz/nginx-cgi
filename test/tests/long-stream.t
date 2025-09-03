#!/usr/bin/perl

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Nginx;

use HTTP::Tiny;
use Digest::SHA qw(sha1_hex);

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
        }
    }
}

EOF

$t->run();

###############################################################################
# basic tests

my $url = "http://127.0.0.1:8080/cgi-bin/yes.sh?w=yes&n=20000000";

my $http = HTTP::Tiny->new;
my $response = $http->get($url);
ok($response->{success});

my $body = $response->{content};
my $sha1 = sha1_hex($body);

is($sha1, "ba086b2d0d62148d7a55c6936883d25399ea3881");