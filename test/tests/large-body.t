#!/usr/bin/perl

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Nginx;

use HTTP::Tiny;
use Digest::SHA qw(sha1_hex);
use MIME::Base64 qw(encode_base64);

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
# A body larger than the request buffer must keep flowing to CGI stdin.

my $body = "x" x (512 * 1024);
my $url = "http://127.0.0.1:" . port(8080) . "/cgi-bin/base64.sh";
my $http = HTTP::Tiny->new(timeout => 5);
my $response = $http->post($url, { content => $body });
ok($response->{success}, 'large request completes');

my $expected = encode_base64($body);
is(sha1_hex($response->{content}), sha1_hex($expected), 'complete base64 output');
