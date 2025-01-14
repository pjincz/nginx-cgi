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
            cgi_stderr $t->{_testdir}/cgierr.log;
        }
    }
}

EOF

$t->run();

like(http_get('/cgi-bin/stderr.sh?test1'), qr/okay/, 'write log 1');
like(http_get('/cgi-bin/stderr.sh?test2'), qr/okay/, 'write log 2');

open my $fh, '<', "$t->{_testdir}/cgierr.log" or die "Cannot open file: $!";
my $cgierr = do { local $/; <$fh> };
close $fh;

like($cgierr, qr/test1/, 'test1');
like($cgierr, qr/test2/, 'test2');
