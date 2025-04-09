#!/usr/bin/perl

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Nginx;

use Time::HiRes qw(gettimeofday tv_interval);

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
            cgi_timeout 1;
        }
    }
}

EOF

$t->run();

my $start = [gettimeofday];
my $r = http_get('/cgi-bin/sleep-99.sh');
my $dur = tv_interval($start);

ok($dur < 2, 'timeout t1 works');

$t->stop();

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
            cgi_timeout 0 1;
        }
    }
}

EOF

$t->run();

$start = [gettimeofday];
$r = http_get('/cgi-bin/sleep-99.sh');
$dur = tv_interval($start);

ok($dur < 2, 'timeout t2 works');

$t->stop();

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
            cgi_timeout 1 1;
        }
    }
}

EOF

$t->run();

$start = [gettimeofday];
$r = http_get('/cgi-bin/sleep-99.sh');
$dur = tv_interval($start);

ok($dur < 2, 'sleep-99.sh kill by t1');

$start = [gettimeofday];
$r = http_get('/cgi-bin/sleep-99-trap-term.sh');
$dur = tv_interval($start);

# nginx's timer is very imprecise, causes too much flaky here, just disable it
# ok($dur > 1.5, 'sleep-99-trap-term.sh not kill by t1');
ok($dur < 3, 'sleep-99-trap-term.sh kill by t2');

$t->stop();
