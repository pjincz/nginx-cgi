#!/usr/bin/perl

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Nginx;

use List::Util qw(shuffle);

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->plan(21);
ok($t->has_module('cgi'), 'has cgi module');

###############################################################################

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;
master_process off;

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

my @tasks = ();
for (my $i = 0; $i < 20; $i++) {
    my $s = Test::Nginx::http_start(<<EOF, start=>1);
POST /cgi-bin/cat.sh HTTP/1.1
Host: localhost
Connection: close
Content-Type: plain/text
Transfer-Encoding: chunked

EOF

    push @tasks, $s;
}

sleep(1);

@tasks = shuffle(@tasks);
for (my $i = 0; $i < scalar @tasks; $i++) {
    $tasks[$i]->print("4\r\nping\r\n0\r\n\r\n");
    my $r = Test::Nginx::http_end($tasks[$i]);
    like($r, qr/200/);
}
