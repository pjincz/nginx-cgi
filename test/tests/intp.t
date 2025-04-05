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

like(http_get('/cgi-bin/no-perm.sh'), qr/HTTP\/1\.[01] 403/m, 'no-perm');
like(http_get('/cgi-bin/no-shebang.sh'), qr/HTTP\/1\.[01] 500/m, 'no-shebang');

$t->stop();

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
            cgi_interpreter /bin/sh;
        }
    }
}

EOF

$t->run();

like(http_get('/cgi-bin/no-perm.sh'), qr/HTTP\/1\.[01] 200/m, 'intp no-perm');
like(http_get('/cgi-bin/no-shebang.sh'), qr/HTTP\/1\.[01] 200/m, 'intp no-shebang');

$t->stop();

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
            cgi_interpreter /usr/bin/env URI=\$uri;
        }
    }
}

EOF

$t->run();

like(http_get('/cgi-bin/env.sh'), qr/URI=\/cgi-bin\/env.sh/m, 'intp var');

$t->stop();
