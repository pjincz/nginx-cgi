#!/usr/bin/perl

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->plan(9);
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
            cgi_x_only on;
        }
    }
}

EOF

$t->run();

like(http_get('/cgi-bin/no-perm.sh'), qr/HTTP\/1\.[01] 403/m, 'x-only-on no-perm');
like(http_get('/cgi-bin/no-shebang.sh'), qr/HTTP\/1\.[01] 500/m, 'x-only-on no-shabang');

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
            cgi_x_only off;
        }
    }
}

EOF

$t->run();

like(http_get('/cgi-bin/no-perm.sh'), qr/HTTP\/1\.[01] 500/m, 'x-only-off no-perm');
like(http_get('/cgi-bin/no-shebang.sh'), qr/HTTP\/1\.[01] 500/m, 'x-only-off no-shebang');

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
            cgi_x_only on;
            cgi_interpreter /usr/bin/bash;
        }
    }
}

EOF

$t->run();

like(http_get('/cgi-bin/no-perm.sh'), qr/HTTP\/1\.[01] 403/m, 'intp x-only-on no-perm');
like(http_get('/cgi-bin/no-shebang.sh'), qr/HTTP\/1\.[01] 200/m, 'intp x-only-on no-shebang');

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
            cgi_x_only off;
            cgi_interpreter /usr/bin/bash;
        }
    }
}

EOF

$t->run();

like(http_get('/cgi-bin/no-perm.sh'), qr/HTTP\/1\.[01] 200/m, 'intp x-only-off no-perm');
like(http_get('/cgi-bin/no-shebang.sh'), qr/HTTP\/1\.[01] 200/m, 'intp x-only-off no-shebang');

$t->stop();
