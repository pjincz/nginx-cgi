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

        location / {
            cgi pass $document_root/cgi-bin/env.sh;
        }
    }
}

EOF

$t->run();

like(http_get('/hello/world'), qr/^REQUEST_URI=\/hello\/world$/m, 'hello');
like(http_get('/hello/world'), qr/^PATH_INFO=\/hello\/world$/m, 'hello');
like(http_get('/hello/world'), qr/^SCRIPT_FILENAME=.*env.sh$/m, 'hello');

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

        location / {
            cgi_pass $document_root/cgi-bin/env.sh;
        }
    }
}

EOF

$t->run();

like(http_get('/hello/world'), qr/^REQUEST_URI=\/hello\/world$/m, 'hello');
like(http_get('/hello/world'), qr/^PATH_INFO=\/hello\/world$/m, 'hello');
like(http_get('/hello/world'), qr/^SCRIPT_FILENAME=.*env.sh$/m, 'hello');

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

        location / {
            cgi pass $document_root/cgi-bin/argv.sh 111 222;
        }
    }
}

EOF

$t->run();

like(http_get('/'), qr/^ARGV=111 222$/m, 'argv');

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

        location / {
            cgi_pass $document_root/cgi-bin/argv.sh 111 222;
        }
    }
}

EOF

$t->run();

like(http_get('/'), qr/^ARGV=111 222$/m, 'argv');

$t->stop();
