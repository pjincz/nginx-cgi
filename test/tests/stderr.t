#!/usr/bin/perl

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->plan(21);
ok($t->has_module('cgi'), 'has cgi module');

sub truncate_file {
    my ($t, $fname) = @_;
    open my $fh, '>', "$t->{_testdir}/$fname";
    close $fh;
}

###############################################################################

sub run_test {
    my ($t, $opt) = @_;

    my $opt_line = '';
    if ($opt ne '') {
        $opt_line = "cgi_stderr $opt;";
    }

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
            $opt_line
        }
    }
}
EOF

    # truncate log before each run, to avoid pollution across tests 
    truncate_file($t, 'error.log');

    $t->run();

    like(http_get('/cgi-bin/stderr.sh'), qr/okay/, 'call stderr.sh');

    $t->stop();
}

run_test($t, '');
like($t->read_file('error.log'), qr/\[warn\].*a_magic_string/);

run_test($t, 'off');
unlike($t->read_file('error.log'), qr/a_magic_string/);

run_test($t, 'info');
like($t->read_file('error.log'), qr/\[info\].*a_magic_string/);

run_test($t, 'warn');
like($t->read_file('error.log'), qr/\[warn\].*a_magic_string/);

run_test($t, 'error');
like($t->read_file('error.log'), qr/\[error\].*a_magic_string/);

run_test($t, 'crit');
like($t->read_file('error.log'), qr/\[crit\].*a_magic_string/);

run_test($t, 'alert');
like($t->read_file('error.log'), qr/\[alert\].*a_magic_string/);

run_test($t, 'emerg');
like($t->read_file('error.log'), qr/\[emerg\].*a_magic_string/);

run_test($t, 'stderr');
like($t->read_file('error.log'), qr/^a_magic_string$/m);

run_test($t, "file $t->{_testdir}/cgierr.log");
like($t->read_file('cgierr.log'), qr/a_magic_string/);

# this test set may generate log with level >= alert, this will cause an error
# from nginx test framework, just clean the log to prevent it
truncate_file($t, 'error.log');
