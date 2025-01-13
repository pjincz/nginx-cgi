# Known issues

## `PATH_TRANSLATED` impl not accurate

By rfc3875, `PATH_TRANSLATED` should point to the file that as if `$PATH_INFO`
accessed as `uri`. But that's really hard to impl on nginx, it need re-trigger
nginx's location process. And those functions are private, cannot access by
plugin directly. The another way to impl it is starting a sub-request, but it's
too expensive, and this var is really rearly used. It's really not worth to do
it. So I simply construct this var by document root and path_info vars.

## RDNS impl doesn't access /etc/hosts
