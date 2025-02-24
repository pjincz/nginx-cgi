# nginx-cgi plugin

Brings CGI support to [Nginx](https://github.com/nginx/nginx) and
[Angie](https://github.com/webserver-llc/angie) webserver.

| OS      | Distribution                                 | Nginx  | Angie  |
| ------- | -------------------------------------------- | ------ | ------ |
| Linux   | Ubuntu 24.04 and Debian 12                   | Tested | Tested |
| Darwin  | MacOS 15.1                                   | Tested | Tested |
| BSD     | FreeBSD 14.2 and OpenBSD 7.6                 | Tested | Tested |
| Solaris | OmniOS r1510521                              | Tested | Tested |
| Windows | No plan, nginx barely supports Windows       |        |        |

## Before everything

CGI is neither a demon nor an angel. It is simply a tool. Just like a chef's
knife in the hands of a cook or a sword in the hands of a warrior, you won't use
a sword for cooking, nor you take a chef's knife to the battlefield. The same
goes for CGI, it has its appropriate scenarios, and it should not be misused or
demonized.

CGI is good for:

* Low frequency applications, such as system management
* Resource limited systems, such as embeding system
* Low budget projects, such as personal website
* Prototyping, for fast iterate

CGI is bad for:

* High QPS
* High traffic
* High concurrency

## Quick start (with Debian 12+, Ubuntu 24.04+)

Build and install:

```sh
# checkout source code
git clone https://github.com/pjincz/nginx-cgi
cd nginx-cgi

# install required build tool
sudo apt install build-essential devscripts dpkg-dev fakeroot -y

# install build dependencies
# if you haven't installed nginx before, this command will install nginx either
sudo apt build-dep . -y

# build with debuild
debuild -us -uc

# install build result
dpkg -i ../libnginx-mod-http-cgi_*_amd64.deb 
```

Then enable cgi in nginx. If you have a newly installed nginx, you can find a
default site at `/etc/nginx/sites-enabled/default`. The default one looks like
this:

```text
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/html;

    index index.html index.htm index.nginx-debian.html;

    server_name _;

    location / {
        try_files $uri $uri/ =404;
    }
}
```

The default `root` points to `/var/www/html`, keep it as it as, and add
following section after `location /` section.

```text
    location /cgi-bin {
        cgi on;
    }
```

The newly added section means, for all request under `/cgi-bin`, turns on cgi
support. Now restart nginx:

```sh
systemctl restart nginx
```

Save following content to /var/www/html/cgi-bin/hello.sh

```sh
#!/bin/bash

echo "Content-Type: text/plain"
echo

echo Hello CGI
```

Add x perm to cgi script:

```sh
chmod +x /var/www/html/cgi-bin/hello.sh
```

Now, try it:

```sh
curl http://127.0.0.1/cgi-bin/hello.sh
```

If you nothing wrong, you will get an output of `Hello CGI`.

## Build

If you are using latest deb based system, such as Debian and Ubuntu, and not
willing to debug the plugin, you can just following the `Quick start` to get a
usable deb package.

If you are using Angie, the cgi plugin has already in Angie's official repo.
Please have a look here:
<https://en.angie.software/angie/docs/installation/oss_packages/#install-thirdpartymodules-oss>

Manual build guide:

1. Checkout nginx and this plugin

   ```sh
   cd an-empty-dir
   git clone https://github.com/nginx/nginx
   git clone https://github.com/pjincz/nginx-cgi
   ```

2. Generate makefile in nginx dir

   ```sh
   cd nginx
   ./auto/configure --add-dynamic-module=$PWD/../nginx-cgi [...other option...]
   ```

   If you want to debug the plugin, you may also want `--with-debug`.

   If you want to build a module compatible with system's nginx, you need run
   `nginx -V` to checkout system nginx's build options first.

3. Make the binary

   ```sh
   make
   ```

If everything is good, then you will find `ngx_http_cgi_module.so` under `objs`
directory.

## Usage

### Loading plugin

If this plugin is installed to nginx's default module path (such as
`/usr/lib/nginx/modules`), the plugin will be loaded automatically.
Otherwise, you need to manually load the plugin by `load_module`.

Add following statement to nginx's top level context to load the plugin:

```text
load_module <dir-of-plugin>/ngx_http_cgi_module.so;
```

### Enable cgi

After loading the plugin, you can add `cgi on` to location contexts to enable
cgi. Example:

```text
location /cgi-bin {
    cgi on;
}
```

Once cgi turned on on a location, all nested locations will also have cgi turned
on. If you want to disable cgi for a child location, just use `cgi off`.

When the location is accessed, nginx-cgi will find the script under the document
root (it's specified by `root` statement). For example, if you have specify the
document root as `/var/www/html`, then when you access `/cgi-bin/hello.sh`,
`/var/www/html/cgi-bin/hello.sh` will be executed.

Nginx-cgi also support `alias`, it like `root` statement in nginx, the only
difference is the location prefix will be removed from uri. For example, if you
want `/cgi/hello.sh` also reference to the same script, you can do this:

```text
location /cgi {
    alias /var/www/html/cgi-bin;
    cgi on;
}
```

### Hello script

A cgi script can be wrotten by any language. Here's an exmaple with shell. You
can save it to `/var/www/html/cgi-bin/hello.sh` for testing (if you didn't
change the default document root):

```sh
#!/bin/sh

echo "Content-Type: text/plain"
echo "Status: 200 OK"
echo

echo "Hello world"
```

The first line of the script is shebang. If you clearly set `cgi_interpreter`,
it's okay to remove this line, otherwise missing of shebang will causes a 500
error. Some shell allows script be executable even without shebang, but it's not
allowed here. If a script runable by shell, but return 500 error, check the
shebang.

The output of cgi script contains 2 sections: the header section and body
section. The first 2 `echo` statements output the header section, and the last
`echo` statement outputs the body section. The `echo` statement in middle
outputs the separator. Both header section and body section can be empty, but
the separator is mandatory. Missing of separator will causes an 500 error.

All lines in header section will be parsed as normal http response header line.
And then passed to the client side. There's one special header `Status`, it will
be passed in response status line. If `cgi_strict` is on, nginx-cgi will check
all cgi output headers, and 500 error will be responsed if invalid header found.
Otherwise, invalid headers will be forwarded to client side too. It's fully
recommanded to keep `cgi_strict` on.

After separator, all output will be sent to client as body as it is.

### x permission

After all, you need to add the x permission to the file:

```sh
chmod +x /var/www/html/cgi-bin/hello.sh
```

Nginx-cgi will check file's x permission before executing it. If the file has
no x permission. A 403 error will be return to the client.

This behaviour can be changed by turning off `cgi_x_only` option. If you want to
do this, don't forget to set `cgi_interpreter` as well, otherwise you will got
a 500 error.

### Request header

Request headers will be parsed and then translated to environment variables and
then passed to cgi script.

For example, you can find the query string in `QUERY_STRING` environment var.
And access `Http-Accept` by `HTTP_ACCPET`.

Here's an example:

```sh
#!/bin/sh
echo ""

echo "query string: $QUERY_STRING"
echo "http accept: $HTTP_ACCEPT"
```

For full list of environment variables, see environment session.

### Request body

The request body will be passed via stdin. Here's an example to read all request
body and echo it:

```sh
#!/bin/sh
echo ""

body=$(cat)

echo "request body: $body"
```

### Streaming

Nginx-cgi has streaming support for both request and response body. For example,
we can implement a simplest online caculator by `bc`:

```sh
#!/bin/sh
echo ""

bc 2>&1
```

Then we can test our caculator by `curl`:

```sh
curl 127.0.0.1/cgi-bin/bc.sh --no-progress-meter -T .
```

The nginx-cgi plugin is smart enough to choose the correct way to return the
request body. If it got all output soon enough, it will output the body in once.
If the output is delayed, it will output the body chunkly(HTTP 1.1) or
streamingly (HTTP 1.0).

### Hop-by-hop http headers

Hop-by-hop http headers are not allowed in cgi script output. If it appears
in response here, a 500 error will response to the client.

For more information:
<https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#hop-by-hop_headers>

## Manual

### Options

#### `cgi <on|off>`

Enable or disable cgi module on giving location block.

Default: off

#### `cgi_path <PATH>`

Change cgi script PATH environment variable

Default: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

#### `cgi_strict <on|off>`

Enable or disable strict mode.

When strict mode turns on, bad cgi header will cause 500 error. When strict mode
turns off, bad cgi header be forward as it is.

Default: on

#### `cgi_interpreter <interpreter> [args...]`

Set interpreter and interpreter args for cgi script.

When this option is not empty, cgi script will be run with giving interpreter.
Otherwise, script will be executed directly.

Default: empty

#### `cgi_x_only <on|off>`

Enable or disable x-only mode.

When this option turns on, only file with x perm will be treated as cgi script.
Otherwise 403 will be returned. If this option turns off, the cgi plugin will
try to execute the script no matter whther x perm exists. Note: this option only
meanful if `cgi_interpreter` is set.

Default: on

#### `cgi_set_var <name> <value>`

Add and pass extra environment variables to CGI script. The first argument of
this command is the name of final environment variable. It should contains only
alphabets, numbers and underscore, and doesn't start with number. The second
argument of this command is the value express of the var. It can contains nginx
variables, see <https://nginx.org/en/docs/varindex.html> for more details.

This option can appears more than 1 time to set multiple variables. If more than
one option set the same var, then the last one works. These directives are
inherited from the previous configuration level if and only if there's no
cgi_set_var directives defined on the current level.

The option also can be used to override standard CGI vars. This may be useful in
some case, for example hacking old CGI script or simulate standard vars that are
not supported by this plugin now (Such as `PATH_TRANSLATED`, `REMOTE_IDENT`).
But it's not recommanded, it may introduce confusing issues to your system.

#### `cgi_stderr <path>`

Redirect cgi stderr to giving file.

By default, nginx-cgi grab cgi script's stderr output and dump it to nginx log.
But this action is somewhat expensive, because it need to create an extra
connection to listen stderr output. If you want to avoid this, you can use this
option to redirect cgi script's stderr output to a file. Or you can even discard
all stderr output by redirect to `/dev/null`. Also you can use this to redirect
all stderr output to nginx's stderr by set it as `/dev/stderr`.

#### `cgi_rdns <on|off|double> [required]`

Enable or disable reverse dns.

off: disable rdns feature.

on: Do reverse dns before launching cgi script, and pass rdns result to cgi
    script via `REMOTE_HOST` environment variable.

double: After reverse dns, do a forward dns again to check the rdns result. if
        result matches, pass result as `REMOTE_HOST`.

required: If rdns failed, 403, 503 or 500 returns to the client. Depends on the
          failure reason of rdns.

If you turns on this option, you need to setup a `resolver` in nginx too.
Otherwise you will get an error of `no resolver defined to resolve`.

author notes: do not enable this option, it will makes every request slower.
              this feature can be easily implemented by `dig -x` or `nslookup`
              in script when need. the only reason I impled this is just to make
              the module fully compliant with the rfc3875 standard.

### Standard Environment Variables

Nginx-cgi implemented almost all rfc3875 standard variables. If they cannot
cover all of your usage, you can add your own variable by `cgi_set_var`. Also
you can override standard variables by `cgi_set_var` if you want.

* `AUTH_TYPE`, `REMOTE_USER` (rfc3875 standard)

If cgi script is behind an authorization module (such as
`ngx_http_auth_basic_module`), and the authorization is succeed, the value is
set to auth type (such as `Basic`) and authorized user.

If no authorization module enabled, no matter client passes autoriazation header
or not. Those 2 fields are not present.

`Authorization` header is not visible in cgi script for security reason.

* `CONTENT_LENGTH`, `CONTENT_TYPE` (rfc3875 standard)

Same to request header `Content-Length` and `Content-Type`.

* `GATEWAY_INTERFACE` (rfc3875 standard)

Always be `CGI/1.1` in this plugin.

* `PATH_INFO` (rfc3875 standard)

Let's say if you have a script under `/cgi-bin/hello.sh`, and you access
`http://127.0.0.1/cgi-bin/hello.sh/somewhat`.

Then `PATH_INFO` contains the string `/somewhat`.

This variable is really useful for dynamic content generating, for example you
can write a script to index directory. Following nginx config can rewrite all
directory access to an indexing script.

```text
location / {
    if (-d $document_root$uri) {
        rewrite ^ /cgi-bin/index.sh$uri last;
    }
}
```

* `PATH_TRANSLATED` (rfc3875 standard)

**Note**: this option is not implemented strictly compliant with rfc3875.

This is related to `PATH_INFO`.

Let's say if you have a script under `/cgi-bin/hello.sh`, and you access
`http://127.0.0.1/cgi-bin/hello.sh/somewhat`.

The standard says, the server should try again with `http://127.0.0.1/somewhat`,
and found out where the uri should mapped to.

For technical reason, I just construct this variable by document root and
`PATH_INFO`.

The behaviour may be changed in future version.

* `QUERY_STRING` (rfc3875 standard)

Contains the query string of the request. For example, if you are accessing
`http://127.0.0.1/cgi-bin/hello.sh?a=1&b=2`, `QUERY_STRING` will contains
`a=1&b=2`.

* `REMOTE_ADDR`, (rfc3875 standard)

Client ip address.

* `REMOTE_HOST` (rfc3875 standard)

Client host name. Only available if `cgi_rdns` is turns on.

If `cgi_rdns` is on, nginx-cgi will do a reverse DNS, and find a domain matches
`REMOTE_ADDR`. If any found, it will be set to `REMOTE_HOST`.

If `cgi_rdns` is double, after the RDNS, nginx-cgi will do a forward DNS again.
`REMOTE_HOST` will only be set if the forward DNS result contains original
address.

Normally, don't do this. This feature can be easily implemented in script when
need. Turning on this will make every connection slower.

* `REMOTE_IDENT` (rfc3875 standard)

Nginx-cgi plugin doesn't support this for security reason.

* `REQUEST_METHOD` (rfc3875 standard)

Request method of the request, for example: `GET`, `POST`...

* `SCRIPT_NAME` (rfc3875 standard)

Path to current script. Normally, you don't need this. It doesn't contains the
full path. See `SCRIPT_FILENAME`.

The only reason to use this is construct the URI after rewriting. You can use
`SCRIPT_NAME` + `PATH_INFO` to get the URI after rewriting.

* `SERVER_NAME` (rfc3875 standard)

Server name, normally it equals to `Host` header without port part. If `Host`
header doesn't appear in the request (HTTP/1.0) or contains invalid value, then
this value is set to the reflect server ip address. If the ip address is an ipv6
address, it will be quoted with bracket like `[::1]`.

* `SERVER_PORT` (rfc3875 standard)

Server listening port, such as `80`, `443`...

* `SERVER_PROTOCOL` (rfc3875 standard)

The protocol used between client and server. Such as `HTTP/1.0`, `HTTP/1.1`...

* `SERVER_SOFTWARE` (rfc3875 standard)

Contains a string of nginx and version, such as `nginx/1.27.4`.

* `X_` (rfc3875 standard)

All `X-` prefixed http request header will be convert to `X_` variables. For
example:

If `X-a: 123` appears in header, `X_A` will be set to `123`.

* `HTTP_` (rfc3875 standard)

All other http request header will be convert to `HTTP_` variables, for example:

If `Accept: */*` appears in header, `HTTP_ACCEPT` will be set to `*/*`.

* `DOCUMENT_ROOT` (non-standard, impled by apache2)

Document root of current location block, see `root` stmt in nginx.

* `REMOTE_PORT` (non-standard, impled by apache2)

Client port number.

* `REQUEST_SCHEME` (non-standard, impled by apache2)

`http` or `https`.

* `REQUEST_URI` (non-standard, impled by apache2)

The raw uri before rewriting. If you want the URL after rewriting, try
`SCRIPT_NAME` + `PATH_INFO`.

* `SCRIPT_FILENAME` (non-standard, impled by apache2)

The full path to script.

* `SERVER_ADDR` (non-standard, impled by apache2)

Server ip address. If the server has multiple ip addresses. The value of this
variable can be different if requests come from different interface.

## Tricks

### Find all environment variables

Save following script to your cgi directory (eg, `/cgi-bin/env.sh`).

```sh
#!/bin/sh

echo 'Content-Type: text/plain'
echo

export
```

### Do action with root permission

CGI is really good for system management. So it's inevitable to do something
with root or other user's permission.

Apache has a special mod `mod_suexec` for this purpose. It can launch cgi
scripts with other user and group. It uses a special `suexec` binary to archive
this.

But nowadays, `sudo` is really popular, and it almost pre-installed in other
Linux distributions. I think it's a better replacement of `suexec`.

Let's see how to do this:

#### Run cgi script under another user and group **NOT RECOMMANDED**

This is what apache do, we can do something similar by change `cgi_interpreter`
to `/usr/bin/sudo`:

```text
location /cgi-bin {
    cgi on;
    cgi_interpreter /usr/bin/sudo -E -n -u www -g www;
}
```

`-E` is used to preserve cgi vars. And `-n` is used to indicate non-interactive
mode. `-u` and `-g` indicate user and group. In aboving example, all script
will be run as `www:www`.

Then you need add a sudo entry to allow those scripts be executed without
password, for example, save following line to `/etc/sudoers.d/www-data`:

```text
www-data ALL=(www:www) NOPASSWD: SETENV: /var/www/html/cgi-bin/*
```

This line indicates that: `www-data` user can run all scripts under
`/var/www/html/cgi-bin` with `www` user `www` group without password. `SETENV`
is required here, because we need to pass CGI environment variables to the
script.

Now you all your cgi script will be run with root user.

But, this way is a bit too dangerous.

#### Run cgi script with default user, grant special power when needed

It's much better do run cgi script with default permission. And then grant
special sudo permission when needed. Here's an example how to implement a CGI
program to poweroff the machine.

`/var/www/html/cgi-bin/poweroff.sh`:

```bash
#!/bin/sh

# do whatever authorization you want here

# response header and body
echo 'Content-Type: text/plain'
echo
echo 'machine will be powered off in 5s'

# close stdin and stdout to tell nginx-cgi there's no more input and output
# needed, nginx-cgi will send the response to the client immediently without
# waiting of script finish
exec <&- >&-

# add a sleep before poweroff, to let nginx have time to send response
sleep 5

# poweroff machine
sudo /usr/sbin/poweroff
```

`/etc/sudoers.d/www-data`:

```text
www-data ALL=(ALL) NOPASSWD: /usr/sbin/poweroff
```

## Known Issues

### `PATH_TRANSLATED` impl not accurate

By rfc3875, `PATH_TRANSLATED` should point to the file that as if `$PATH_INFO`
accessed as `uri`. But that's really hard to impl on nginx, it need re-trigger
nginx's location process. And those functions are private, cannot access by
plugin directly. The another way to impl it is starting a sub-request, but it's
too expensive, and this var is really rearly used. It's really not worth to do
it. So I simply construct this var by document root and `path_info` vars.

### RDNS impl doesn't access /etc/hosts

Nginx's resolver impl doesn't access /etc/hosts. I don't want to impl an extra
resolver in plugin. So I just ignore this problem.

## Reference

## rfc3875

<https://datatracker.ietf.org/doc/html/rfc3875>

### nginx

<https://nginx.org/en/docs/dev/development_guide.html>
<https://hg.nginx.org/nginx-tests>

### Hop-by-hop headers

<https://datatracker.ietf.org/doc/html/rfc2616#section-13.5.1>

### CGI environments

<https://datatracker.ietf.org/doc/html/rfc3875#section-4.1>

### Apache CGI

<https://httpd.apache.org/docs/2.4/howto/cgi.html>

### Lighttpd CGI

<https://redmine.lighttpd.net/projects/lighttpd/wiki/Mod_cgi>

## License

[2-clause BSD license](LICENSE)
