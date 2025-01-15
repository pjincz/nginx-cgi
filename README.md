# nginx-cgi plugin

Brings CGI support to Nginx.

## Quick start (with Debian 12+, Ubuntu 24.04+)

Build and install:

```sh
# checkout source code
git clone https://github.com/pjincz/nginx-cgi
cd nginx-cgi

# install required build tool
sudo apt install build-essential devscripts dpkg-dev fakeroot -y

# install build dependencies
sudo apt build-dep . -y

# build with debuild
debuild -us -uc

# install build result
dpkg -i ../libnginx-mod-http-cgi_*_amd64.deb 
```

Enable cgi in nginx, add following section to /etc/nginx/sites-enabled/default:

```
    root /var/www/html;

    location /cgi-bin {
            cgi on;
    }
```

And restart nginx:

```sh
systemctl restart nginx
```

Save following content to /var/www/html/cgi-bin/hello.sh

```sh
#!/bin/bash

echo "Content-Type: text/plain"
echo

echo hello
```

Add x perm to cgi script:

```sh
chmod +x /var/www/html/cgi-bin/hello.sh
```

Try it:

```sh
curl http://127.0.0.1/cgi-bin/hello.sh
```

## Build

If you are using latest deb based system, such as Debian and Ubuntu, and not
willing to debug the plugin, you can just following the `Quick start` to get a
usable deb package.

1. Checkout nginx and this plugin

```sh
cd an-empty-dir
git clone https://github.com/nginx/nginx
git clone https://github.com/pjincz/nginx-cgi
```

2. Generate makefile in nginx dir

```sh
cd nginx
./auto/configure --add-dynamic-module=$PWD/../nginx-cgi [...other options...]
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

```
load_module <dir-of-plugin>/ngx_http_cgi_module.so;
```

### Enable cgi

After loading the plugin, you can add `cgi on;` to location contexts to enable
cgi. Example:

```
location /cgi-bin {
    cgi on;
}
```

Once cgi turned on on a location, all nested locations will also have cgi turned
on. If you want to disable cgi for a child location, just use `cgi off`.

When the location is accessed, nginx-cgi will find the script under the document
root (it's specified by `root` statement). For example, if you have specify the
document root as `/var/www/html`, then you access `/cgi-bin/hello.sh`,
`/var/www/html/cgi-bin/hello.sh` will be executed.

Nginx-cgi also support `alias`, it like `root` statement in nginx, the only
difference is the location prefix will be removed from uri. For example, if you
want `/cgi/hello.sh` also reference to the same script, you can do this:

```
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
it's okay to remove this line, otherwise the missing of shebang will causes
a 500 error. Some shell allows script be executable without shebang, but it's
not allowed here. If a script runable by shell, but return 500 error, check
the shebang.

The output of cgi script contains 2 sections: the header section and body
section. The first 2 `echo` statements output the header section, and the last
`echo` statement outputs the body section. The third `echo` statement outputs
the separator. Both header section and body section can be empty, but the
separator is mandatory. Missing of separator will causes an 500 error.

All lines in header section will be parsed as normal http response header line.
And then passed to the client side. There's one sepcial header `Status`, it will
be passed and appears in response status line. If `cgi_strict` is on, nginx-cgi
will check all cgi output header, and causes 500 error if invalid header exists.
Otherwise, invalid headers will be forwarded to client side too. If fully
recommanded to keep `cgi_strict` on.

After separator, all output will be sent to client as it is.

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

If you strictly follow the doc, you can try the cgi by `curl` now.

### Request header

Request header will be parsed and then translated to environment variables and
then passed to cgi script.

For example, you can find the query string in `QUERY_STRING` environment var.
Also access `Http-Accept` by `HTTP_ACCPET`.

Here's an example:

```sh
#!/bin/sh
echo ""

echo "query string: $QUERY_STRING"
echo "http accept: $HTTP_ACCEPT"
```

For full list of environment variables, see environment session.

### Request body

The request body will be passed as stdin. Here's an example to read all request
body and echo it:

```sh
#!/bin/sh
echo ""

body=$(cat)

echo "request body: $body"
```

### Streaming

Both request body and response body are streaming. For example, following script
streamingly read request and write calc result by `bc`.

```sh
#!/bin/sh
echo ""

bc >&1
```

Sadly, `curl` doesn't suport streaming request body, you can test it by
following script:

```sh
#!/bin/bash

IP=$1
PORT=$2
URI=$3

function gen_request() {
    printf "POST $URI HTTP/1.1\r\n"
    printf "Host: $IP:$PORT\r\n"
    printf "Transfer-Encoding: chunked\r\n"
    printf "Content-Type: text/plain\r\n"
    printf "Connection: close\r\n"
    printf "\r\n"

    while IFS= read -r line; do
        printf "%x\r\n%s\n\r\n" "$((${#line}+1))" "$line"
    done

    printf "0\r\n\r\n"
}

gen_request | nc "$IP" "$PORT"
```

The output is a bit strange, but don't worries about it. The output contains
encoding data, just because the test script prints tcp output directly. That's
not an issue of cgi script itself.

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

* `cgi <on|off>`

Enable or disable cgi module on giving location block.

Default: off

* `cgi_path <PATH>`

Change cgi script PATH environment variable

Default: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

* `cgi_strict <on|off>`

Enable or disable strict mode.

When strict mode turns on, bad cgi header will cause 500 error. When strict mode
turns off, bad cgi header be forward as it is.

Default: on

* `cgi_interpreter <interpreter> [args...]`

Set interpreter and interpreter args for cgi script.

When this option is not empty, cgi script will be run be giving interpreter.
Otherwise, script will be executed directly.

Default: empty

* `cgi_x_only <on|off>`

Enable or disable x-only mode.

When this option turns on, only file with x perm will be treated as cgi script.
Otherwise 403 will be returned. If this option turns off, the cgi plugin will
try to execute the script no matter whther x perm exists. Note: this option only
meanful if `cgi_interpreter` is set.

Default: on

* `cgi_stderr <path>`

Redirect cgi stderr to giving file.

By default, nginx-cgi grab cgi script's stderr output and dump it to nginx log.
But this action is somewhat expensive, because it need to create an extra
connection to listen stderr output. If you want to avoid this, you can use this
option to redirect cgi script's stderr output to a file. Or you can even discard
all stderr output by redirect to `/dev/null`. Also you can use this to redirect
all stderr output to nginx's stderr by set it as `/dev/stderr`.

* `cgi_rdns <on|off|double>`

Enable or disable reverse dns.

off: disable rdns feature.

on: Run reverse dns before launching cgi script, and pass rdns to cgi script via
    `REMOTE_HOST` environment variable.

double: After reverse dns, do a forward dns again to check the rdns result. it
        result matches, pass result as `REMOTE_HOST`.

If you turns on this option, you need to setup a `resolver` in nginx too.
Otherwise you will get an error of `no resolver defined to resolve`.

author notes: do not enable this option, it will makes every request slower.
              this feature can be easily implemented by `dig -x` or `nslookup`
              in script when need. the only reason I impled this is just to make
              the module fully compliant with the rfc3874 standard.

### Environment Variables

* `AUTH_TYPE`, `REMOTE_USER` (rfc3875 standard)

If cgi script is behind an authorization module (such as
`ngx_http_auth_basic_module`), and the authorization is succeed, the value is
set to auth type (such as `Basic`) and authorized user.

If no authorization module enabled, no matter client passes autoriazation header
or not. Those 2 fields are empty.

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

```
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
and found out whether the uri should mapped to.

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

Server name, normally it equals to `Host` header without port part.

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

`htttp` or `htttps`.

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
scripts with other user and group. It uses a sepcial `suexec` binary to archive
this.

But nowadays, `sudo` is really popular, and it almost pre-installed in other
Linux distributions. I think it's a better replacement of `suexec`.

Let's see how to do this:

#### Run cgi script under another user and group **NOT RECOMMANDED**

This is what apache do, we can do something similar by change `cgi_interpreter`
to `/usr/bin/sudo`:

```
location /cgi-bin {
    cgi on;
    cgi_interpreter /usr/bin/sudo -E -n -u www -g www;
}
```

`-E` is used to preserve cgi vars. And `-n` is used to indicate non-interactive
mode. `-u` and `-g` indicate user and group. In aboving example, all script
will be run as `www:www`.

Then you need add a sudo entry to allow those scripts be executed without
password, for example, save following line to `/etc/sudoers.d/cgi-bin`:

```
www-data ALL=(www:www) NOPASSWD: SETENV: /var/www/html/cgi-bin/*
```

This line indicates that: `www-data` user can run all scripts under
`/var/www/html/cgi-bin` with `www` user `www` group without password. `SETENV`
is required here, because we need to pass CGI environment variables to the
script.

Now you all your cgi script will be run with root user.

But, this way is a bit too dangerous.

#### Run cgi script with default user, and put super power scripts to a special directory

It's much better do run cgi script with default permission. We can add another
directory that contains script that can be invoked by cgi scripts, and has super
power. Eg, put all sbin script to `/var/www/sbin`, and allow them be invoked by
`www-data`. This will be more secure.

Save following line to /etc/sudoers.d/www-sbin

```
www-data ALL=(ALL) NOPASSWD: /var/www/sbin/*
```

Here's an example shows how to poweroff machine in CGI script.

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
sudo /var/www/sbin/poweroff
```

`/var/www/sbin/poweroff`:

```bash
#!/bin/sh

poweroff
```

`/etc/sudoers.d/www-sbin`:

```
www-data ALL=(ALL) NOPASSWD: /var/www/sbin/*
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

### nginx
https://nginx.org/en/docs/dev/development_guide.html
https://hg.nginx.org/nginx-tests

### Hop-by-hop headers

https://datatracker.ietf.org/doc/html/rfc2616#section-13.5.1

### CGI environments

https://datatracker.ietf.org/doc/html/rfc3875#section-4.1

### Apache CGI

https://httpd.apache.org/docs/2.4/howto/cgi.html

### Lighttpd CGI

https://redmine.lighttpd.net/projects/lighttpd/wiki/Mod_cgi

## License

[2-clause BSD license](LICENSE)
