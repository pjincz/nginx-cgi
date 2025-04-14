# nginx-cgi plugin

Brings CGI support to [Nginx](https://github.com/nginx/nginx) and
[Angie](https://github.com/webserver-llc/angie) webserver.

| OS      | Tested with                                   | Nginx  | Angie |
| ------- | --------------------------------------------- | ------ | ----- |
| Linux   | AlmaLinux 9, Debian 12 and Ubuntu 24.04/20.04 | okay   | okay  |
| Darwin  | MacOS 15.1                                    | okay   | okay  |
| BSD     | FreeBSD 14.2 and OpenBSD 7.6                  | okay   | okay  |
| Solaris | OmniOS r1510521                               | okay   | okay  |
| Windows | No plan, nginx barely supports Windows        |        |       |

## Before everything

CGI is neither a demon nor an angel. It is simply a tool. Just like a chef's
knife in the hands of a cook or a sword in the hands of a warrior, you won't use
a sword for cooking, nor you take a chef's knife to the battlefield. The same
goes for CGI, it has its appropriate scenarios, and it should not be misused or
demonized.

CGI is good for:

* Low frequency applications, such as system management
* Resource limited systems, such as embeding system
* Low budget projects, such as personal websites
* Prototyping, for fast iterate

CGI is bad for:

* High QPS
* High traffic
* High concurrency

I created a discord channel. If:

* You are also a fun of CGI
* If you have any problem with nginx-cgi
* If you want to get update of nginx-cgi
* If you want to know more friends

Please join us: <https://discord.gg/DVwbbt9k>.

## Quick start (with Debian 12+, Ubuntu 24.04+)

Build and install:

```sh
# checkout source code
git clone https://github.com/pjincz/nginx-cgi
cd nginx-cgi

# build deb package
./build-deb-package.sh

# install built package
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
   cd <some-where-you-like>
   git clone https://github.com/nginx/nginx
   git clone https://github.com/pjincz/nginx-cgi
   ```

2. Generate Makefile in nginx dir

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

echo "Status: 200 OK"
echo "Content-Type: text/plain"
echo

echo "Hello world"
```

The first line of the script is a shebang. If you clearly set `cgi_interpreter`,
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

Normally, you need x-permission to make script runable. Missing of x-permission
can cause 403 error. If can't do this for any reason, `cgi_interpreter` can
help.

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

## Tricks && FAQ

### I want to list all environment variables

Put following script to your cgi directory, and curl it form your terminal:

```sh
#!/bin/sh

echo 'Content-Type: text/plain'
echo

printenv
```

### I want root permission

Put a sudo file to `/etc/sudoers.d` and run `sudo` in your script or set
`cgi_interpreter` as `/usr/bin/sudo`.

Here's an example of sudo config file:

```text
# allow wwww-data run /var/www/bin/my-danger-script with root account
www-data ALL=(root) NOPASSWD: /var/www/bin/my-danger-script

# allow all CGI script be luanched with sudo by nginx-cgi directly
www-data ALL=(root) NOPASSWD: SETENV: /var/www/html/cgi-bin/*
```

### How can I run CGI scripts with chroot

It's highly not recommanded to run CGI script with chroot. Because chroot is not
designed for security purpose. It still shared a lot of kernel spaces with host
system. For example, run `ps -ef` in chrooted process, all processes in host
system will return. That sould not too aweful? No, that's really terrible,
because you can also do `kill` in chrooted script for the same reason. And
people normally run programs with root permission in chrooted environment.
That's terribly bad. It causes system on high risk than just run script with
`www-data`.

If you want a sandbox environment, `lxc`, `docker` and `jails` are much better
for this purpose.

If you still want `chroot`, okay let me show you how to do it.

In this example, I assume you're using `/var/www/html` as the document root.

Prepare a hello.sh CGI script first:

```sh
mkdir -p /var/www/html/cgi-bin
cat > /var/www/html/cgi-bin/ls.sh <<EOF
#!/bin/sh
echo "Status: 200"
echo "Content-Type: text-plain"
echo
echo "files under /:"
ls /
EOF
chmod +x /var/www/html/cgi-bin/ls.sh

# try it
/var/www/html/cgi-bin/ls.sh
```

Step 1: prepare a chroot directory.

That're a lot of ways to do this step. `debootstrap` is a popular way on debian
based system. `busybox` is the most light way. `docker` is a modern way.

Let's make a lightest directory with `busybox` here:

```sh
# In this example, I put everything to /var/www/chroot
# Be careful, I download x86_64 busybox version here, you may need to change it
# You need root permission to run all following commands, I'm too lazy to
# prepend sudo to every commands here.

root_dir=/var/www/chroot

mkdir -p "$root_dir/bin" && cd "$root_dir/bin"
wget https://www.busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox
chmod +x busybox

cd "$root_dir"
mkdir -p $(dirname $(./bin/busybox --list-full) | sort -u)
./bin/busybox --list-full | while read line; do ln -sf /bin/busybox $line; done

# try it
chroot "$root_dir" ls
```

Step 2: mount document root into chroot dir

```sh
mkdir -p /var/www/chroot/var/www/html
mount --bind /var/www/html /var/www/chroot/var/www/html

# try it
ls /var/www/chroot/var/www/html
```

Notice:

* I use a trick here, after chroot, the document root is still the same. By this
  we can same some time to do path mapping.

* The mounting will not persist after a reboot. You may need to add an entry to
  /etc/fstab. Or move /var/www/html into chroot, and make a symbolic link
  outside.

Step 3: allow `www-data` to run `chroot` with root permission.

```sh
cat >/etc/sudoers.d/www-run-with-chroot <<EOF
# allow and only allow www-data run chroot with /var/www/chroot
www-data ALL=(root) NOPASSWD: /usr/sbin/chroot /var/www/chroot *
EOF
```

Now everything is ready, add following section to your nginx/angie:

```conf
location /cgi-bin {
    cgi on;
    cgi_interpreter /usr/bin/sudo /usr/sbin/chroot /var/www/chroot;
}
```

try it:

```sh
curl 127.0.0.1/cgi-bin/ls.sh
```

### How can I run CGI scripts with docker

In this example, I assume you're using `/var/www/html` as the document root.

Prepare a hello.sh CGI script first:

```sh
mkdir -p /var/www/html/cgi-bin
cat > /var/www/html/cgi-bin/ls.sh <<EOF
#!/bin/sh
echo "Status: 200"
echo "Content-Type: text-plain"
echo
echo "files under /:"
ls /
EOF
chmod +x /var/www/html/cgi-bin/ls.sh

# try it
/var/www/html/cgi-bin/ls.sh
```

Create a container and keep running in the background:

```sh
# Change -v if necessary
# -d: runs background
# -i -t: keep a terminal
# --restart always: keep container alive
docker run -dit --restart always --name my_cgi_docker -v /var/www:/var/www busybox sh

# try it
docker exec my_cgi_docker /var/www/html/cgi-bin/ls.sh
```

Allow `www-data` to run `docker` commands:

```sh
sudo usermod -aG docker www-data

# try it
sudo -u www-data docker exec my_cgi_docker /var/www/html/cgi-bin/ls.sh
```

Now everything is ready, add following section to your nginx/angie:

```conf
location /cgi-bin {
    cgi on;
    cgi_interpreter /usr/bin/docker exec my_cgi_docker;
}
```

### How can I run CGI scripts with jails

Okay, you're a fun of FreeBSD? Me too.

It's really similar to run scripts with `jails`.

Here I assume you're using `/var/www/html` as the document root too.

Prepare a hello.sh CGI script first:

```sh
mkdir -p /var/www/html/cgi-bin
cat > /var/www/html/cgi-bin/ls.sh <<EOF
#!/bin/sh
echo "Status: 200"
echo "Content-Type: text-plain"
echo
echo "files under /:"
ls /
EOF
chmod +x /var/www/html/cgi-bin/ls.sh

# try it
/var/www/html/cgi-bin/ls.sh
```

Step 1: create a jail

Let's put the jail to `/var/www/jail`.

```sh
mkdir -p /var/www/jail && cd /var/www/jail
fetch https://download.freebsd.org/ftp/releases/$(uname -m)/$(uname -m)/$(uname -r)/base.txz
tar -xvf base.txz -C .

# create mount point
mkdir -p /var/www/jail/var/www/html
```

Put following config to `/etc/jail.conf`:

```conf
www-jail {
    path = "/var/www/jail";
    host.hostname = "www-jail.local";

    # mount /var/www/html => /var/www/jail/var/www/html
    exec.prestart += "mount_nullfs /var/www/html /var/www/jail/var/www/html";
    exec.poststop += "umount /var/www/jail/var/www/html";
    mount.devfs;

    exec.start = "/bin/sh /etc/rc";
    exec.stop = "/bin/sh /etc/rc.shutdown";
    exec.clean;

    persist; # keep jail if no process runs
}
```

And ensure that following line appears in `/etc/rc.conf`:

```conf
jail_enable="YES"
```

And start the jail:

```sh
service jail start www-jail

# try it
jexec www-jail ls /
jexec www-jail /var/www/html/cgi-bin/ls.sh
```

Step 2: allow `www` to run `jexec` with root permission.

I uses `sudo` here. I'm not familiar with `doas`, if you prefer `doas` you can
try it yourself. Anyhow, neither `sudo` nor `doas` preloaded with FreeBSD. You
need to manually install one of them.

```sh
cat >/usr/local/etc/sudoers.d/www-jexec <<EOF
# allow and only allow `www` run `jexec` with `www-jail`
www ALL=(root) NOPASSWD: /usr/sbin/jexec www-jail *
EOF

# try it
sudo -u www sudo jexec www-jail /var/www/html/cgi-bin/ls.sh
```

Now everything is ready, add following section to your nginx/angie:

```conf
location /cgi-bin {
    cgi on;
    cgi_interpreter /usr/local/bin/sudo /usr/sbin/jexec www-jail;
}
```

try it:

```sh
curl 127.0.0.1/cgi-bin/ls.sh
```

Notes: a default jail even has no network access permssion. It's really a jail!
I didn't cover how to add network support of jails here. Because it's another
complex topic.

### I want create a long-run background process

Just make sure not to inherit `stdout` when creating the process (ideally, avoid
inheriting `stdin` and `stderr` as well). Here's an example write in shell.

```sh
taskid=1234
logfile="/var/lib/my-project/$taskid"
./long-run-task.sh "$taskid" </dev/null >"$logfile" 2>&1 &
```

Or if you are familiar with pipe operation, just close `stdout` (also, it's
better to close `stdin` and `stderr` as well), http request will finished
immediently. And you can use the process as background process.

```sh
exec </dev/null >somewhere 2>&1

# now http response is done, do what every you like
sleep 9999
```


### My http request hangs

As you see abvoing. In CGI world, http request's lifecycle depends on pipe's
(stdout's) lifecycle.

Each child process might inherit the CGI process's pipe. If any process that
inherited stdout remains alive, the HTTP request will never finish.

This may causes confiusing, when you want a long run background or killing
CGI process.

For creating long-run process, see aboving topic.

For killing CGI process, kill the whole process group rather than CGI process
itself.

```sh
cgi_pid=...

# don't do this
# kill "$cgi_pid"

# do this
kill -- "-$cgi_pid"
```

### I want to kill my cgi script

See aboving topic.

### I want to generate content dynamicaly

Traditionally, people use rewriting to archive this. But it's much easier here.
You can do it with `cgi pass`. Here's an example to render markdone dynamically:

```conf
{
    location ~ ^.*\.md$ {
        cgi_pass /var/www/bin/cgi/render-markdown.sh;
    }
}
```

```sh
#!/bin/sh

set -e

if [ ! -f "${DOCUMENT_ROOT}${PATH_INFO}" ]; then
    echo "Status: 404"
    echo
    exit
fi

echo "Status: 200"
echo "Content-Type: text/html"
echo

echo "<html><body>"
markdown "${DOCUMENT_ROOT}${PATH_INFO}"
echo "</body></html>"
```

### I don't like suffixes in url

Way 1: Removing CGI script's suffix

Way 2: do rewriting

Way 3: `cgi pass`

### How can I response status other than 200

```sh
#!/bin/sh

echo "Status: 404"
echo "Content-Type: text/plain"
echo

echo "Welcome to the void"
```

### How can I response a redirection

```sh
#!/bin/sh

echo "Status: 302"
echo "Location: https://theuselessweb.com"
echo
```

### How can I get http request body

You can read the request body from `stdin`. If you're using shell, `cat` can
quickly save request body to a file.

### How can send file to the client

For small files, you can write file to `stdout` directly.

For large files, it's much better to send a 302 response. Because CGI response
is streaming, protocol cannot easily handle caching, chunked downloads, or
resume support.

### I want to write CGI with python, ruby, perl, C, C++...

Go for it. Nginx-cgi don't care what language you use. Just grabs information
from environment var, and read request body from `stdin`, and write output to
`stdout`.

## Manual

### Options

#### `cgi <on|off>` or `cgi pass <script_path>`

Enable or disable cgi module on giving location block.

If you specify `on` here, the plugin will work in traditional mode. It parses
the request uri first, and then locate the script under document root directory
with request uri. After all it splits request uri to `SCRIPT_NAME` and
`PATH_INFO`. This is good if you have an old CGI project or you want to strictly
follow rfc3875.

I also provided a nginx style syntax here. If you specify `cgi pass` here, the
plugin will skip the step to locate the CGI script. It uses the the value you
provided directly. You can references nginx variables in the second argument,
eg: `cgi pass $document_root$uri`. The aboving example do something similar to
rfc3875, but not equal. In this form, request uri will be assigned to
`PATH_INFO` directly. And `SCRIPT_NAME` will be empty.

The second form is really good for dynamic content generating. It gets around
the complex and unnecessary uri re-writing.

If you specify `off` here, the plugin will be disabled.

Default: off

#### `cgi_pass <script_path>`

Alias of `cgi pass <script_path>`.

#### `cgi_interpreter [interpreter] [args...]`

Set interpreter and interpreter args for cgi script.

When this option is not empty, cgi script will be run with giving interpreter.
Otherwise, script will be executed directly.

This option can contains nginx variables, see
<https://nginx.org/en/docs/varindex.html> for more details.

This option is extremely useful in a lot of senarios, for example:

* run CGI scripts missing x-perm
* do sudo before executing CGI script
* wrap general binary as CGI script
* filter CGI script output
* ...

Default: empty

#### `cgi_working_dir <dir>`

Set the working directory of CGI script.

If this value is set to empty, CGI scripts will inherit nginx' working
directory.

If this value is set to an non-empty string, the CGI script will be launched
with giving working directory.

The action of changing working directory may failed. For example, giving
directory doesn't exist, no perm or name too long. In this case, script will
failed to execute.

This option doesn't change the way to find interpreter or script (if they are
specified with related path, they are always related to nginx' working
directory).

This option can contain nginx variable. Althrough I don't know what use this is.
Maybe you can setup different working dir for different server_name by this.

Default: empty

#### `cgi_body_only <on|off>`

A standard CGI script should output two parts: header and body. And an empty
line to split those two parts.

If you want to simply run a normal program as CGI program. You can turn this on.

Once this option is enabled, all outout will be treated as response body, and be
sent to the client.

Default: off

#### `cgi_path <PATH>`

Change cgi script PATH environment variable.

Default: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

#### `cgi_strict <on|off>`

Enable or disable strict mode.

When strict mode turns on, bad cgi header will cause 500 error. When strict mode
turns off, bad cgi header be forward as it is.

Default: on

#### `cgi_set_var <name> <value>`

Add and pass extra environment variables to CGI script. The first argument of
this command is the name of environment variable. It should contains only
alphabets, numbers and underscore, and doesn't start with number. The second
argument of this command is the value express of the var. It can contains nginx
variables, see <https://nginx.org/en/docs/varindex.html> for more details.

This option can appears more than 1 time to set multiple variables. If more than
one option set the same var, then the last one works. These directives are
inherited from the previous configuration level if and only if there's no
cgi_set_var directives defined on the current level.

This option can also be used to override standard CGI vars. This may be useful
in some case, for example hacking old CGI script or simulate standard vars that
are not supported by this plugin now (Such as `PATH_TRANSLATED`,
`REMOTE_IDENT`). But it's not recommanded, it may introduce confusing issues to
your system.

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

`off`: disable rdns feature.

`on`: Do reverse dns before launching cgi script, and pass rdns result to cgi
script via `REMOTE_HOST` environment variable.

`double`: After reverse dns, do a forward dns again to check the rdns result. if
result matches, pass result as `REMOTE_HOST`.

`required`: If rdns failed, 403, 503 or 500 returns to the client. Depends on
the failure reason of rdns.

If you turns this option on, you need to setup a `resolver` in nginx too.
Otherwise you will get an error of `no resolver defined to resolve`.

**author notes**: do not enable this option, it will makes every request slower.
this feature can be easily implemented by `dig -x` or `nslookup` in script. the
only reason I implement this is just to make the module fully compliant with the
rfc3875 standard.

#### `cgi_timeout <t1> [t2]`

Send `TERM`/`KILL` signals to the CGI process if it runs too long.

If both `t1` and `t2` equal to `0`. Timeout feature is disabled.

If `t1` or `t2` doesn't equal to `0`. A `TERM` or `KILL` signal will be sent to
the process after timeout.

If both `t1` and `t2` not zero. Send `TERM` at `t1` timestamp first. And send
`KILL` again at `t1+t2` timestamp (if process still alive at that timestamp).

If `t2` doesn't present, it treated as `0`.

Default: 0 0

### Standard Environment Variables

Nginx-cgi implemented almost all rfc3875 standard variables. If they cannot
cover all of your usage, you can add your own variable by `cgi_set_var`. Also
those variables can be overrided by `cgi_set_var` if you really want to.

* `AUTH_TYPE`, `REMOTE_USER` (rfc3875 standard)

If cgi script is behind an authorization module (such as
`ngx_http_auth_basic_module`), and the authorization is succeed, the value is
set to auth type (such as `Basic`) and authorized user.

If no authorization module enabled, no matter client passes autoriazation header
or not. Those 2 fields are not present.

`Authorization` header is not visible in cgi script for security reason. If you
really want to do authorization in CGI script, try `cgi_set_var`.

* `CONTENT_LENGTH`, `CONTENT_TYPE` (rfc3875 standard)

Same to request header's `Content-Length` and `Content-Type`.

* `GATEWAY_INTERFACE` (rfc3875 standard)

Always be `CGI/1.1` in this plugin.

* `PATH_INFO` (rfc3875 standard)

Let's say if you have a script under `/cgi-bin/hello.sh`, and you access
`http://127.0.0.1/cgi-bin/hello.sh/somewhat`.

Then `PATH_INFO` contains the string `/somewhat`.

Combination with url `rewrite` or `cgi pass`, this variable can be used for
dynamic content generating.

* `PATH_TRANSLATED` (rfc3875 standard)

**Note**: this option is not implemented strictly compliant with rfc3875.
Please avoid this, if you are writing new CGI script.

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
`REMOTE_HOST` will only be set if the forward DNS result matches the original
address.

See `cgi_rdns` for more information.

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

Note: this variable doesn't same to nginx varible `$request_uri`. You can find
the document at <https://httpd.apache.org/docs/2.4/mod/mod_rewrite.html>.

* `SCRIPT_FILENAME` (non-standard, impled by apache2)

The full path to the CGI script.

* `SERVER_ADDR` (non-standard, impled by apache2)

Server ip address. If the server has multiple ip addresses. The value of this
variable can be different if requests came from different interfaces.

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
