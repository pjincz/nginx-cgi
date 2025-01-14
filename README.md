# nginx-cgi plugin

Brings CGI support to Nginx.

## Quick start (with Debian 12+, Ubuntu 24.04+)

Build and install:
```
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
    location /cgi-bin {
            cgi on;
    }
```

And restart nginx:

```
systemctl restart nginx
```

Save following content to /var/www/html/cgi-bin/hello.sh

```
#!/bin/bash

echo "Content-Type: text/plain"
echo

echo hello
```

Add x perm to cgi script:

```
chmod +x /var/www/html/cgi-bin/hello.sh
```

Try it:

```
curl http://127.0.0.1/cgi-bin/hello.sh
```

## License

[2-clause BSD license](LICENSE)

