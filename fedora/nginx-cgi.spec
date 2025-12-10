# This file is contributed by Matt A. Tobin

%global _disable_source_fetch 0
%global debug_package %{nil}
%global source_date_epoch_from_changelog 0

Name:           nginx-mod-http-cgi
Version:        0.14.1
Release:        1
Summary:        CGI support for Nginx

License:        BSD-2-Clause
Source0:        https://github.com/pjincz/nginx-cgi/archive/refs/tags/v%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  nginx-mod-devel
Requires:       nginx-filesystem

%description
CGI is neither a demon nor an angel. It is simply a tool. Just like a chef's
knife in the hands of a cook or a sword in the hands of a warrior, you won't
use a sword for cooking, nor you take a chef's knife to the battlefield.

The same goes for CGI, it has its appropriate scenarios, and it should not
be misused or demonized.

%prep
%autosetup -n nginx-cgi-%{version}

%build
%nginx_modconfigure
%nginx_modbuild

%install
pushd %{_vpath_builddir}

install -dm 0755 %{buildroot}%{nginx_moddir}
install -pm 0755 ngx_http_cgi_module.so %{buildroot}%{nginx_moddir}

install -dm 0755 %{buildroot}%{nginx_modconfdir}
echo 'load_module "%{nginx_moddir}/ngx_http_cgi_module.so";' \
    > %{buildroot}%{nginx_modconfdir}/mod-http-cgi.conf

popd

%files
%{nginx_moddir}/ngx_http_cgi_module.so 
%{nginx_modconfdir}/mod-http-cgi.conf
