#!/bin/sh
# Installs and runs one stock reference daemon inside a reference image.
#
# The Dockerfile copies this script into every reference image and calls it
# to install the daemon at build time and to start it at run time, so what a
# reference is made of is written down in one place.
#
#   provision.sh sources <archive>    point apt at a frozen package archive
#   provision.sh install <service>    install the daemon's distribution package
#   provision.sh run [<service>]      run the daemon in the foreground
#   provision.sh versions [<service>] report what is installed
#
# Services: sshd, apache, nginx, vsftpd, proftpd, telnetd.
#
# <archive> pins what apt installs, so a rebuild next year gets the builds
# this year's measurements were taken against:
#   Ubuntu 20.04  a snapshot.ubuntu.com timestamp, e.g. 20231115T000000Z
#   Debian 11     "release": the release pocket on archive.debian.org,
#                 frozen at the last point release (11.11)
#
# Nothing here edits a daemon's configuration: the point of a reference is
# the package as the distribution ships it. The only additions are the
# runtime directories an init system would create at boot, and, for the FTP
# daemons, one local account so the logged-in replies can be compared.
set -eu

# The search path a container runtime or a login gives root. Whatever the
# caller's shell had is not to be trusted to include the sbin directories.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

SERVICE_FILE=/etc/reference-service
ARCHIVE_FILE=/etc/reference-archive
APT_CONF=/etc/apt/apt.conf.d/90reference

die() {
    echo "provision.sh: $*" >&2
    exit 1
}

distro() {
    . /etc/os-release
    echo "${ID}:${VERSION_CODENAME}"
}

service_name() {
    if [ -n "${1:-}" ]; then
        echo "$1"
    elif [ -r "$SERVICE_FILE" ]; then
        cat "$SERVICE_FILE"
    else
        die "no service given and $SERVICE_FILE is missing"
    fi
}

cmd_sources() {
    archive=${1:?archive: a snapshot timestamp (Ubuntu) or "release" (Debian)}
    : > "$APT_CONF"
    case "$(distro)" in
    ubuntu:focal)
        base="https://snapshot.ubuntu.com/ubuntu/${archive}"
        {
            echo "deb ${base} focal main universe"
            echo "deb ${base} focal-updates main universe"
            echo "deb ${base} focal-security main universe"
        } > /etc/apt/sources.list
        # snapshot.ubuntu.com is HTTPS only and the base image carries no CA
        # bundle. apt authenticates the archive by the signature on its
        # InRelease files whatever the transport, so the TLS check is turned
        # off for this one host rather than pulling certificates from a
        # second, undated archive.
        {
            echo 'Acquire::https::snapshot.ubuntu.com::Verify-Peer "false";'
            echo 'Acquire::https::snapshot.ubuntu.com::Verify-Host "false";'
        } >> "$APT_CONF"
        echo "snapshot.ubuntu.com ${archive} (focal, focal-updates, focal-security)" > "$ARCHIVE_FILE"
        ;;
    debian:bullseye)
        [ "$archive" = release ] || die "Debian 11 is installed from its release pocket; pass 'release'"
        # Only the release pocket. bullseye-security has moved on past the
        # OpenSSH build the decoy names (8.4p1-5+deb11u3), while the release
        # pocket stopped at the last point release, which carries it.
        echo "deb http://archive.debian.org/debian bullseye main" > /etc/apt/sources.list
        echo "archive.debian.org bullseye main (release pocket)" > "$ARCHIVE_FILE"
        ;;
    *)
        die "unsupported base image: $(distro)"
        ;;
    esac
    # A frozen archive serves the Release files of its day, whose validity
    # window has passed.
    echo 'Acquire::Check-Valid-Until "false";' >> "$APT_CONF"
    apt-get update
}

install_packages() {
    # Recommends are left out to keep the images small; none of them takes
    # part in what the daemons put on the wire. Retries because the archives
    # answer 503 now and then.
    DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=8 install -y \
        --no-install-recommends "$@"
}

add_ftp_account() {
    # A local account both FTP references can log in with (the decoy accepts
    # test/test too), so the replies after login can be compared.
    useradd --create-home --shell /bin/bash test
    echo 'test:test' | chpasswd
}

cmd_install() {
    service=${1:?service name}
    case "$service" in
    sshd)
        install_packages openssh-server
        ;;
    apache)
        # mod_php because every Apache identity the decoy can take also
        # claims PHP 7.4; the default site stays the package's static page.
        install_packages apache2 libapache2-mod-php7.4
        ;;
    nginx)
        install_packages nginx
        ;;
    vsftpd)
        # The decoy's greeting says 3.0.3, which is the build in the focal
        # release pocket; focal-updates later moved to 3.0.5.
        install_packages vsftpd=3.0.3-12
        add_ftp_account
        ;;
    proftpd)
        install_packages proftpd-basic
        add_ftp_account
        ;;
    telnetd)
        # netbase provides /etc/services. A stock server has it; the
        # container base image does not, and without it inetd cannot
        # look up "telnet" and listens on nothing.
        install_packages netbase openbsd-inetd telnetd
        ;;
    *)
        die "unknown service: $service"
        ;;
    esac
    echo "$service" > "$SERVICE_FILE"
}

cmd_run() {
    service=$(service_name "${1:-}")
    case "$service" in
    sshd)
        # systemd's RuntimeDirectory= creates this on a normal host.
        mkdir -p /run/sshd
        exec /usr/sbin/sshd -D -e
        ;;
    apache)
        exec apache2ctl -D FOREGROUND
        ;;
    nginx)
        exec nginx -g 'daemon off;'
        ;;
    vsftpd)
        # The unit file's ExecStartPre does the same.
        mkdir -p /var/run/vsftpd/empty
        exec /usr/sbin/vsftpd /etc/vsftpd.conf
        ;;
    proftpd)
        mkdir -p /run/proftpd
        exec /usr/sbin/proftpd --nodaemon
        ;;
    telnetd)
        exec /usr/sbin/inetd -i
        ;;
    *)
        die "unknown service: $service"
        ;;
    esac
}

packages_for() {
    case "$1" in
    sshd) echo "openssh-server openssh-client libssl1.1 libpam-modules" ;;
    apache) echo "apache2 apache2-bin libapache2-mod-php7.4" ;;
    nginx) echo "nginx nginx-core nginx-common" ;;
    vsftpd) echo "vsftpd libpam-modules" ;;
    proftpd) echo "proftpd-basic" ;;
    telnetd) echo "telnetd openbsd-inetd netbase login base-files" ;;
    esac
}

config_for() {
    case "$1" in
    sshd) echo "/etc/ssh/sshd_config" ;;
    apache) echo "/etc/apache2/apache2.conf /etc/apache2/sites-enabled/000-default.conf /etc/apache2/conf-enabled/security.conf" ;;
    nginx) echo "/etc/nginx/nginx.conf /etc/nginx/sites-enabled/default" ;;
    vsftpd) echo "/etc/vsftpd.conf" ;;
    proftpd) echo "/etc/proftpd/proftpd.conf" ;;
    telnetd) echo "/etc/inetd.conf /etc/issue.net" ;;
    esac
}

cmd_versions() {
    service=$(service_name "${1:-}")
    . /etc/os-release
    echo "service: $service"
    echo "os: $PRETTY_NAME"
    echo "apt_archive: $(cat "$ARCHIVE_FILE" 2>/dev/null || echo unknown)"
    for package in $(packages_for "$service"); do
        version=$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null || true)
        [ -n "$version" ] && echo "package: $package $version"
    done
    for path in $(config_for "$service"); do
        [ -r "$path" ] && echo "config_sha256: $path $(sha256sum "$path" | cut -d' ' -f1)"
    done
    case "$service" in
    sshd)
        echo "reports: $(ssh -V 2>&1)"
        keys=""
        for key in /etc/ssh/ssh_host_*_key.pub; do
            [ -e "$key" ] && keys="$keys${key##*/} "
        done
        echo "host_keys: $keys"
        ;;
    apache) echo "reports: $(apache2 -v 2>&1 | head -n1)" ;;
    nginx) echo "reports: $(nginx -v 2>&1)" ;;
    # vsftpd 3.0.3 writes its version to standard input's descriptor.
    vsftpd) echo "reports: $(vsftpd -v 0>&1 2>&1)" ;;
    proftpd) echo "reports: $(proftpd --version 2>&1)" ;;
    telnetd) echo "reports: inetd runs $(grep -v '^#' /etc/inetd.conf | grep telnet | tr -s '\t ' ' ' || true)" ;;
    esac
}

command=${1:-}
[ -n "$command" ] && shift
case "$command" in
sources) cmd_sources "$@" ;;
install) cmd_install "$@" ;;
run) cmd_run "$@" ;;
versions) cmd_versions "$@" ;;
*) die "usage: provision.sh sources <archive> | install <service> | run [<service>] | versions [<service>]" ;;
esac
