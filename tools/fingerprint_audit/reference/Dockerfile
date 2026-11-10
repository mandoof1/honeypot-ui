# One reference daemon per image: the distribution's own package on a dated
# build of the distribution's own base image, configuration untouched.
# compose.yaml builds this file once per service with different arguments.
#
#   BASE_IMAGE  the release whose packages the decoy claims to run
#   ARCHIVE     the frozen package archive to install from (see provision.sh)
#   SERVICE     sshd | apache | nginx | vsftpd | proftpd | telnetd
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG ARCHIVE
ARG SERVICE

COPY provision.sh /usr/local/sbin/reference-provision

# One layer: point apt at the frozen archive, install the package, record
# what was installed, and drop the package lists again.
RUN chmod 0755 /usr/local/sbin/reference-provision \
    && reference-provision sources "${ARCHIVE}" \
    && reference-provision install "${SERVICE}" \
    && reference-provision versions > /etc/reference-versions \
    && rm -rf /var/lib/apt/lists/*

# `docker compose exec <service> cat /etc/reference-versions` prints the
# package versions to quote in --reference-description.
CMD ["/usr/local/sbin/reference-provision", "run"]
