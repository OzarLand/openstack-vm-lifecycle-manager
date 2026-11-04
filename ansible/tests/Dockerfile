# CI target for the ovlm-counter playbooks: an UNPRIVILEGED Ubuntu 24.04 container reached over SSH.
# No systemd (that needs privileges), so the playbooks run with ovlm_test_mode=true.
ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssh-server sudo python3 python3-apt psmisc e2fsprogs util-linux ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && useradd -m -s /bin/bash ovlm \
 && echo 'ovlm ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/ovlm \
 && chmod 0440 /etc/sudoers.d/ovlm \
 && mkdir -p /home/ovlm/.ssh && chmod 700 /home/ovlm/.ssh && chown ovlm:ovlm /home/ovlm/.ssh
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
