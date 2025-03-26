FROM debian:12.10-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y --no-install-recommends sudo git autoconf automake \
    libtool make libreadline-dev texinfo libjson-c-dev pkg-config bison flex \
    libc-ares-dev python3-dev python3-pytest python3-sphinx build-essential \
    libsnmp-dev libcap-dev libelf-dev libunwind-dev libyang2-dev iproute2 \
    iputils-ping traceroute tcptraceroute curl && \
    apt clean && rm -rf /var/lib/apt/lists/*

RUN apt update && apt install -y gnupg2 lsb-release && curl -s https://deb.frrouting.org/frr/keys.asc | apt-key add -
RUN echo "deb https://deb.frrouting.org/frr $(lsb_release -s -c) frr-stable" | tee /etc/apt/sources.list.d/frr.list
        
RUN apt update && \
    apt install -y frr frr-pythontools && \
    rm -rf /var/lib/apt/lists/*

RUN apt update && apt install -y rsyslog

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY modules.conf /etc/modules-load.d/modules.conf
COPY sysctl.conf /etc/sysctl.mod.conf
COPY daemons /etc/frr/daemons

RUN apt update && apt install -y tcpdump

RUN adduser zebra && \
    usermod -aG sudo zebra && \
    adduser zebra frr && \
    adduser zebra frrvty && \
    cat /etc/sysctl.mod.conf >> /etc/sysctl.conf && \
    chmod +x /usr/local/bin/entrypoint.sh && \
    mkdir -p /var/run/frr /var/log/frr /var/tmp/frr && \
    chown -R frr:frr /var/run/frr /var/log/frr /var/tmp/frr && \
    chmod 755 /var/run/frr /var/log/frr /var/tmp/frr && \
    echo "DefaultLimitNOFILE=100000" >> /etc/systemd/system.conf

COPY interfaces /etc/network/interfaces

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

CMD ["/usr/bin/vtysh", "--no-fork"]
