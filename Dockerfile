FROM debian:stretch

RUN apt update && \
    apt upgrade -y && \
    apt install -y \
    gcc \
    g++ \
    make \
    cmake \
    gdb \
    gdbserver \
    rsync \
    vim \
    wget \
    net-tools \
    openssh-server \
    freeradius-utils \
    # App dependencies.
    libssl-dev \
    sqlite3 \
    libsqlite3-dev && \

    mkdir /var/run/sshd && \
    mkdir /root/radius-server && \
    mkdir /root/build

ADD . /root/radius-server
WORKDIR /root/build
RUN sed -i 's/# export LS_OPTIONS/export LS_OPTIONS/' /root/.bashrc && \
    sed -i 's/# alias ls=/alias ls=/' /root/.bashrc && \
    sed -i 's/# alias ll=/alias ll=/' /root/.bashrc && \
    sed -i 's/# alias l=/alias l=/' /root/.bashrc && \
    cmake ../radius-server
CMD ["/usr/sbin/sshd", "-d"]
