FROM ubuntu:latest

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      gcc make git libssl-dev libcurl4-openssl-dev \
 && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/cristianzsh/foremost-ng.git /opt/foremost-ng
WORKDIR /opt/foremost-ng/src
RUN make && make install

WORKDIR /
