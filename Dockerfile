FROM ubuntu:22.04

# 타임존 설정 (설치 중 멈춤 방지)
ENV DEBIAN_FRONTEND=noninteractive

# 기본 패키지 및 컴파일/디버깅 툴 설치
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    gdb \
    git \
    vim \
    strace \
    ltrace \
    python3 \
    python3-pip \
    wget \
    curl \
    sudo \
    libcapstone-dev \
    libkeystone-dev \
    && rm -rf /var/lib/apt/lists/*

# Pwndbg 설치
RUN git clone https://github.com/pwndbg/pwndbg /opt/pwndbg && \
    cd /opt/pwndbg && \
    ./setup.sh

# 기본 작업 디렉토리 설정 (볼륨 마운트 경로와 일치시킴)
WORKDIR /home/myhooking

# 컨테이너 실행 시 bash 쉘 유지
CMD ["/bin/bash"]