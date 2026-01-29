FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      curl \
      iproute2 \
      python3 \
      && rm -rf /var/lib/apt/lists/*

WORKDIR /rootfs

# 默认进入交互式 Shell（由启动脚本以 -it 方式运行）
CMD ["/bin/bash"]
