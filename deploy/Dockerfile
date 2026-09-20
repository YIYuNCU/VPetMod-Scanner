# 离线镜像：以 scratch 为基，docker build 不拉取任何镜像层，适合无法访问 dockerhub 的机器。
# 二进制在构建机上用 CGO_ENABLED=0 交叉编译好后放到构建上下文，见 deploy.sh。
FROM scratch

# 静态二进制，无任何运行时依赖。
COPY vpetscan-linux-amd64 /vpetscan

# /data 挂卷持久化任务与审核记录。
VOLUME ["/data"]
EXPOSE 8740

# ENTRYPOINT 只放二进制；serve 及参数由 CMD 提供，docker run 传参时整体覆盖 CMD，
# 避免与 ENTRYPOINT 里的 serve 重复导致 Go flag 提前停止解析（token/auto-dynamic 被吞）。
ENTRYPOINT ["/vpetscan"]
CMD ["serve", "-listen", "0.0.0.0:8740", "-data", "/data"]
