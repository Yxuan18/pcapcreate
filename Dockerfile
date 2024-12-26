#FROM python:3.11
#WORKDIR /app
#COPY web_apps/ /app
#COPY Detect/ /home/Detect
## COPY debian_etc_apt_sources.list /etc/apt/sources.list
## RUN echo "nameserver 8.8.8.8">/etc/resolv.conf
#RUN apt update -y && apt install -y suricata
## 使用清华大学的pip镜像源安装依赖
#RUN pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r /app/requirements.txt
#EXPOSE 9900
#CMD ["python", "app.py"]

# ---------------- * 		*  ----------------
# 由于当前直接运行 docker build 命令会各种报错
# 所以：
#     当前采用间接打包的方式
#	  1、运行一个 Python 的原始镜像为容器。 此处使用 Python:3.11
#	  2、在 容器 中先执行了 apt update -y && apt install -y suricata
#	  3、将外部的代码复制到容器 中的 /var/www/web_apps/
#       use command:  docker cp web_apps/  my_container_id:/var/www/
#	  4、在 容器 中继续执行 pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r /var/www/web_apps/requirements.txt
#	  5、将 容器 打包为镜像 docker commit -a "my_name" -m "my_message" my_container_id mypcapcreate:v3
#	  6、假定新的镜像名称为 mypcapcreate:v3
#     7、修改下面的 FROM 为 mypcapcreate:v3
#     8、运行 docker build -t topsec/pcapcreate:v2.4 .
#     9、打包镜像： docker save -o pcapcreate.tar topsec/pcapcreate:v2.4
#    10、去另一边解开： docker load -i pcapcreate.tar
# ---------------- * 		*  ----------------
FROM mypcapcreate:v3
# 直接在这将端口引出来
EXPOSE 9900
# 记得加上 app.py 的绝对路径。
# 注意：该 Dcokerfile 不会将原有的数据删除。旧的 PCAP 文件以及 RULES 文件还在
# 但不用担心，文件在 48 小时后会自动删除
CMD ["python", "/var/www/web_apps/app.py"]
