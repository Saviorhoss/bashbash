FROM nginx:latest

WORKDIR /app
USER root
EXPOSE 80

RUN apt update -y && apt install -y wget unzip qrencode net-tools

RUN rm -rf /usr/share/nginx/*
RUN wget https://gitlab.com/Misaka-blog/xray-paas/-/raw/main/mikutap.zip -O /usr/share/nginx/mikutap.zip
RUN unzip -o "/usr/share/nginx/mikutap.zip" -d /usr/share/nginx/html
RUN rm -f /usr/share/nginx/mikutap.zip

COPY nginx.conf /etc/nginx/nginx.conf

RUN mkdir /etc/mysql /usr/local/mysql

COPY main.sh /usr/local/mysql/

RUN chmod a+x /usr/local/mysql/main.sh

CMD bash /usr/local/mysql/main.sh
