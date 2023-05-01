FROM ubuntu

RUN apt update -y && apt install -y wget unzip qrencode net-tools
EXPOSE 80

RUN mkdir /etc/mysql /usr/local/mysql

COPY main.sh /usr/local/mysql/

RUN chmod a+x /usr/local/mysql/main.sh

CMD bash /usr/local/mysql/main.sh
