FROM ubuntu

RUN apt update -y && apt install -y wget unzip qrencode net-tools


RUN mkdir /etc/mysql /usr/local/mysql

COPY main.sh /usr/local/mysql/

RUN chmod a+x /usr/local/mysql/main.sh

CMD bash /usr/local/mysql/main.sh
