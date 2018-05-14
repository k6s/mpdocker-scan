FROM iotsec/arm-alpine

RUN apk --update add python3 python3-dev build-base \
            mariadb-dev
RUN pip3 install mysqlclient

COPY ./nmap_scan.py /usr/bin/nmap_scan.py

CMD pwnable.py "$IP_RANGE" "${MYSQL_HOST}" "${MYSQL_USER}" "${MYSQL_PASSWORD}" $MYSQL_DATABASE
