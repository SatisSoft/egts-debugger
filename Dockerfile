FROM python:3.8

RUN mkdir /app

WORKDIR /app

RUN pip install crcmod

ADD . /app

ENV DISPATCHER_ID=1

CMD python start_client_loop_debugger.py -d ${DISPATCHER_ID}
