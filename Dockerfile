FROM python:3.8

RUN mkdir /app

WORKDIR /app

RUN pip install crcmod

ADD . /app

CMD python start_client_debugger.py
