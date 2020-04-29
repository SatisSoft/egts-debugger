FROM python:3.8

RUN mkdir /app

WORKDIR /app

RUN pip install crcmod

ADD . /app

ENV DISPATCHER_ID=1
ENV PORT=9090

CMD python start_client_loop_debugger.py --dispatcher ${DISPATCHER_ID} --port=${PORT}
