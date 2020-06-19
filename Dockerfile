FROM tiangolo/meinheld-gunicorn:python3.7

LABEL maintainer="Justin Paul <jp@zerto.com>"

COPY . /app

RUN pip install -r requirements.txt

RUN pip3 install git+https://github.com/recklessop/pyzerto3.git
