FROM python:3.7.7-slim-stretch
RUN apt update && apt install git rlwrap -y
RUN mkdir /red-toolkit
COPY requirements.txt /red-toolkit/requirements.txt
WORKDIR /red-toolkit
RUN pip3 install -r requirements.txt
COPY toolkit.py /red-toolkit/toolkit.py
COPY README.md /red-toolkit/README.md
ENTRYPOINT ["python3", "toolkit.py"]