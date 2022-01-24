FROM alpine:3.15
RUN apk add --no-cache python3-dev python3 py-pip gcc musl-dev
WORKDIR /app
COPY . .
RUN pip install -r wol/requirements.txt

ENTRYPOINT ["python3", "wol.py"]
CMD []
