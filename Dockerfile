#
# Example cmdline:
# docker run -d --restart unless-stopped -e TZ=Europe/Helsinki -e MQTT_BROKER_HOST=XXXX -e MQTT_BROKER_USER=YYYY -e MQTT_BROKER_PASS=ZZZZ -e ALSAVO_SERIAL=NNNNNN -e ALSAVO_PASS=MMMMMMM alsavo-mqtt

####################################################################################
#### Use base image to compile AlsavoCtrl
####################################################################################
FROM debian AS build

#### Install build dependencies for AlsavoCtrl
RUN apt-get update && \
        apt-get install -y cmake make g++ git		

#### Copy AlsavoCtrl files to image
RUN git clone https://github.com/strandborg/AlsavoCtrl.git

WORKDIR /AlsavoCtrl

#### Build AlsavoCtrl
RUN mkdir build

WORKDIR /AlsavoCtrl/build

RUN cmake ..
RUN make

# Use the official Python image as the base image
FROM python:3.11-slim

ENV ALSAVO_CTRL_PATH=./app/AlsavoCtrl

# Set the working directory inside the container
WORKDIR /app

# Copy your Python script and script file into the container
COPY alsavo.py .
COPY --from=build \
    ./AlsavoCtrl/build/AlsavoCtrl \
    ./app/

# Install the paho-mqtt library
RUN pip install paho-mqtt==1.6.1 Homie4

# Run the Python script with environment variables
CMD ["python", "alsavo.py"]
