FROM debian:stretch
LABEL Description="This image is used to test Tor2web" Version="0.1"
RUN apt-get -yq update && apt-get -yq --no-install-suggests --no-install-recommends --allow-downgrades --allow-remove-essential --allow-change-held-packages install strace libio-socket-socks-perl libproc-daemon-perl libipc-run-perl libcommon-sense-perl libhttp-daemon-perl libio-socket-ssl-perl python-pip  python-setuptools python-dev libffi-dev libssl1.0-dev apparmor apparmor-utils build-essential python-zope.component python-zope.event python-zope.interface python-coverage python-wheel python-requests python-idna python-certifi git procps
RUN ln -s python-coverage /usr/bin/coverage; pip install codecov
COPY . /usr/src/github/Tor2web
RUN pip2 install -r /usr/src/github/Tor2web/requirements.txt
