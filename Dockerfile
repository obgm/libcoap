FROM debian:testing-slim

RUN apt-get update && apt-get install -y autoconf automake gcc \
  libtool libtool-bin make pkg-config libcunit1-dev libssl-dev
#RUN apt-get install -y graphviz doxygen libxml2-utils xsltproc
#RUN apt-get install -y docbook-xml docbook-xsl asciidoc

ENV libcoap_dir=/libcoap
ADD . $libcoap_dir
WORKDIR $libcoap_dir

RUN ./autogen.sh --clean && ./autogen.sh
