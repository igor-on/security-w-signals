FROM opensearchproject/opensearch:2.17.1
ADD ./build/distributions/opensearch-security-w-signals-2.17.1.0-SNAPSHOT.zip /usr/

RUN /usr/share/opensearch/bin/opensearch-plugin install --batch file:///usr/opensearch-security-w-signals-2.17.1.0-SNAPSHOT.zip