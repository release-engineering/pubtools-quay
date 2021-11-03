FROM fedora@sha256:72c6c48a902baff1ab9948558556ef59e3429c65697287791be3c709738955b3

WORKDIR /src

COPY ./ ./
RUN cp /src/Red_Hat_IT_Root_CA.crt /etc/pki/ca-trust/source/anchors && \
    update-ca-trust

RUN dnf install -y skopeo && dnf -y clean all
