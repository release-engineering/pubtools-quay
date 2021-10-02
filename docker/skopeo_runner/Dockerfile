FROM fedora@sha256:0c18a515203b836ea840f7033a11d6833f9468fda6a99f5a29695cfbaf43f24a

WORKDIR /src

COPY ./ ./
RUN cp /src/Red_Hat_IT_Root_CA.crt /etc/pki/ca-trust/source/anchors && \
    update-ca-trust

RUN dnf install -y skopeo && dnf -y clean all
