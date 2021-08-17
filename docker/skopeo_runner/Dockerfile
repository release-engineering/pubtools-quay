FROM fedora@sha256:d18bc88f640bc3e88bbfacaff698c3e1e83cae649019657a3880881f2549a1d0

WORKDIR /src

COPY ./ ./
RUN cp /src/Red_Hat_IT_Root_CA.crt /etc/pki/ca-trust/source/anchors && \
    update-ca-trust

RUN dnf install -y skopeo && dnf -y clean all
