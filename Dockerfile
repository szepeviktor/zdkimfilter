FROM debian:stretch

ENV LC_ALL C
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y \
    wget subversion unzip build-essential courier-mta \
    libtool-bin m4 gettext autoconf pkg-config publicsuffix \
    libopendkim-dev uuid-dev zlib1g-dev libunistring-dev nettle-dev libopendbx1-dev \
    && wget "http://ftp.de.debian.org/debian/pool/main/libi/libidn2/libidn2-0_2.0.5-1~bpo9+1_amd64.deb" \
    && wget "http://ftp.de.debian.org/debian/pool/main/libi/libidn2/libidn2-dev_2.0.5-1~bpo9+1_amd64.deb" \
    && dpkg -i libidn2*_amd64.deb
    # https://packages.debian.org/source/stretch-backports/libidn2

RUN mkdir /root/zdkimfilter

WORKDIR /root/zdkimfilter

RUN svn checkout "http://www.tana.it/svn/zdkimfilter/trunk/" . \
    && unzip m4_redist.zip \
    && libtoolize \
    && aclocal \
    && autoheader --verbose \
    && touch NEWS README AUTHORS ChangeLog \
    && automake --verbose --add-missing \
    && autoreconf --verbose -si

RUN ./configure --prefix=/usr --enable-dkimsign-setuid \
    && make

RUN make check
