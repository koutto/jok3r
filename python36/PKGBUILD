# Maintainer: Tobias Kunze <r@rixx.de>
# Maintained at https://github.com/rixx/pkgbuilds, feel free to submit patches

pkgname=python36
pkgver=3.6.15
pkgrel=5
_pybasever=3.6
_pymajver=3
pkgdesc="Major release 3.6 of the Python high-level programming language"
arch=('i686' 'x86_64' 'arm' 'pentium4')
license=('custom')
url="http://www.python.org/"
depends=('expat' 'bzip2' 'gdbm' 'openssl' 'libffi' 'zlib')
makedepends=('tk' 'sqlite' 'bluez-libs' 'mpdecimal')
optdepends=('tk: for tkinter' 'sqlite')
source=(http://www.python.org/ftp/python/${pkgver}/Python-${pkgver}.tar.xz alignment.patch)
sha256sums=('6e28d7cdd6dd513dd190e49bca3972e20fcf455090ccf2ef3f1a227614135d91' SKIP)
provides=("python=$pkgver")

prepare() {
  cd "${srcdir}/Python-${pkgver}"

  # FS#23997
  sed -i -e "s|^#.* /usr/local/bin/python|#!/usr/bin/python|" Lib/cgi.py

  msg "fix alignment issue (issue27987)"
  # via https://github.com/pyenv/pyenv/issues/1889
  # and https://bugs.python.org/file44413/alignment.patch
  patch -p1 < ../alignment.patch

  # Ensure that we are using the system copy of various libraries (expat, zlib and libffi),
  # rather than copies shipped in the tarball
  rm -rf Modules/expat
  rm -rf Modules/zlib
  rm -rf Modules/_ctypes/{darwin,libffi}*
  rm -rf Modules/_decimal/libmpdec
}

build() {
  cd "${srcdir}/Python-${pkgver}"

  CFLAGS=-DOPENSSL_NO_SSL2 ./configure --prefix=/usr \
              --enable-shared \
              --with-threads \
              --with-computed-gotos \
              --enable-ipv6 \
              --with-system-expat \
              --with-dbmliborder=gdbm:ndbm \
              --with-system-libmpdec \
              --with-system-ffi \
              --enable-loadable-sqlite-extensions \
              --without-ensurepip

  make
}

package() {
  cd "${srcdir}/Python-${pkgver}"
  # altinstall: /usr/bin/pythonX.Y but not /usr/bin/python or /usr/bin/pythonX
  make DESTDIR="${pkgdir}" altinstall maninstall

  # Avoid conflicts with the main 'python' package, once Python 3.7 is standard.
  rm "${pkgdir}/usr/lib/libpython${_pymajver}.so"
  rm "${pkgdir}/usr/share/man/man1/python${_pymajver}.1"

  # Fix FS#22552
  ln -sf ../../libpython${_pybasever}m.so \
    "${pkgdir}/usr/lib/python${_pybasever}/config-${_pybasever}m-${CARCH}-linux-gnu/libpython${_pybasever}m.so"

  # Fix pycairo build
  ln -sf python${_pybasever}m-config "${pkgdir}/usr/bin/python${_pybasever}-config"

  # Clean-up reference to build directory
  sed -i "s|$srcdir/Python-${pkgver}:||" "$pkgdir/usr/lib/python${_pybasever}/config-${_pybasever}m-${CARCH}-linux-gnu/Makefile"

  # License
  install -Dm644 LICENSE "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
}
