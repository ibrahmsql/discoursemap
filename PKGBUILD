# Maintainer: ibrahimsql <ibrahimsql@proton.me>
# Contributor: ibrahimsql <ibrahimsql@proton.me>

pkgname=discoursemap
pkgver=1.2.2
pkgrel=1
pkgdesc="Discourse forum security scanner for security professionals and forum administrators"
arch=('any')
url="https://github.com/ibrahmsql/discoursemap"
license=('MIT')
groups=()
backup=('etc/discoursemap/config.yaml')
depends=('python>=3.8' 
         'python-pip'
         'python-pyyaml'
         'python-requests>=2.28.0'
         'python-beautifulsoup4>=4.11.0'
         'python-lxml>=4.9.0'
         'python-colorama'
         'python-tqdm>=4.64.0'
         'python-jinja2>=3.1.0'
         'python-urllib3>=1.26.0'
         'python-certifi>=2022.0.0'
         'python-chardet>=5.0.0'
         'python-idna>=3.4'
         'python-pysocks>=1.7.1'
         'python-cryptography>=45.0.0'
         'python-pyopenssl>=25.1.0'
         'python-typing-extensions'
         'python-setuptools'
         'python-wheel')
makedepends=('python-build' 'python-installer' 'python-wheel' 'python-setuptools')
optdepends=('ruby-nokogiri: HTML/XML parsing for Ruby exploits'
depends=('python>=3.8' 'python-pip')
makedepends=('python-build' 'python-installer' 'python-wheel' 'python-setuptools')
optdepends=('python-pyyaml: YAML configuration support'
            'python-requests: HTTP library for API calls'
            'python-beautifulsoup4: HTML parsing'
            'python-lxml: XML/HTML processing'
            'python-colorama: Colored terminal output'
            'python-tqdm: Progress bars'
            'python-jinja2: Template engine'
            'python-urllib3: HTTP client library'
            'python-certifi: SSL certificate verification'
            'python-chardet: Character encoding detection'
            'python-idna: Internationalized domain names'
            'python-cryptography: Cryptographic operations'
            'python-pyopenssl: OpenSSL wrapper'
            'ruby-nokogiri: HTML/XML parsing for Ruby exploits'
            'ruby-json: JSON processing for Ruby exploits'
            'ruby-openssl: SSL/TLS support for Ruby exploits')
source=("https://files.pythonhosted.org/packages/source/d/discoursemap/discoursemap-${pkgver}.tar.gz")
sha256sums=('8df189ac1eed024fffd2ec73b6ec987b0e31446be642b33c7626bfc835701ffb')

build() {
    cd "$srcdir/$pkgname-$pkgver"
    python -m build --wheel --no-isolation
}

package() {
    cd "$srcdir/$pkgname-$pkgver"
    python -m installer --destdir="$pkgdir" dist/*.whl
    
    # Install license
    install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
    
    # Install documentation
    install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
    
    # Install configuration files
    install -Dm644 config.yaml "$pkgdir/etc/$pkgname/config.yaml"
    
    # Install data files
    if [ -d "data" ]; then
        install -dm755 "$pkgdir/usr/share/$pkgname/data"
        cp -r data/* "$pkgdir/usr/share/$pkgname/data/"
    fi
    
    # Install Ruby exploits
    if [ -d "ruby_exploits" ]; then
        install -dm755 "$pkgdir/usr/share/$pkgname/ruby_exploits"
        cp -r ruby_exploits/* "$pkgdir/usr/share/$pkgname/ruby_exploits/"
    fi
    
    # Install discourse exploits
    if [ -d "discoursemap/discourse_exploits" ]; then
        install -dm755 "$pkgdir/usr/share/$pkgname/discourse_exploits"
        cp -r discoursemap/discourse_exploits/* "$pkgdir/usr/share/$pkgname/discourse_exploits/"
    fi

}
