# Maintainer: Ibrahim <ibrahim@example.com>
pkgname=discoursemap
pkgver=1.2.2
pkgrel=1
pkgdesc="Discourse forum security scanner for security professionals and forum administrators"
arch=('any')
url="https://github.com/ibrahmsql/discoursemap"
license=('MIT')
depends=('python' 'python-pip')
optdepends=(
    'python-pyyaml: YAML configuration support'
    'python-requests: HTTP requests'
    'python-beautifulsoup4: HTML parsing'
    'python-lxml: XML processing'
    'python-colorama: Colored terminal output'
    'python-tqdm: Progress bars'
    'python-jinja2: Template engine'
)
source=("https://files.pythonhosted.org/packages/source/d/discoursemap/discoursemap-${pkgver}.tar.gz")
sha256sums=('SKIP')  # Will be updated with actual checksum

build() {
    cd "$srcdir/$pkgname-$pkgver"
    python setup.py build
}

package() {
    cd "$srcdir/$pkgname-$pkgver"
    python setup.py install --root="$pkgdir" --optimize=1
    
    # Install license
    install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
    
    # Install documentation
    install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
}