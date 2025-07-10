# 🔍 DiscourseMap - Discourse Forum Güvenlik Tarayıcısı

## 📋 Proje Hakkında

Merhaba BTT Community! Discourse forumlarınıza güvenlik taramalarını yapmak için geliştirdiğim yeni bir araçtan bahsetmek istiyorum.

**DiscourseMap**, Discourse forum platformları için özel olarak geliştirilmiş kapsamlı bir güvenlik değerlendirme aracıdır. Penetrasyon testçileri, güvenlik araştırmacıları ve forum yöneticileri için tasarlanmış bu araç, Discourse forumlarındaki potansiyel güvenlik açıklarını tespit etmeye yardımcı olur.

---

## 🖼️ Görsel Önizleme



## ⚡ Temel Özellikler

- **🎯 Modüler Tarama Sistemi**: API, kimlik doğrulama, plugin'ler, kullanıcı enumerasyonu
- **🔐 CVE Exploit Modülü**: Bilinen güvenlik açıklarını test etme
- **📊 Çoklu Rapor Formatı**: JSON, HTML, TXT çıktı desteği
- **🐳 Docker Desteği**: Kolay kurulum ve taşınabilirlik
- **🔄 CI/CD Entegrasyonu**: GitHub Actions ile otomatik testler
- **🛡️ Ruby Exploit Koleksiyonu**: Gelişmiş exploit modülleri
- **⚙️ Yapılandırılabilir**: Özelleştirilebilir tarama parametreleri

## 🚀 Kurulum ve Kullanım

```bash
# PyPI'den kurulum
pip install discoursemap

# Temel kullanım
discoursemap -u https://forum.example.com

# Modüler tarama
discoursemap -u https://forum.example.com --modules info,api,users

# Docker ile
docker run -it ghcr.io/ibrahimsql/discoursemap --help
```

## 💡 Kullanım Senaryoları

- **Penetrasyon Testleri**: Discourse forumlarının güvenlik değerlendirmesi
- **Forum Yönetimi**: Kendi forumunuzun güvenlik kontrolü
- **Güvenlik Araştırması**: Discourse platformu güvenlik analizi
- **Compliance Kontrolü**: Güvenlik standartlarına uygunluk testi

## 🛠️ Teknik Detaylar

- **Platform**: Python 3.8+ & Ruby 2.7+ (Cross-platform)
- **Lisans**: MIT (Açık kaynak)
- **Mimari**: Modüler yapı, genişletilebilir
- **Performans**: Async/await desteği, hızlı tarama
- **Güvenlik**: Güvenli kodlama standartları
- **Exploit Engine**: Ruby tabanlı exploit scriptleri
- **Hybrid Architecture**: Python + Ruby entegrasyonu

## 📈 Gelişim Durumu

✅ **Tamamlanan Özellikler**:
- Temel tarama modülleri
- Rapor sistemi
- Docker entegrasyonu
- CI/CD pipeline
- PyPI dağıtımı

🔄 **Devam Eden Geliştirmeler**:
- False positivesiz SQLİ ve SSRF Taraması 
- Gelişmiş exploit modülleri
---

## 🙏 Teşekkürler

Bu projenin geliştirilmesinde bana yardımcı olan ve destek veren herkese teşekkür ederim:

### 💝 Özel Teşekkürler

- **[İsim]** - Proje fikri ve ilk geliştirme aşamasındaki değerli katkıları için
- **[İsim]** - Code review ve güvenlik önerileri için
- **[İsim]** - Test süreçlerindeki yardımları için
- **[İsim]** - Dokümantasyon ve kullanıcı deneyimi iyileştirmeleri için

### 🌟 Topluluk Desteği

- **BTT Community** - Geri bildirimler ve öneriler için
- **GitHub Contributors** - Bug raporları ve feature request'ler için
- **Security Community** - Güvenlik testleri ve vulnerability raporları için

### 🔧 Teknik Destek

- **Open Source Libraries** - Kullandığımız tüm açık kaynak kütüphanelere
- **Python & Ruby Communities** - Dokümantasyon ve best practice'ler için
- **Docker & GitHub Actions** - CI/CD altyapısı için

---

## ⚠️ Yasal Uyarı

Bu araç **sadece yasal penetrasyon testleri** ve **kendi sistemlerinizin güvenlik değerlendirmesi** için kullanılmalıdır. İzniniz olmayan sistemlerde kullanmak yasaktır ve sorumluluğu kullanıcıya aittir.

## 🤝 Katkıda Bulunun

Proje tamamen açık kaynak! GitHub'da:
- ⭐ Star vermeyi unutmayın
- 🐛 Bug raporları
- 💡 Özellik önerileri
- 🔧 Pull request'ler

Hepsi memnuniyetle karşılanır!

## 📞 İletişim

Sorularınız, önerileriniz veya katkılarınız için:
- GitHub Issues
- Bu topic altında yorum
- Discord: [username]
- Email: [email]

---

**Güvenlik alanında çalışan arkadaşlar için faydalı olacağını düşünüyorum. Deneyenler geri bildirimlerini paylaşırsa çok memnun olurum! 🔒**

*#güvenlik #penetrationtest #discourse #python #opensource #cybersecurity*

---

### 📊 Proje İstatistikleri

- **⭐ GitHub Stars**: [Güncel sayı]
- **🍴 Forks**: [Güncel sayı]
- **📦 PyPI Downloads**: [Güncel sayı]
- **🐳 Docker Pulls**: [Güncel sayı]
- **🔄 Son Güncelleme**: [Tarih]

### 🔗 Bağlantılar

- **GitHub Repository**: https://github.com/username/discoursemap
- **PyPI Package**: https://pypi.org/project/discoursemap/
- **Docker Hub**: https://hub.docker.com/r/username/discoursemap
- **Documentation**: https://discoursemap.readthedocs.io/