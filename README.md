# Digital Security Toolkit

Sigurnosni alat za oporavak podataka, YARA skeniranje i forenzičku analizu.

## 🚀 Pokretanje sa Admin Privilegijama

### Opcija 1: Direktno pokretanje (preporučeno)
```bash
python main.py
```
- Aplikacija će automatski provjeriti admin privilegije
- Ako nema admin privilegija, pokušaće da se restartuje sa admin privilegijama
- Ako ne uspije, nastaviti će u limited modu

### Opcija 2: Admin launcher (alternativno)
```bash
python run_as_admin.py
```
- Koristi alternativni pristup za admin restart
- Može biti pouzdaniji na nekim sistemima

### Opcija 3: Manualno pokretanje kao Administrator
1. Desni klik na `main.py`
2. "Run as administrator"

## ⚠️ Rješavanje problema sa UAC promptom

Ako se aplikacija gasi nakon UAC prompta:

1. **Pokušajte alternativni launcher:**
   ```bash
   python run_as_admin.py
   ```

2. **Ili pokrenite direktno kao Administrator:**
   - Desni klik na `main.py`
   - "Run as administrator"

3. **Provjerite da li imate pytsk3 instaliran:**
   ```bash
   pip install pytsk3
   ```

## 🔧 Funkcionalnosti

### File Recovery (Oporavak podataka)
- **Recycle Bin recovery** - oporavak iz Recycle Bin-a
- **Recent Items scanning** - skeniranje .lnk fajlova
- **pytsk3 unallocated carving** - oporavak totalno obrisanih fajlova (sa admin privilegijama)
- **User directory scanning** - skeniranje korisničkih direktorija

### YARA Scanning
- Malware detection
- Custom rule support
- Batch scanning

### System Monitoring
- File integrity monitoring
- Timeline analysis
- Security reports

## 📋 Zahtjeve

- Python 3.7+
- Windows 10/11
- Admin privilegije (za punu funkcionalnost)
- pytsk3 (za stvarni oporavak obrisanih fajlova)

## 🛠️ Instalacija

1. **Klonirajte repozitorij:**
   ```bash
   git clone <repository-url>
   cd digital_security_toolkit
   ```

2. **Instalirajte zavisnosti:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Pokrenite aplikaciju:**
   ```bash
   python main.py
   ```

## 🔒 Sigurnosne mjere

- **Read-only operacije** - aplikacija ne mijenja sistemske fajlove
- **Admin provera** - pytsk3 oporavak radi samo sa admin privilegijama
- **Ograničenja** - maksimalno 100MB unallocated carving
- **Safe paths** - skenira samo korisničke direktorije

## 📊 Status indikatori

- 🔒 **ADMIN MODE** - aplikacija radi sa admin privilegijama
- ⚠️ **LIMITED MODE** - aplikacija radi bez admin privilegija

## 🧪 Testiranje

Pokrenite test skriptu da provjerite funkcionalnost:
```bash
python test_admin.py
```

## 📝 Logovi

Logovi se čuvaju u `logs/dst.log` direktoriju.

## ⚡ Troubleshooting

### Problem: Aplikacija se gasi nakon UAC prompta
**Rešenje:** Koristite `run_as_admin.py` ili pokrenite direktno kao Administrator

### Problem: pytsk3 nije dostupan
**Rešenje:** Instalirajte pytsk3: `pip install pytsk3`

### Problem: Import greške
**Rešenje:** Proverite da li su svi moduli instalirani: `pip install -r requirements.txt`

## 📄 Licenca

PMF License - pogledajte LICENSE fajl za detalje.

## 👨‍💻 Autor

**Harun Mutevelić** 