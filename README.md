# itsec-shell-automation

Detta repository innehåller enkla skript för grundläggande säkerhetskontroller
skrivna i Bash och PowerShell.

Syftet är att visa förståelse för:
- scripting
- automatisering
- grundläggande IT-säkerhetskontroller
- versionshantering med Git

---

## Innehåll

### Bash
- `hello-bash.sh` – testskript för Bash
- `basic-security-check.sh` – utför grundläggande säkerhetskontroller

### PowerShell
- `hello-ps.ps1` – testskript för PowerShell
- `basic-security-check.ps1` – utför grundläggande säkerhetskontroller

---

## Funktionalitet i säkerhetsskripten

Båda säkerhetsskripten kan:

- kontrollera om en fil existerar
- visa filinformation/rättigheter
- kontrollera om en användare existerar
- logga resultat till `security_log.txt`
- ta input från användaren
- använda funktioner för modulär struktur

---

## Körning

### Bash
```bash
bash basic-security-check.sh
