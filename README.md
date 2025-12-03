# Chatter

## Übersicht

Dieses Projekt ist ein verschlüsseltes Chat-System in Python. Es besteht aus einem Client ([client.py](client.py)), einer Verschlüsselungsbibliothek ([cipher.py](cipher.py)) und beliebig vielen dezentralen Chat-Server-Instanzen.

---

## Komponenten

- [`client.py`](client.py): Der Chat-Client (benötigt auch [`cipher.py`](cipher.py))
- [`cipher.py`](cipher.py): Verschlüsselungsfunktionen für Nachrichten
- [`server-instance.py`](server-instance.py): **Dezentrale Chat-Server-Instanz**
  - Jeder kann damit einen eigenen Gruppenchat-Server hosten (z.B. mit Port-Forwarding)
  - Verbindungen sind nur nach erfolgreichem Login am Main Server möglich

---

## Was wird benötigt?

- **Python 3.8+**
- Für den Chat-Client: [`client.py`](client.py) und [`cipher.py`](cipher.py)
- Für eigene Gruppenchat-Server: [`server-instance.py`](server-instance.py) und [`cipher.py`](cipher.py)

---

## Installation der benötigten Bibliotheken

Vor dem Start musst du die benötigten Python-Bibliotheken installieren.
Führe dazu im Projektordner folgenden Befehl im Terminal aus:

```sh
pip install -r reqirements.txt
```

Das installiert alle benötigten Pakete (z.B. `tk` für die grafische Oberfläche).

---

## Wie funktioniert das System?

1. **Main Server**
   - Der Main Server wird **von mir zentral gehostet**.
   - Die IP-Adresse ist im Client fest einprogrammiert.
   - Er ist für Login und Benutzerverwaltung zuständig.
   - **Du musst diesen Server nicht selbst hosten!**

2. **Chat-Instanz (`server-instance.py`)**
   - Jeder Nutzer kann eine eigene Instanz starten, z.B. für einen privaten Gruppenchat:
     ```sh
     python server-instance.py
     ```
   - Instanzen können öffentlich (mit Port-Forwarding) oder im lokalen Netzwerk betrieben werden.
   - Eine Verbindung zu einer Instanz ist nur möglich, wenn du dich vorher am Main Server mit Benutzername und Passwort angemeldet hast.

3. **Client**
   - Starten mit:
     ```sh
     python client.py
     ```
   - Verbindet sich automatisch mit dem zentralen Main Server für Login/Registrierung.
   - Nach erfolgreichem Login kannst du dich in der Client-GUI mit beliebigen Chat-Instanzen verbinden.

---

## Wichtige Hinweise

- **Der Main Server wird zentral von mir betrieben.**
  Du musst ihn nicht selbst hosten und kannst dich mit deinem Account einloggen.
- **`server-instance.py` ist für dezentrale Gruppen-Chats** – jeder kann damit einen eigenen Chat-Server hosten.
- **Ohne Login am Main Server ist keine Verbindung zu Chat-Instanzen möglich!**
- **`client.py` und `cipher.py` werden immer benötigt**, egal ob du chattest oder einen Server betreibst.

---

## Zusammenfassung

- **Zum Chatten brauchst du:** [`client.py`](client.py) und [`cipher.py`](cipher.py)
- **Zum Hosten eines eigenen Gruppenchats:** [`server-instance.py`](server-instance.py) und [`cipher.py`](cipher.py)
- **Der zentrale Login läuft immer über den Main Server** – dieser ist bereits für dich funktional und online.