# Portfolio Dashboard

Aplikacja do śledzenia portfela inwestycyjnego. Działa jako kontener Docker na NAS-ie.

## Struktura

```
portfolio/
├── docker-compose.yml
├── backend/
│   ├── Dockerfile
│   ├── main.py
│   └── requirements.txt
├── frontend/
│   └── index.html
└── data/           # SQLite tutaj (tworzony automatycznie)
```

## Uruchomienie

```bash
# Sklonuj/skopiuj folder na NAS
# Przejdź do folderu
cd portfolio

# Zbuduj i uruchom
docker compose up -d --build

# Sprawdź logi
docker compose logs -f
```

Aplikacja działa na porcie **8765** (możesz zmienić w docker-compose.yml).

## Nginx Proxy Manager

1. Dodaj nowy Proxy Host
2. Domain Names: `portfolio.twoja-domena.pl`
3. Forward Hostname/IP: adres NAS-a (np. `192.168.1.100`)
4. Forward Port: `8765`
5. Zakładka **Advanced** → Basic Auth:
   - Włącz "Access List" lub użyj wbudowanego Basic Auth
   - Alternatywnie w NPM: Access Lists → Add → Basic HTTP Authentication

### Basic Auth w NPM (prostsze)

1. NPM → Access Lists → Add Access List
2. Nazwa: `portfolio`
3. Zakładka Authorization → Add:
   - Username: `twoj_login`
   - Password: `silne_haslo`
4. Zakładka Access → Allow: `0.0.0.0/0` (lub zawęź do LAN: `192.168.1.0/24`)
5. Przypisz listę do Proxy Host portfolio

## Backup

- **Eksport**: w aplikacji → Ustawienia → Eksportuj JSON
- **Plik SQLite**: `./data/portfolio.db` — możesz kopiować bezpośrednio

## Aktualizacja frontendu

Edytuj `frontend/index.html` — zmiany widoczne od razu, bez przebudowania kontenera.

## Aktualizacja backendu

```bash
docker compose down
docker compose up -d --build
```

## Zatrzymanie

```bash
docker compose down
```