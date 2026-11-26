# mcp-s3

MCP (Model Context Protocol) server yang memberi Claude akses **baca saja** ke **satu root prefix** di satu bucket AWS S3, misalnya `s3://my-bucket/claude-workspace/`. Claude hanya melihat path relatif terhadap root itu dan tidak bisa membaca, menulis, atau melihat key di luar root, walau diminta oleh pengguna atau oleh isi file.

Status versi ini (0.1.0):

- Provider: AWS S3. Storage S3-compatible (MinIO dan sejenisnya) bisa dipakai lewat `S3_ENDPOINT_URL`; MinIO dipakai untuk test lokal.
- Read-only. Hanya ada empat tool: `list_objects`, `get_object_info`, `read_object`, `search_objects`. Tool write dan delete ditunda dan belum ada di kode.
- Transport:
  - stdio: Claude Code dan Claude Desktop di komputer yang sama.
  - Streamable HTTP dengan OAuth (remote, selalu read-only): Claude Code di komputer lain, MCP Inspector, dan custom connector claude.ai. Lihat [Mode HTTP (remote)](#mode-http-remote).
- Mode HTTP sudah dites dengan smoke test di `http://localhost` (alur OAuth lengkap dengan MinIO). Tes manual dengan Claude Code dan MCP Inspector, serta deploy nyata dan pendaftaran connector claude.ai, belum dilakukan (menunggu domain HTTPS).
- Audit log: satu baris JSON per pemanggilan tool di stderr. Lihat [Audit log](#audit-log).

Rencana lengkap dan keputusan desain ada di [`PLAN.md`](PLAN.md).

## Daftar isi

- [Model keamanan](#model-keamanan)
- [Prasyarat](#prasyarat)
- [Setup IAM dan profile `mcp-s3`](#setup-iam-dan-profile-mcp-s3)
- [Instalasi dan build](#instalasi-dan-build)
- [Konfigurasi](#konfigurasi)
- [Connect ke Claude Code](#connect-ke-claude-code)
- [Connect ke Claude Desktop](#connect-ke-claude-desktop)
- [Testing dengan MCP Inspector](#testing-dengan-mcp-inspector)
- [Mode HTTP (remote)](#mode-http-remote)
  - [Menjalankan secara lokal](#menjalankan-secara-lokal)
  - [Alur login OAuth](#alur-login-oauth)
  - [Connect Claude Code lewat HTTP](#connect-claude-code-lewat-http)
  - [Connect MCP Inspector lewat HTTP](#connect-mcp-inspector-lewat-http)
  - [Docker](#docker)
  - [Deploy di balik HTTPS (`deploy/`)](#deploy-di-balik-https-deploy)
  - [Custom connector claude.ai](#custom-connector-claudeai)
  - [Client OAuth dan redirect URI](#client-oauth-dan-redirect-uri)
  - [Token, restart, dan pencabutan akses](#token-restart-dan-pencabutan-akses)
  - [Batasan mode HTTP](#batasan-mode-http)
- [Audit log](#audit-log)
- [Menjalankan test](#menjalankan-test)
- [Daftar tool](#daftar-tool)
- [Peringatan keamanan](#peringatan-keamanan)
- [Troubleshooting](#troubleshooting)

## Model keamanan

S3 tidak punya folder sungguhan; key hanyalah string datar. Karena itu pembatasan dilakukan di dua lapis, supaya satu lapis yang gagal tidak langsung membuka seluruh bucket.

### Lapis 1: path jail di aplikasi

- Semua path dari Claude relatif terhadap root. String kosong `""` berarti root itu sendiri, dan `/` di awal path diabaikan.
- Path ditolak jika berisi segmen `.` atau `..`, backslash `\`, karakter kontrol (termasuk NUL), segmen kosong di tengah (`a//b`), atau menghasilkan key lebih dari 1024 byte UTF-8.
- Input tidak pernah di-URL-decode: `%2e%2e/x` diperlakukan sebagai teks literal, bukan `../x`.
- Semua key di respons dikembalikan relatif (root prefix dibuang). Key hasil list yang tidak diawali root prefix dibuang.
- Pesan error dipetakan ke kode generik (`NotFound`, `AccessDenied`, `PathOutsideRoot`, ...) tanpa nama bucket, root prefix, credential, atau stack trace.
- `S3_ROOT_PREFIX` divalidasi saat start: wajib diisi (tidak ada mode "seluruh bucket") dan wajib diakhiri `/`, supaya prefix `data` tidak ikut cocok dengan `data-backup/...`. Konfigurasi yang tidak valid membuat proses berhenti dengan pesan di stderr.
- `next_token` dari `list_objects` adalah token terenkripsi (AES-256-GCM) yang terikat ke path dan mode `recursive` yang sama dan berlaku satu jam. Token mentah dari S3 tidak pernah dikirim ke Claude.
- Pola glob `search_objects` dicocokkan dengan matcher buatan sendiri yang waktunya terbatas (tanpa regex backtracking), jadi pola aneh tidak bisa membekukan server.
- Log dan audit log hanya ditulis ke stderr. stdout dipakai protokol MCP stdio.
- Mode HTTP menambah lapis autentikasi: `/mcp` hanya menerima access token OAuth yang valid, dan login memakai satu akun admin. Detail di [Mode HTTP (remote)](#mode-http-remote).

### Lapis 2: IAM policy least-privilege

Credential yang dipakai server hanya boleh `s3:ListBucket` dengan `s3:prefix` di bawah root, dan `s3:GetObject` untuk key di bawah root. Contoh siap pakai ada di [`iam-policy.example.json`](iam-policy.example.json). Policy ini tidak memberi izin write atau delete sama sekali. `HeadObject` (dipakai `get_object_info` dan `read_object`) tercakup oleh `s3:GetObject`.

Jika kode lapis 1 punya bug, lapis 2 tetap membuat S3 menjawab `AccessDenied` untuk key di luar root.

### Read-only

Versi ini tidak punya tool yang mengubah data. `MCP_S3_READ_ONLY` default `true` dan `MCP_S3_ALLOW_DELETE` default `false`. Di mode stdio, mengubah keduanya saat ini hanya memunculkan WARN di stderr, tidak menambah tool. Di mode HTTP, `MCP_S3_READ_ONLY=false` atau `MCP_S3_ALLOW_DELETE=true` membuat server gagal start. Isi file di bucket diperlakukan sebagai data, bukan instruksi, tetapi tetap waspadai prompt injection dari file yang tidak tepercaya.

## Prasyarat

- Node.js 24 (lihat `.nvmrc` dan `"engines"` di `package.json`) dan npm.
- Akun AWS dengan bucket yang sudah ada, dan izin untuk membuat IAM user serta policy.
- AWS CLI v2 (opsional, dipakai di langkah setup IAM di bawah; bisa juga lewat AWS Console).
- Claude Code dan/atau Claude Desktop.
- Docker dengan Compose v2, untuk `npm run test:int`, `npm run test:e2e`, image mode HTTP, dan contoh deploy.
- Untuk custom connector claude.ai: domain dengan HTTPS publik di port 443.

## Setup IAM dan profile `mcp-s3`

Buat IAM user khusus untuk server ini. Jangan memakai credential admin atau credential yang juga dipakai untuk hal lain.

1. Salin policy contoh lalu ganti `my-bucket` dan `claude-workspace/` dengan bucket dan root prefix milikmu (ada di tiga tempat: ARN bucket, dua nilai `s3:prefix`, dan ARN object). Root prefix di policy harus sama persis dengan `S3_ROOT_PREFIX`, termasuk `/` di akhir.

   ```bash
   cp iam-policy.example.json iam-policy.json
   # edit iam-policy.json
   ```

2. Buat user, pasang policy, dan buat access key:

   ```bash
   aws iam create-user --user-name mcp-s3
   aws iam put-user-policy --user-name mcp-s3 \
     --policy-name mcp-s3-read-only \
     --policy-document file://iam-policy.json
   aws iam create-access-key --user-name mcp-s3
   ```

   Output `create-access-key` berisi `AccessKeyId` dan `SecretAccessKey`. Secret hanya ditampilkan sekali; jangan disalin ke file di repo.

3. Simpan sebagai profile `mcp-s3` di `~/.aws/credentials`:

   ```bash
   aws configure --profile mcp-s3
   ```

   Isi access key, secret, dan region bucket. Server membaca profile lewat `AWS_PROFILE=mcp-s3` (default credential provider chain AWS SDK v3), jadi access key tidak perlu ditulis di konfigurasi MCP.

4. Uji lapis IAM langsung dengan credential ini, tanpa server:

   ```bash
   # Boleh: list di bawah root (perhatikan "/" di akhir)
   aws s3 ls s3://my-bucket/claude-workspace/ --profile mcp-s3

   # Harus AccessDenied: list di luar root
   aws s3 ls s3://my-bucket/ --profile mcp-s3

   # Harus 403/AccessDenied: baca key di luar root (ganti dengan key yang ada)
   aws s3api head-object --bucket my-bucket --key path/di-luar-root.txt --profile mcp-s3

   # Harus AccessDenied: menulis, walau di bawah root
   echo test > /tmp/mcp-s3-write-test.txt
   aws s3 cp /tmp/mcp-s3-write-test.txt s3://my-bucket/claude-workspace/mcp-s3-write-test.txt --profile mcp-s3
   ```

   Jika salah satu perintah yang seharusnya ditolak ternyata berhasil, perbaiki policy sebelum memakai server.

### IAM terpisah untuk server remote

Server mode HTTP wajib memakai IAM user atau role **terpisah** dari mode stdio, dengan policy read-only yang sama ([`iam-policy.example.json`](iam-policy.example.json) hanya berisi `s3:ListBucket` di bawah root dan `s3:GetObject`). Alasannya:

- Server remote bisa dijangkau dari internet. Jika credential-nya bocor, kerusakannya terbatas pada baca di bawah root.
- Credential stdio nanti bisa diberi izin tulis saat tool write diaktifkan. Credential remote tidak boleh pernah mendapat izin itu.
- Access key bisa dicabut satu per satu tanpa mengganggu mode lainnya.

```bash
aws iam create-user --user-name mcp-s3-remote
aws iam put-user-policy --user-name mcp-s3-remote \
  --policy-name mcp-s3-read-only \
  --policy-document file://iam-policy.json
aws iam create-access-key --user-name mcp-s3-remote
```

Di container, berikan access key lewat env (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) dari file env yang tidak di-commit, misalnya `deploy/mcp-s3.env`. Di EC2/ECS, lebih baik pakai instance role atau task role dengan policy yang sama dan kosongkan access key. Ulangi uji lapis IAM di langkah 4 dengan credential ini.

## Instalasi dan build

```bash
cd /path/to/mcp-s3
nvm use            # opsional, membaca .nvmrc (Node 24)
npm install
npm run build      # tsc, menghasilkan dist/
```

Entrypoint hasil build adalah `dist/index.js`. Jalankan ulang `npm run build` setiap kali kode berubah, karena Claude menjalankan file di `dist/`.

Untuk pengembangan, `npm run dev` menjalankan `src/index.ts` langsung dengan `tsx`. Server stdio menunggu pesan MCP di stdin, jadi menjalankannya langsung di terminal terutama berguna untuk mengecek konfigurasi; hentikan dengan Ctrl+C.

## Konfigurasi

Semua konfigurasi lewat environment variable. Contoh lengkap dengan komentar, dikelompokkan per mode (umum, stdio, http), ada di [`.env.example`](.env.example).

Server tidak membaca file `.env` secara otomatis. Biasanya env diisi di konfigurasi MCP client (lihat bagian connect di bawah). Untuk uji manual:

```bash
cp .env.example .env    # .env sudah di .gitignore
node --env-file=.env dist/index.js
```

| Variable | Wajib | Default | Keterangan |
| --- | --- | --- | --- |
| `S3_BUCKET` | ya | - | Nama bucket |
| `S3_ROOT_PREFIX` | ya | - | Root prefix, wajib diakhiri `/` (lihat aturan di bawah) |
| `AWS_REGION` | ya | - | Region bucket |
| `AWS_PROFILE` | tidak | - | Profile di `~/.aws/credentials` (disarankan) |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | tidak | - | Alternatif dari profile; `AWS_SESSION_TOKEN` untuk credential sementara. Dibaca AWS SDK, bukan kode server |
| `S3_ENDPOINT_URL` | tidak | - | URL `http(s)` untuk storage S3-compatible (MinIO, R2, ...) |
| `S3_FORCE_PATH_STYLE` | tidak | `false` | Biasanya `true` untuk MinIO |
| `MCP_S3_READ_ONLY` | tidak | `true` | Belum ada tool write; di stdio `false` hanya memunculkan WARN. Di mode HTTP `false` membuat server gagal start |
| `MCP_S3_ALLOW_DELETE` | tidak | `false` | Belum ada tool delete; tidak berefek selama read-only. Di mode HTTP `true` membuat server gagal start |
| `MCP_S3_MAX_READ_BYTES` | tidak | `1048576` (1 MiB) | Batas byte per panggilan `read_object` |
| `MCP_S3_MAX_WRITE_BYTES` | tidak | `5242880` (5 MiB) | Batas byte per tulis. Divalidasi, tetapi belum dipakai di versi read-only |
| `MCP_S3_MAX_LIST_KEYS` | tidak | `200` | Batas entri per halaman `list_objects` dan hasil `search_objects`; maksimum `1000` |
| `MCP_S3_TRANSPORT` | tidak | `stdio` | `stdio` atau `http` (Streamable HTTP + OAuth, lihat [Mode HTTP (remote)](#mode-http-remote)) |
| `MCP_S3_LOG_LEVEL` | tidak | `INFO` | `DEBUG`, `INFO`, `WARN`, atau `ERROR` (tidak case-sensitive). Log selalu ke stderr. Tidak mempengaruhi [audit log](#audit-log) |
| `MCP_S3_AUDIT_DATABASE_URL` | tidak | - | **Secret.** URL `postgresql://`. Jika diisi, [audit log](#audit-log) juga disimpan ke PostgreSQL |
| `MCP_S3_TOKEN_KEY` | wajib jika `http` | kunci acak per proses (stdio) | **Secret.** Kunci AES-256-GCM 32 byte dalam base64. Mengenkripsi `next_token`; di mode HTTP juga sumber kunci OAuth (lewat HKDF). Buat sekali dengan `openssl rand -base64 32` lalu simpan |

Variabel khusus mode HTTP (`MCP_S3_TRANSPORT=http`). Tidak dibaca di mode stdio.

| Variable | Wajib | Default | Keterangan |
| --- | --- | --- | --- |
| `MCP_S3_HTTP_HOST` | tidak | `127.0.0.1` | Alamat bind. Di container: `0.0.0.0`. Host bukan loopback dengan `MCP_S3_PUBLIC_URL` `http` memicu `WARN` di stderr (server tetap jalan) |
| `MCP_S3_HTTP_PORT` | tidak | `3000` | Port (1-65535) |
| `MCP_S3_PUBLIC_URL` | wajib jika host bukan loopback | `http://localhost:<port>` | Origin publik sekaligus OAuth issuer, misalnya `https://mcp.example.com`. Wajib `https`, kecuali `localhost`/`127.0.0.1`. Tanpa path, query, atau fragment |
| `MCP_S3_AUTH_USERNAME` | ya | - | **Secret.** Username akun admin di halaman login OAuth |
| `MCP_S3_AUTH_PASSWORD` | ya | - | **Secret.** Password admin, minimal 12 karakter. Tidak ada default |
| `MCP_S3_OAUTH_CLIENT_ID` | tidak | - | Client OAuth statis, 1-128 karakter `A-Z a-z 0-9 . _ ~ -`. Diisi bersama secret |
| `MCP_S3_OAUTH_CLIENT_SECRET` | wajib jika `MCP_S3_OAUTH_CLIENT_ID` diisi | - | **Secret.** Minimal 32 karakter, hanya `A-Z a-z 0-9 . _ ~ -`, misalnya `openssl rand -hex 32` |
| `MCP_S3_OAUTH_REDIRECT_URIS` | tidak | `https://claude.ai/api/mcp/auth_callback` | Daftar redirect URI (dipisah koma, dicocokkan persis) untuk client DCR dan client statis. Mengisi variabel ini **mengganti** default. Redirect loopback selalu diterima untuk DCR. Client statis hanya menerima loopback yang tercantum di sini |
| `MCP_S3_OAUTH_DYNAMIC_REGISTRATION` | tidak | `true` | `false` mematikan `/register`; wajib ada client statis |
| `MCP_S3_TRUST_PROXY` | tidak | `0` | Jumlah hop reverse proxy yang dipercaya untuk `X-Forwarded-For` (0-10). Isi `1` di belakang satu proxy (Caddy di `deploy/`) |

Catatan:

- Boolean menerima `true`/`false` (juga `1`/`0`, `yes`/`no`, `on`/`off`), tidak case-sensitive. Nilai lain membuat server gagal start.
- Variabel `S3_*` dan `MCP_S3_*` yang opsional dan diisi string kosong dianggap tidak di-set. Variabel wajib yang kosong dianggap error.
- Tanpa `MCP_S3_TOKEN_KEY` di mode stdio, `next_token` hanya berlaku selama proses server hidup. Isi kunci ini jika ingin token tetap berlaku setelah restart.
- Di mode HTTP, semua masalah konfigurasi (umum dan HTTP) dilaporkan sekaligus.

Membuat secret:

```bash
openssl rand -base64 32   # MCP_S3_TOKEN_KEY: tepat 32 byte acak, base64
openssl rand -base64 18   # MCP_S3_AUTH_PASSWORD: 24 karakter acak
openssl rand -hex 32      # MCP_S3_OAUTH_CLIENT_SECRET: 64 karakter hex
```

Buat `MCP_S3_TOKEN_KEY` sekali lalu simpan di secret manager atau file env yang tidak di-commit. Jangan membuatnya ulang setiap start: kunci baru membatalkan semua `next_token`, client OAuth terdaftar, dan token OAuth. Untuk password, pakai nilai acak panjang, bukan kata yang mudah ditebak; halaman login bisa dijangkau siapa pun yang tahu URL server.

Aturan `S3_ROOT_PREFIX`: tidak boleh kosong, wajib diakhiri `/`, tidak boleh diawali `/`, tidak boleh berisi `//`, segmen `.` atau `..`, backslash, atau karakter kontrol, dan harus lebih pendek dari 1024 byte. Contoh valid: `claude-workspace/`, `teams/data/claude/`.

Konfigurasi yang tidak valid membuat proses keluar dengan kode 1 dan pesan di stderr, misalnya:

```text
[mcp-s3] Invalid configuration:
  - S3_ROOT_PREFIX must end with '/' (e.g. claude-workspace/)
```

## Connect ke Claude Code

Build dulu (`npm run build`), lalu daftarkan server. Pakai path absolut ke `dist/index.js`.

```bash
claude mcp add s3 --scope project \
  -e S3_BUCKET=my-bucket \
  -e S3_ROOT_PREFIX=claude-workspace/ \
  -e AWS_REGION=ap-southeast-1 \
  -e AWS_PROFILE=mcp-s3 \
  -- node /path/to/mcp-s3/dist/index.js
```

Tulis nama server (`s3`) sebelum `-e`. Opsi `-e` menerima banyak nilai sekaligus, jadi nama yang ditulis setelahnya akan dibaca sebagai env dan perintah gagal dengan `Invalid environment variable format`.

`--scope project` menulis `.mcp.json` di direktori saat ini (bisa di-commit dan dipakai bersama tim). Tanpa `--scope`, server hanya terdaftar untuk kamu di proyek ini (`local`); `--scope user` mendaftarkannya untuk semua proyekmu.

Alternatifnya, tulis `.mcp.json` di root proyek secara langsung:

```json
{
  "mcpServers": {
    "s3": {
      "type": "stdio",
      "command": "node",
      "args": ["/path/to/mcp-s3/dist/index.js"],
      "env": {
        "S3_BUCKET": "my-bucket",
        "S3_ROOT_PREFIX": "claude-workspace/",
        "AWS_REGION": "ap-southeast-1",
        "AWS_PROFILE": "mcp-s3"
      }
    }
  }
}
```

Jangan menaruh access key di `.mcp.json` yang di-commit. Pakai `AWS_PROFILE`, atau ekspansi env Claude Code seperti `"AWS_PROFILE": "${AWS_PROFILE:-mcp-s3}"`. Claude Code meminta persetujuan sebelum memakai server dari `.mcp.json` proyek untuk pertama kali.

Cek koneksi dengan `claude mcp list`, atau `/mcp` di dalam sesi Claude Code.

Untuk server remote (mode HTTP), lihat [Connect Claude Code lewat HTTP](#connect-claude-code-lewat-http).

Opsional: izinkan tool read tanpa prompt konfirmasi di `.claude/settings.json` proyek:

```json
{
  "permissions": {
    "allow": [
      "mcp__s3__list_objects",
      "mcp__s3__get_object_info",
      "mcp__s3__read_object",
      "mcp__s3__search_objects"
    ]
  }
}
```

Jika nama server bukan `s3`, sesuaikan bagian tengah nama tool (`mcp__<nama-server>__<tool>`).

## Connect ke Claude Desktop

Edit `claude_desktop_config.json`:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "s3": {
      "command": "/Users/you/.nvm/versions/node/v24.x.y/bin/node",
      "args": ["/Users/you/mcp-s3/dist/index.js"],
      "env": {
        "S3_BUCKET": "my-bucket",
        "S3_ROOT_PREFIX": "claude-workspace/",
        "AWS_REGION": "ap-southeast-1",
        "AWS_PROFILE": "mcp-s3"
      }
    }
  }
}
```

Catatan path `node` untuk nvm: Claude Desktop tidak menjalankan shell init kamu, jadi `nvm` tidak aktif dan `"command": "node"` bisa tidak ditemukan atau menunjuk ke Node versi lain. Tulis path absolut ke binary Node 24. Cari dengan `nvm which 24` (atau `which node` setelah `nvm use 24`; di Windows `where node`). Perbarui path ini setiap kali kamu pindah versi Node lewat nvm. Path ke `dist/index.js` juga harus absolut.

Tutup Claude Desktop sepenuhnya lalu buka lagi setelah mengedit file ini. Jika server gagal start, log MCP Claude Desktop ada di `~/Library/Logs/Claude/` (macOS) atau `%APPDATA%\Claude\logs\` (Windows); pesan dari server diawali `[mcp-s3]`.

## Testing dengan MCP Inspector

[MCP Inspector](https://github.com/modelcontextprotocol/inspector) memanggil tool secara manual tanpa Claude. Build dulu, lalu:

```bash
npm run build
npm run inspect
```

`npm run inspect` menjalankan `npx @modelcontextprotocol/inspector node dist/index.js` dan membuka UI web. Isi env (`S3_BUCKET`, `S3_ROOT_PREFIX`, `AWS_REGION`, `AWS_PROFILE`) di bagian "Environment Variables" pada UI sebelum connect. Jangan mengandalkan env dari shell; MCP client umumnya hanya meneruskan sebagian kecil env (seperti `PATH` dan `HOME`) ke server stdio.

Atau berikan env lewat flag `-e`:

```bash
npx @modelcontextprotocol/inspector \
  -e S3_BUCKET=my-bucket \
  -e S3_ROOT_PREFIX=claude-workspace/ \
  -e AWS_REGION=ap-southeast-1 \
  -e AWS_PROFILE=mcp-s3 \
  node dist/index.js
```

Untuk cek cepat tanpa UI, pakai mode CLI Inspector:

```bash
npx @modelcontextprotocol/inspector --cli \
  -e S3_BUCKET=my-bucket -e S3_ROOT_PREFIX=claude-workspace/ \
  -e AWS_REGION=ap-southeast-1 -e AWS_PROFILE=mcp-s3 \
  --method tools/call --tool-name list_objects --tool-arg recursive=true \
  -- node dist/index.js
```

Hal yang perlu dicoba: `tools/list` hanya berisi empat tool read; `read_object` dengan `path` `../rahasia.txt` menghasilkan `PathOutsideRoot`; respons tidak pernah memuat nama bucket atau root prefix.

Catatan:

- Inspector versi terbaru punya syarat versi Node sendiri, yang bisa lebih ketat dari proyek ini. Jika `npx` menolak versi Node kamu, perbarui Node 24 ke rilis patch terbaru.
- Inspector v2 menyimpan nilai env server stdio sebagai secret di keychain OS, atau di `~/.mcp-inspector/secrets.json` **tanpa enkripsi** jika keychain tidak tersedia (umum di Linux tanpa Secret Service). Pakai `AWS_PROFILE`, jangan access key mentah, saat testing dengan Inspector.

## Mode HTTP (remote)

Dengan `MCP_S3_TRANSPORT=http`, server memakai transport Streamable HTTP dan menjadi authorization server OAuth 2.1 sendiri. Tool dan path jail sama persis dengan mode stdio.

Ringkasan:

- **Selalu read-only.** `MCP_S3_READ_ONLY=false` atau `MCP_S3_ALLOW_DELETE=true` membuat server gagal start.
- **`/mcp` wajib access token.** Request tanpa token valid dijawab `401` dengan header `WWW-Authenticate` yang menunjuk ke metadata OAuth, jadi client bisa memulai login sendiri. Body JSON baru dibaca setelah token valid (maksimal 100 KB). JSON rusak dari client yang sudah login dijawab `400` dengan error JSON-RPC `-32700`.
- **Satu akun admin.** Halaman login memeriksa `MCP_S3_AUTH_USERNAME` dan `MCP_S3_AUTH_PASSWORD` (perbandingan constant-time). Tidak ada IdP eksternal dan tidak ada database user.
- **Tanpa database.** Client terdaftar, authorization code, dan token adalah data terenkripsi (AES-256-GCM, kunci diturunkan dari `MCP_S3_TOKEN_KEY` dan terpisah per jenis token). Token `next_token`, access token, dan refresh token tidak bisa dipakai saling menggantikan.
- **Satu S3 client bersama.** Semua request HTTP memakai satu `S3Client`.
- **Bind default `127.0.0.1`.** Header `Host` dibatasi ke hostname `MCP_S3_PUBLIC_URL` dan nama loopback (perlindungan DNS rebinding). Jika bind bukan loopback dan `MCP_S3_PUBLIC_URL` masih `http`, server mencatat `WARN`: password dan token lewat jaringan tanpa TLS. Ini wajar hanya di container yang port-nya di-publish ke `127.0.0.1`, atau di belakang reverse proxy HTTPS (lalu isi `MCP_S3_PUBLIC_URL` dengan `https`).

Endpoint:

| Path | Metode | Auth | Fungsi |
| --- | --- | --- | --- |
| `/mcp` | `POST` | Bearer token | MCP (stateless, respons JSON) |
| `/mcp` | `GET`, `DELETE` | Bearer token | `405`: tidak ada sesi dan stream SSE |
| `/.well-known/oauth-protected-resource/mcp`, `/.well-known/oauth-protected-resource` | `GET` | - | Protected resource metadata (RFC 9728) |
| `/.well-known/oauth-authorization-server` | `GET` | - | Authorization server metadata (RFC 8414) |
| `/authorize` | `GET`, `POST` | - | Mulai otorisasi, menampilkan halaman login |
| `/login` | `POST` | form + CSRF | Memeriksa username dan password admin |
| `/token` | `POST` | client | Menukar authorization code atau refresh token |
| `/register` | `POST` | - | Dynamic client registration (jika `MCP_S3_OAUTH_DYNAMIC_REGISTRATION=true`) |
| `/revoke` | `POST` | client | Mencabut access atau refresh token |
| `/healthz` | `GET` | - | Liveness tanpa detail (tidak diteruskan oleh Caddy di `deploy/`) |

### Menjalankan secara lokal

Build dulu (`npm run build`). Buat file env yang tidak di-commit, misalnya `.env.http`, berisi variabel umum ditambah:

```bash
MCP_S3_TRANSPORT=http
MCP_S3_TOKEN_KEY=<hasil openssl rand -base64 32>
MCP_S3_AUTH_USERNAME=admin
MCP_S3_AUTH_PASSWORD=<hasil openssl rand -base64 18>
# Opsional, default 127.0.0.1:3000 dan http://localhost:3000
# MCP_S3_HTTP_PORT=3000
```

Jalankan:

```bash
node --env-file=.env.http dist/index.js
```

stderr menampilkan baris `server started` dengan `listen` dan `publicUrl`. Cek cepat:

```bash
curl -i http://localhost:3000/mcp
# HTTP/1.1 401 Unauthorized
# WWW-Authenticate: Bearer error="invalid_token", ..., scope="read",
#   resource_metadata="http://localhost:3000/.well-known/oauth-protected-resource/mcp"

curl http://localhost:3000/.well-known/oauth-authorization-server
```

Pakai host yang sama dengan `MCP_S3_PUBLIC_URL` di semua client. Dengan default, itu `http://localhost:3000`; `http://127.0.0.1:3000` dianggap server lain dan login akan gagal.

### Alur login OAuth

1. Client memanggil `/mcp` tanpa token dan mendapat `401`.
2. Client membaca metadata OAuth, lalu mendaftar lewat `/register` (atau memakai client statis).
3. Client membuka browser ke `/authorize` dengan PKCE (`S256`).
4. Halaman login menampilkan nama client dan origin tujuan redirect. Lanjutkan hanya jika kamu sendiri yang memulai koneksi itu, lalu isi username dan password admin.
5. Server redirect ke client dengan authorization code. Client menukarnya di `/token` dengan access token (scope `read`) dan refresh token.

Aturan request `/authorize`:

- Satu-satunya scope adalah `read`. Scope lain dijawab redirect `error=invalid_scope`.
- `resource` (RFC 8707) harus URL `/mcp` server ini, tanpa fragment (`#...`). Selain itu dijawab `error=invalid_target`.
- `state` maksimal 2048 byte UTF-8 dan tidak boleh berisi karakter kontrol. Selain itu dijawab `error=invalid_request`.
- `grant_types` client DCR ditegakkan. Client tanpa `authorization_code` mendapat `error=unauthorized_client`. Client tanpa `refresh_token` tidak diberi refresh token, dan refresh-nya ditolak dengan `unauthorized_client`.

Perlindungan halaman login:

- Semua nilai yang ditampilkan di-escape. Password tidak pernah dikirim balik ke halaman atau ditulis ke log. Username yang dicoba juga tidak di-log.
- Nama client dari DCR dibersihkan dari karakter format Unicode yang tak terlihat (misalnya override arah teks) sebelum ditampilkan.
- CSRF: cookie nonce `HttpOnly; SameSite=Lax` yang terikat ke form lewat HMAC. Di https, cookie bernama `__Host-mcp_s3_login_csrf` dengan `Secure` dan `Path=/`. Setiap kali halaman login dibuka, cookie dikirim ulang dengan umur 10 menit yang baru.
- Header `Origin` pada `POST /login` harus sama dengan origin `MCP_S3_PUBLIC_URL`. `Origin: null` hanya diterima jika browser juga mengirim `Sec-Fetch-Site: same-origin`. `Sec-Fetch-Site: cross-site` dan `same-site` selalu ditolak.
- Header: Content-Security-Policy ketat, `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Cache-Control: no-store`.
- Referrer: halaman login memakai `Referrer-Policy: same-origin` (header dan tag `<meta>`), supaya Chrome mengirim `Origin` asli saat form dikirim. Dengan `no-referrer`, Chrome mengirim `Origin: null`. Redirect `303` ke client memakai `Referrer-Policy: no-referrer`, dan referrer `same-origin` memang tidak dikirim lintas origin. Jadi callback client tidak menerima header `Referer` berisi URL server.
- Rate limit login (in-memory): 5 percobaan gagal per IP per 15 menit, dan 100 percobaan gagal dari semua IP per 15 menit. Setelah batas tercapai, server menjawab `429` dengan `Retry-After`.
- Rate limit client secret (in-memory): 10 client secret salah per IP per 15 menit di `/token` dan `/revoke`. Setelah itu, setiap request ke kedua endpoint itu yang membawa secret dari IP tersebut dijawab `429` dengan `Retry-After` dan `{"error":"too_many_requests"}`, termasuk request dengan secret yang benar, sampai jendela berakhir. Public client (tanpa secret) tidak terkena batas ini.
- IPv6 dihitung per prefix `/64`, karena satu host biasanya menguasai satu `/64` penuh. Alamat IPv4-mapped (`::ffff:192.0.2.1`) dihitung sebagai alamat IPv4-nya.
- Rate limit bawaan MCP SDK di `/authorize`, `/token`, `/register`, dan `/revoke` hanya menghitung request yang sampai ke handler SDK. Tebakan client secret ditangani rate limit server di atas.

### Connect Claude Code lewat HTTP

```bash
claude mcp add --transport http s3 http://localhost:3000/mcp
```

Untuk server remote, ganti URL dengan `https://<domain>/mcp`. Opsi `--scope` sama seperti mode stdio. Setelah itu, jalankan `/mcp` di dalam sesi Claude Code, pilih server `s3`, lalu autentikasi. Browser membuka halaman login. Claude Code mendaftar sendiri lewat dynamic client registration dan memakai redirect loopback `http://localhost:<port>/callback` dengan port ephemeral. Server selalu menerima redirect loopback untuk client DCR, jadi tidak perlu konfigurasi tambahan.

Tidak ada credential AWS di konfigurasi Claude Code. Credential hanya ada di server.

### Connect MCP Inspector lewat HTTP

```bash
npx @modelcontextprotocol/inspector
```

Di UI, pilih transport Streamable HTTP, isi URL `http://localhost:3000/mcp`, lalu connect. Inspector memulai alur OAuth saat mendapat `401`, mendaftar lewat DCR dengan redirect loopback-nya sendiri, lalu membuka halaman login. Jika login tidak mulai otomatis, jalankan alur OAuth dari pengaturan autentikasi di UI Inspector. Endpoint OAuth dan `/mcp` mengirim header CORS, jadi koneksi langsung dari browser juga bisa.

Hal yang perlu dicoba sama dengan mode stdio. Tambahkan juga: `tools/list` tanpa login harus gagal dengan `401`.

### Docker

[`Dockerfile`](Dockerfile) membangun image multi-stage untuk mode HTTP. Image berjalan sebagai user non-root `node`, hanya berisi dependency produksi dan `dist/`, dan punya `HEALTHCHECK` ke `/healthz`. Default di image: `MCP_S3_TRANSPORT=http`, `MCP_S3_HTTP_HOST=0.0.0.0`, `MCP_S3_HTTP_PORT=3000`.

```bash
docker build -t mcp-s3 .
docker run --rm -p 127.0.0.1:3000:3000 \
  --env-file mcp-s3.env \
  -e MCP_S3_PUBLIC_URL=http://localhost:3000 \
  --read-only --cap-drop ALL \
  mcp-s3
```

`mcp-s3.env` berisi variabel umum, `MCP_S3_TOKEN_KEY`, akun admin, dan access key IAM remote (lihat [IAM terpisah untuk server remote](#iam-terpisah-untuk-server-remote)). Karena server di container bind ke `0.0.0.0`, `MCP_S3_PUBLIC_URL` wajib diisi. Publish port hanya ke `127.0.0.1` (`-p 127.0.0.1:3000:3000`), jangan `-p 3000:3000`: tanpa TLS, password dan token bisa disadap dari jaringan. Kombinasi bind `0.0.0.0` dan URL `http` ini memicu `WARN` di log; itu wajar selama port hanya di-publish ke `127.0.0.1`. `AWS_PROFILE` tidak berguna di container kecuali `~/.aws` di-mount; pakai access key atau instance role. Nilai di file `--env-file` Docker tidak boleh diberi tanda kutip.

### Deploy di balik HTTPS (`deploy/`)

[`deploy/`](deploy/) berisi contoh Docker Compose: mcp-s3 di belakang [Caddy](https://caddyserver.com/), yang mengurus sertifikat Let's Encrypt dan redirect http ke https secara otomatis.

```bash
cp deploy/mcp-s3.env.example deploy/mcp-s3.env   # isi; file ini di-ignore git
MCP_S3_DOMAIN=mcp.example.com docker compose -f deploy/compose.yml up -d --build
```

Syarat:

- Record DNS A/AAAA untuk `MCP_S3_DOMAIN` menunjuk ke host.
- Port 80 (ACME HTTP challenge) dan 443 terbuka dari internet.

Isi contoh:

- Hanya Caddy yang mem-publish port. Container mcp-s3 hanya bisa dijangkau Caddy lewat network internal, berjalan read-only, tanpa capability, dengan `no-new-privileges`.
- `compose.yml` mengisi `MCP_S3_PUBLIC_URL=https://${MCP_S3_DOMAIN}`, `MCP_S3_HTTP_HOST=0.0.0.0`, dan `MCP_S3_TRUST_PROXY=1`.
- `Caddyfile` hanya meneruskan path yang dilayani server (`/mcp`, endpoint OAuth, dan metadata `/.well-known/...`), mengirim HSTS, dan membuang header request `Authorization` dan `Cookie`, header respons `Location` dan `Set-Cookie`, serta query `code`, `state`, dan `code_challenge` dari access log. `Location` dibuang karena redirect setelah login berisi authorization code.

`MCP_S3_TRUST_PROXY` menentukan berapa entri `X-Forwarded-For` yang dipercaya. Isi dengan jumlah proxy di depan server (`1` untuk satu Caddy). Jangan diisi jika server dijangkau langsung tanpa proxy, karena client bisa memalsukan header itu. Jika diisi `0` padahal ada proxy, semua client terlihat dengan IP proxy, sehingga rate limit login dan client secret per IP berlaku untuk semua orang sekaligus.

URL MCP setelah deploy: `https://<MCP_S3_DOMAIN>/mcp`.

### Custom connector claude.ai

Status: belum dites nyata karena domain HTTPS belum ada.

Syarat:

- Claude menghubungi server dari cloud Anthropic, bukan dari komputermu. Server harus bisa dijangkau publik lewat **HTTPS di port 443**; port lain tidak didukung.
- Izinkan trafik masuk dari rentang egress Anthropic `160.79.104.0/21`. Firewall atau WAF (misalnya proteksi bot) bisa memblokir rentang ini sehingga connector gagal tanpa pesan yang jelas.
- Redirect URI claude.ai, `https://claude.ai/api/mcp/auth_callback`, harus diterima server. Nilai ini adalah default `MCP_S3_OAUTH_REDIRECT_URIS` dan bisa diganti lewat variabel itu.

Langkah: tambahkan custom connector di pengaturan connector claude.ai dengan URL `https://<domain>/mcp`, lalu pilih salah satu cara client:

1. **Register automatically.** Biarkan Client ID dan Secret kosong. claude.ai mendaftar lewat `/register` (`MCP_S3_OAUTH_DYNAMIC_REGISTRATION=true`, default).
2. **Use your own OAuth client.** Isi `MCP_S3_OAUTH_CLIENT_ID` dan `MCP_S3_OAUTH_CLIENT_SECRET` di server, lalu masukkan nilai yang sama di form connector. **Isi Client ID dan Secret keduanya.** Jika secret dikosongkan, Claude memakai Client ID sebagai public client, sedangkan client statis server ini selalu confidential, sehingga penukaran token gagal dengan `invalid_client`. Jika hanya cara ini yang dipakai, matikan DCR dengan `MCP_S3_OAUTH_DYNAMIC_REGISTRATION=false`.

Saat connect, claude.ai membuka halaman login server. Isi akun admin. Setelah itu claude.ai memakai refresh token sampai sesi habis (lihat bagian berikut).

### Client OAuth dan redirect URI

| Cara | Redirect URI yang diterima | Autentikasi di `/token` |
| --- | --- | --- |
| Dynamic client registration | Entri `MCP_S3_OAUTH_REDIRECT_URIS` (persis), atau URI loopback `http(s)://localhost`, `127.0.0.1`, `[::1]` dengan port dan path apa pun | Public client (`none`), atau secret yang dikembalikan `/register` |
| Client statis dari env | Hanya entri `MCP_S3_OAUTH_REDIRECT_URIS`. Loopback hanya jika tercantum di sana (port bebas, host dan path harus sama) | `client_secret_post`, atau HTTP Basic (`client_secret_basic`) |

Catatan:

- Registrasi dengan redirect URI di luar daftar ditolak dengan `invalid_redirect_uri`. Ini mencegah pihak lain mendaftarkan client yang mengirim code ke domain mereka.
- Maksimal 5 redirect URI per client DCR, masing-masing maksimal 512 karakter.
- Secret client DCR tidak kedaluwarsa. Satu-satunya cara mencabut semua client DCR adalah mengganti `MCP_S3_TOKEN_KEY`.
- Secret client dibandingkan secara constant-time.
- Metadata server hanya mengiklankan `client_secret_post` dan `none` (ditentukan MCP SDK), tetapi HTTP Basic juga diterima.
- Saat `/authorize`, redirect URI dicocokkan dengan URI yang terdaftar di client. Untuk loopback, hanya port yang boleh beda (RFC 8252). Scheme, host, path, dan query harus sama. `localhost`, `127.0.0.1`, dan `[::1]` tidak dianggap sama: client yang terdaftar dengan `http://localhost/callback` tidak bisa memakai `http://127.0.0.1:<port>/callback`.
- Client statis tidak otomatis menerima loopback. Untuk memakainya dengan client lokal, tambahkan redirect loopback-nya ke `MCP_S3_OAUTH_REDIRECT_URIS` dengan host yang dipakai client itu. Contoh untuk Claude Code: `http://localhost/callback`. Ingat variabel ini mengganti default, jadi tulis ulang callback claude.ai jika masih dipakai.

### Token, restart, dan pencabutan akses

| Artefak | Masa berlaku |
| --- | --- |
| Form login | 10 menit |
| Authorization code | 2 menit, sekali pakai |
| Access token | 1 jam, scope `read` |
| Refresh token | 7 hari sliding: dirotasi setiap dipakai, dan token baru berlaku 7 hari lagi. Maksimal 90 hari sejak login |
| `client_id` hasil DCR | Tidak kedaluwarsa |

Tetap berlaku setelah restart atau di instance lain (selama `MCP_S3_TOKEN_KEY` dan akun admin sama): client DCR, access token, refresh token, dan `next_token`.

Hilang saat restart (disimpan di memori):

- Daftar authorization code yang sudah ditukar. Code yang belum lewat 2 menit bisa ditukar sekali lagi, tetapi tetap butuh PKCE verifier dari client aslinya.
- Daftar token yang dicabut, termasuk refresh token lama hasil rotasi. Token itu berlaku lagi sampai kedaluwarsa: access token paling lama 1 jam, refresh token paling lama 7 hari.
- Penghitung rate limit login dan client secret.

**Risiko refresh token lama.** Refresh token yang sudah dirotasi atau dicabut lewat `/revoke` hanya ditolak selama server ingat ID-nya. Ingatan itu hilang saat restart. Ingatan itu juga dibatasi 10.000 ID: jika penuh, ID tertua dibuang lebih dulu. Setelah itu, refresh token lama bisa dipakai lagi sampai kedaluwarsa, paling lama 7 hari sejak diterbitkan. Server belum mendeteksi pemakaian ulang refresh token. Jika refresh token mungkin bocor, ganti `MCP_S3_AUTH_PASSWORD` (semua token dan login lama tidak berlaku) atau `MCP_S3_TOKEN_KEY` (semua token dan client DCR tidak berlaku). Jangan andalkan `/revoke` saja.

Mencabut akses:

| Tindakan | Akibat |
| --- | --- |
| `POST /revoke` | Mencabut satu token sampai restart berikutnya atau sampai ID-nya tergeser dari daftar 10.000 ID. Setelah itu refresh token berlaku lagi sampai kedaluwarsa (paling lama 7 hari) |
| Ganti `MCP_S3_AUTH_USERNAME` atau `MCP_S3_AUTH_PASSWORD` | Semua code, access token, dan refresh token tidak berlaku; semua client harus login ulang. Client DCR tetap terdaftar |
| Ganti `MCP_S3_TOKEN_KEY` | Semua client DCR, token OAuth, dan `next_token` tidak berlaku |
| Ganti `MCP_S3_PUBLIC_URL` | Token lama ditolak karena terikat ke URL resource lama |

### Batasan mode HTTP

- **Harus di root hostname.** `MCP_S3_PUBLIC_URL` tidak boleh punya path (misalnya `https://example.com/s3`), karena MCP SDK memasang endpoint OAuth di path absolut (`/authorize`, `/token`, ...). Pakai subdomain sendiri, misalnya `https://mcp.example.com`.
- **Transport stateless.** Tidak ada sesi MCP. Setiap `POST /mcp` berdiri sendiri, `GET` dan `DELETE` dijawab `405`, dan server tidak bisa mengirim notifikasi ke client. Untuk tool read ini tidak dibutuhkan, dan restart tidak memutus client.
- **Akun admin bersama.** Konsekuensi yang diterima: audit log tidak bisa membedakan user, mencabut akses satu orang berarti mengganti password untuk semua, dan password yang bocor membuka akses untuk siapa pun sampai diganti.
- **Rate limit global.** Setelah 100 percobaan gagal dalam 15 menit dari semua IP, login baru ditolak untuk semua orang sampai jendela itu berakhir. Penyerang bisa memakai ini untuk menunda login admin. Token yang sudah ada tetap berfungsi.
- **Rate limit client secret per IP.** Client confidential yang berbagi IP (atau prefix IPv6 `/64`) dengan penyerang ikut mendapat `429` di `/token` dan `/revoke` selama 15 menit. Batas ini tidak punya batas global, jadi penyerang dengan banyak IP tetap bisa menebak. Pakai secret acak minimal 32 karakter.
- **Refresh token lama bisa berlaku lagi** setelah restart atau saat daftar pencabutan penuh, paling lama 7 hari. Lihat [Token, restart, dan pencabutan akses](#token-restart-dan-pencabutan-akses).
- **Siapa pun bisa mendaftar client lewat DCR** (dengan redirect URI yang diizinkan). Pendaftaran tidak memberi akses tanpa password admin. Matikan dengan `MCP_S3_OAUTH_DYNAMIC_REGISTRATION=false` jika tidak dibutuhkan.
- **State in-memory** hilang saat restart, seperti dijelaskan di atas.
- Halaman login berbahasa Inggris.

## Audit log

Setiap pemanggilan tool menghasilkan tepat satu baris JSON di stderr, di mode stdio maupun HTTP. Baris yang sama bisa [disimpan juga ke PostgreSQL](#menyimpan-ke-postgresql). Audit log selalu aktif dan tidak dipengaruhi `MCP_S3_LOG_LEVEL`. Di Docker, baris ini muncul di `docker logs`.

```json
{"type":"audit","time":"2026-11-26T10:00:00.000Z","tool":"read_object","path":"reports/q1.csv","result":"ok","bytes":2048,"duration_ms":12}
{"type":"audit","time":"2026-11-26T10:00:01.000Z","tool":"read_object","path":"../secret.txt","result":"error","code":"PathOutsideRoot","duration_ms":0}
```

| Field | Isi |
| --- | --- |
| `time` | Waktu mulai pemanggilan (ISO 8601, UTC) |
| `tool` | Nama tool |
| `path` (juga `source`, `destination` untuk tool dua path nanti) | Path relatif persis seperti dikirim client, termasuk path yang ditolak |
| `result` | `ok` atau `error` |
| `code` | Kode error generik (`NotFound`, `PathOutsideRoot`, ...) jika `error` |
| `bytes` | Byte yang dibaca dari storage (hanya `read_object`) |
| `duration_ms` | Durasi pemanggilan |

Audit log tidak pernah berisi nama bucket, root prefix, key S3 lengkap, isi file, credential, token, atau password. Karena `path` adalah input client apa adanya, teks yang diketik client (misalnya `../nama-lain/x`) ikut tercatat. Pemanggilan yang ditolak validasi schema MCP SDK sebelum handler berjalan (misalnya parameter bertipe salah) dan nama tool yang tidak dikenal tidak dicatat. MCP SDK menangani kedua kasus itu di dalam `McpServer` dan langsung mengembalikan hasil error ke client tanpa hook yang bisa dipakai server. Pemanggilan itu tidak pernah menyentuh S3.

Di mode HTTP, login yang gagal, berhasil, dan terkena rate limit dicatat terpisah sebagai log biasa (`login failed`, `login succeeded`, `login rate limited`) dengan IP client. Client secret yang salah dan request yang terkena rate limit client secret juga dicatat (`client authentication failed`, `client authentication rate limited`) dengan IP client, tanpa client ID atau secret.

### Menyimpan ke PostgreSQL

Isi `MCP_S3_AUDIT_DATABASE_URL`, misalnya `postgresql://mcp_s3:<password>@127.0.0.1:5432/mcp_s3`. Untuk database lewat jaringan, tambahkan `?sslmode=verify-full`. Audit log tetap ditulis ke stderr.

Tabel `mcp_s3_audit` (kolom `id`, `time`, `tool`, `path`, `source`, `destination`, `result`, `code`, `bytes`, `duration_ms`) dan index pada `time` dibuat otomatis jika belum ada. Jika tabel sudah ada, user database cukup punya izin `INSERT`.

```sql
-- Akses yang gagal dalam 24 jam terakhir
SELECT time, tool, path, code FROM mcp_s3_audit
WHERE result = 'error' AND time > now() - interval '1 day'
ORDER BY time DESC;
```

Penyimpanan ke database bersifat best effort:

- Tool tidak menunggu database. Server tetap start dan tool tetap jalan walau database mati.
- Baris yang gagal disimpan **tidak dicoba ulang**. Salinannya hanya ada di stderr, dan server menulis `WARN` paling sering sekali per menit.
- Paling banyak 1000 baris boleh menunggu database; selebihnya tidak disimpan.
- Saat shutdown, server menunggu baris yang tertunda paling lama 3 detik.
- Karakter NUL di `path` disimpan sebagai teks `\u0000`.
- Server tidak menghapus baris lama. Retensi diatur di sisi database.

Di `deploy/compose.yml` ada service `postgres` opsional. Set `MCP_S3_AUDIT_DB_PASSWORD` di shell, isi `MCP_S3_AUDIT_DATABASE_URL` di `deploy/mcp-s3.env` dengan password yang sama, lalu jalankan `docker compose -f deploy/compose.yml --profile audit-db up -d --build`.

## Menjalankan test

| Perintah | Isi | Butuh |
| --- | --- | --- |
| `npm test` | Unit test (`test/unit`): path jail, config, handler tool dengan S3 di-mock | Tidak butuh Docker atau akun AWS |
| `npm run test:int` | `npm run build`, `docker compose up -d --wait`, lalu integration test (`test/integration`) ke MinIO dan PostgreSQL, termasuk uji policy least-privilege | Docker |
| `npm run test:e2e` | `npm run build`, MinIO, lalu e2e (`test/e2e`): menjalankan `dist/index.js` lewat MCP client stdio | Docker |
| `npm run test:all` | Ketiganya berurutan | Docker |
| `npm run lint` | ESLint, lalu `tsc --noEmit` untuk `src/` dan `test/` | - |
| `npm run minio:down` | Menghentikan MinIO dan menghapus volume-nya | Docker |

PostgreSQL test listen di `127.0.0.1:19432` (ganti dengan `POSTGRES_PORT`). MinIO dari `docker-compose.yml` hanya listen di `127.0.0.1:19000`, datanya di tmpfs (kosong setiap start), dan setiap file test membuat bucket unik sendiri. Test tidak pernah menyentuh AWS. Variabel `MINIO_PORT`, `MINIO_ENDPOINT`, `MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD`, dan `MINIO_IMAGE` bisa dipakai untuk mengganti port, endpoint, credential admin test, atau image MinIO.

## Daftar tool

Semua tool bersifat read-only. Annotation setiap tool: `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: false`. Semua `path` relatif terhadap root; `""` berarti root. Contoh JSON di bawah diringkas; output asli adalah satu text content berisi JSON dengan indentasi 2 spasi.

| Tool | Parameter | Hasil |
| --- | --- | --- |
| `list_objects` | `path=""`, `recursive=false`, `max_keys` (maks. `MCP_S3_MAX_LIST_KEYS`), `continuation_token` | JSON: `path`, `folders[]`, `files[]` (`path`, `size`, `last_modified`), `next_token` |
| `get_object_info` | `path` (file, bukan root) | JSON: `path`, `size`, `content_type`, `last_modified`, `etag`, `metadata` |
| `read_object` | `path`, `offset=0`, `length` (maks. `MCP_S3_MAX_READ_BYTES`) | Teks UTF-8, gambar sebagai image content, atau pemberitahuan "binary" |
| `search_objects` | `path=""`, `pattern` (glob), `max_results` (maks. `MCP_S3_MAX_LIST_KEYS`) | JSON: `path`, `pattern`, `matches[]`, `truncated`, dan `note` jika terpotong |

### `list_objects`

Tanpa `recursive`, hanya anak langsung yang dikembalikan, dan subfolder muncul di `folders` (diakhiri `/`). Dengan `recursive: true`, semua file di bawah folder dikembalikan. Jika `next_token` tidak `null`, panggil lagi dengan `continuation_token` berisi nilai itu dan `path`/`recursive` yang sama.

```json
{
  "path": "",
  "folders": ["reports/"],
  "files": [
    { "path": "notes.txt", "size": 13, "last_modified": "2026-11-20T08:15:00.000Z" }
  ],
  "next_token": null
}
```

### `get_object_info`

```json
{
  "path": "reports/q1.csv",
  "size": 2048,
  "content_type": "text/csv",
  "last_modified": "2026-11-20T08:15:00.000Z",
  "etag": "\"9b2cf535f27731c974343645a3985328\"",
  "metadata": { "owner": "team-a" }
}
```

### `read_object`

- Teks UTF-8 dikembalikan apa adanya. Jika file lebih besar dari batas baca, server mengembalikan potongan pertama ditambah catatan cara membaca lanjutannya:

  ```text
  [showing bytes 0-1048575 of 5242880; to read more, call read_object with offset=1048576]
  ```

- PNG, JPEG, GIF, dan WebP dideteksi dari magic bytes (bukan dari `Content-Type` atau ekstensi) dan dikembalikan sebagai image content jika seluruh file muat sekaligus: tidak lebih dari `MCP_S3_MAX_READ_BYTES` dan tidak lebih dari 3.932.160 byte (5 MB setelah base64, batas gambar di API Claude). Dengan default 1 MiB, gambar yang lebih besar hanya mendapat pemberitahuan; naikkan `MCP_S3_MAX_READ_BYTES` jika perlu.
- File lain yang bukan UTF-8 valid hanya mendapat pemberitahuan singkat, misalnya `[binary file data.zip (application/zip, 52311 bytes): content cannot be shown as text]`.
- File kosong menghasilkan `[empty file: 0 bytes]`.

### `search_objects`

Sintaks glob: `*` (dalam satu level folder), `?` (satu karakter), `**` (sejumlah level folder), `[abc]`, `[a-z]`, `[!abc]`, `{a,b}`, dan `\` untuk escape. Pola tanpa `/` dicocokkan dengan nama file di subfolder mana pun; pola dengan `/` dicocokkan dengan path relatif terhadap `path`. Pencocokan case-sensitive. Extglob seperti `*(...)` dan `!` di awal pola tidak didukung, dan pola maksimal 256 karakter. Satu panggilan memeriksa sekitar 10.000 object. `truncated` bernilai `true` jika batas scan itu tercapai atau jika ada lebih banyak kecocokan dari `max_results`; `note` lalu menyarankan mempersempit pola atau `path`.

```json
{
  "path": "",
  "pattern": "*.csv",
  "matches": ["reports/q1.csv", "reports/2026/q2.csv"],
  "truncated": false
}
```

### Error

Error dikembalikan sebagai hasil tool dengan `isError: true` dan teks `<Kode>: <pesan>`, misalnya:

```text
PathOutsideRoot: path is not allowed (relative segment)
NotFound: object not found
AccessDenied: access denied
```

Kode yang mungkin: `PathOutsideRoot`, `InvalidRequest`, `NotFound`, `AccessDenied`, `InvalidRange`, `Conflict`, `Throttled`, `StorageUnavailable`, `Cancelled`, `InternalError`.

## Peringatan keamanan

- **Jangan commit credential.** `.env` dan `.env.*` (kecuali `.env.example`) sudah ada di `.gitignore`. Jangan menaruh access key di `.mcp.json`, `claude_desktop_config.json`, atau file lain di repo; pakai `AWS_PROFILE`.
- **Mode HTTP di internet wajib di balik HTTPS.** OAuth selalu aktif di mode HTTP, tetapi tanpa TLS password admin dan token terkirim sebagai teks biasa. Pakai reverse proxy HTTPS seperti contoh di `deploy/`, dan jangan bind server langsung ke alamat publik.
- **Perlakukan `MCP_S3_TOKEN_KEY`, `MCP_S3_AUTH_PASSWORD`, dan `MCP_S3_OAUTH_CLIENT_SECRET` sebagai secret.** Jangan di-commit, di-log, atau ditempel di chat. Buat dengan `openssl rand` (lihat [Konfigurasi](#konfigurasi)); jangan memakai ulang nilai dari contoh atau dokumentasi mana pun. Jika bocor, ganti segera:
  - `MCP_S3_TOKEN_KEY`: semua `next_token`, client OAuth terdaftar, dan token OAuth tidak berlaku lagi. Client harus mendaftar dan login ulang.
  - `MCP_S3_AUTH_PASSWORD`: semua token OAuth tidak berlaku lagi. Semua user harus login ulang dengan password baru.
  - `MCP_S3_OAUTH_CLIENT_SECRET`: perbarui juga secret di form connector claude.ai.
- **Server remote memakai IAM user/role sendiri yang read-only.** Lihat [IAM terpisah untuk server remote](#iam-terpisah-untuk-server-remote).
- **Pakai IAM user khusus dengan policy least-privilege.** Path jail di aplikasi bukan satu-satunya pengaman; policy IAM adalah lapis yang tetap berlaku jika aplikasi punya bug.
- **Isi bucket bisa berisi prompt injection.** Claude diberi tahu bahwa isi file adalah data, tetapi tetap hati-hati memberi izin otomatis (`permissions.allow`) jika bucket berisi file dari sumber yang tidak tepercaya.

## Troubleshooting

| Gejala | Kemungkinan penyebab |
| --- | --- |
| Server langsung keluar dengan `Invalid configuration` | Env wajib hilang atau tidak valid; pesan di stderr menyebut variabelnya |
| `StorageUnavailable: storage credentials are not configured` | AWS SDK tidak menemukan credential: `AWS_PROFILE` salah, profile tidak ada di `~/.aws/credentials`, atau env tidak sampai ke proses server |
| `AccessDenied: storage credentials were rejected` | Access key salah atau sudah dihapus |
| `AccessDenied: access denied` untuk path di bawah root | Root prefix di policy IAM tidak sama persis dengan `S3_ROOT_PREFIX`, atau bucket di policy salah. File yang tidak ada juga bisa muncul sebagai `AccessDenied` alih-alih `NotFound`, karena S3 hanya menjawab 404 jika caller punya izin list yang berlaku untuk key tersebut |
| `StorageUnavailable: storage is not available` | Nama bucket salah atau bucket tidak ada |
| `InvalidRequest: continuation_token is invalid or expired, ...` | Token kedaluwarsa (lebih dari satu jam), server sudah restart tanpa `MCP_S3_TOKEN_KEY`, atau `path`/`recursive` berbeda dari panggilan sebelumnya; list ulang tanpa token |
| Claude Desktop tidak menampilkan tool | Path `node` atau `dist/index.js` tidak absolut, Node bukan versi 24, atau Claude Desktop belum di-restart |
| Mode HTTP: `Invalid configuration` menyebut `MCP_S3_AUTH_*`, `MCP_S3_TOKEN_KEY`, atau `MCP_S3_PUBLIC_URL` | Env wajib mode HTTP belum diisi, password kurang dari 12 karakter, atau host bukan loopback tanpa `MCP_S3_PUBLIC_URL` |
| Mode HTTP: `MCP_S3_READ_ONLY=false is not allowed ...` | Mode HTTP selalu read-only; hapus `MCP_S3_READ_ONLY=false` dan `MCP_S3_ALLOW_DELETE=true` |
| Mode HTTP: `403` dengan `Invalid Host` | Header `Host` bukan hostname `MCP_S3_PUBLIC_URL` atau nama loopback. Periksa `MCP_S3_PUBLIC_URL`, dan pastikan reverse proxy meneruskan header `Host` asli |
| Mode HTTP: `401 invalid_token` terus-menerus | Token kedaluwarsa atau dicabut, atau `MCP_S3_TOKEN_KEY`, akun admin, atau `MCP_S3_PUBLIC_URL` berubah sejak login; login ulang. Pastikan URL di client memakai host yang sama dengan `MCP_S3_PUBLIC_URL` |
| Mode HTTP: registrasi client gagal dengan `invalid_redirect_uri` | Redirect URI client bukan loopback dan tidak ada di `MCP_S3_OAUTH_REDIRECT_URIS` |
| Mode HTTP: penukaran token gagal dengan `invalid_client` | Client secret salah, atau secret dikosongkan di form connector padahal client statis butuh secret |
| Mode HTTP: halaman "Sign-in form expired" | Form lebih dari 10 menit, cookie diblokir browser, atau form dikirim dari origin lain. Mulai ulang koneksi dari client |
| Mode HTTP: halaman "Too many attempts" (`429`) | Batas login gagal tercapai (per IP atau global). Tunggu sesuai pesan. Di belakang proxy, periksa `MCP_S3_TRUST_PROXY` |
| Mode HTTP: `/token` atau `/revoke` menjawab `429 too_many_requests` | 10 client secret salah dari IP (atau prefix IPv6 `/64`) yang sama dalam 15 menit. Perbaiki secret, lalu tunggu sesuai `Retry-After`. Di belakang proxy, periksa `MCP_S3_TRUST_PROXY` |
| Mode HTTP: redirect dengan `error=invalid_scope` | Client meminta scope selain `read` |
| Mode HTTP: `/authorize` menjawab `Unregistered redirect_uri` | Redirect URI tidak sama dengan yang terdaftar. Untuk loopback hanya port yang boleh beda; `localhost` dan `127.0.0.1` dianggap berbeda. Client statis butuh redirect loopback-nya di `MCP_S3_OAUTH_REDIRECT_URIS` |
| Mode HTTP: `WARN MCP_S3_HTTP_HOST is not a loopback address ...` | Bind bukan loopback dengan `MCP_S3_PUBLIC_URL` `http`. Wajar di container dengan `-p 127.0.0.1:3000:3000`. Selain itu, pasang reverse proxy HTTPS dan isi `MCP_S3_PUBLIC_URL` dengan `https` |
| claude.ai tidak bisa connect | Server tidak terjangkau lewat HTTPS port 443 dari internet, atau firewall/WAF memblokir egress Anthropic `160.79.104.0/21` |
