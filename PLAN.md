# Plan: MCP Server S3 dengan Akses Terbatas ke Root Prefix

## 1. Tujuan

Membangun MCP (Model Context Protocol) server yang:

1. Bisa dipakai dari Claude (Claude Code dan Claude Desktop lewat stdio, opsional claude.ai lewat HTTP).
2. Memberi Claude akses ke satu bucket S3, **hanya di bawah satu root prefix khusus** (misal `s3://my-bucket/claude-workspace/`).
3. Tidak pernah bisa membaca, menulis, atau melihat key di luar root prefix itu, walau Claude atau isi file meminta.

### Di luar scope (versi awal)

- Multi-bucket atau multi-root.
- UI web sendiri.
- Sinkronisasi folder lokal ke S3.
- Manajemen bucket (create/delete bucket, policy, lifecycle).

## 2. Keputusan Teknis

| Aspek | Pilihan | Alasan |
| --- | --- | --- |
| Bahasa | TypeScript (strict), Node.js 24 LTS | Type safety, SDK MCP resmi paling lengkap |
| Module | ESM (`"type": "module"`) | Wajib untuk import path `@modelcontextprotocol/sdk/...js` |
| MCP SDK | `@modelcontextprotocol/sdk` | `McpServer` + `registerTool()`, transport stdio dan Streamable HTTP |
| S3 client | `@aws-sdk/client-s3` (v3) | Mendukung AWS S3 dan S3-compatible (MinIO, Cloudflare R2, Wasabi) via `endpoint` + `forcePathStyle` |
| Schema & config | `zod` | Satu library untuk input schema tool dan validasi env var |
| Glob | Matcher glob buatan sendiri dengan waktu terbatas (menggantikan `picomatch`, keputusan 2026-11-26) | `picomatch` mengompilasi glob jadi regex yang backtracking, sehingga pola seperti `*?*?*?*?*.zip` bisa membekukan event loop (ReDoS). Sintaks yang didukung: `*`, `?`, `**`, `[...]`, dan `{a,b}` dengan ekspansi terbatas |
| Package manager | `npm` | Default Node, tanpa setup tambahan |
| Build / dev | `tsc` ke `dist/`, `tsx` untuk dev | Output JS biasa, dijalankan dengan `node` |
| Test | `vitest` + `aws-sdk-client-mock`, MinIO (Docker) untuk integrasi | Unit test tanpa akun AWS; integrasi dengan perilaku S3 nyata |
| Lint | `eslint` + `typescript-eslint` | Konsistensi kode |
| Transport | stdio (utama), Streamable HTTP (opsional) | stdio untuk Claude Code/Desktop, HTTP untuk claude.ai connector |

## 3. Model Keamanan: Pembatasan Root Prefix

S3 tidak punya folder sungguhan. Key hanyalah string datar. Pembatasan dilakukan di **dua lapis**, supaya satu lapis gagal tidak langsung membuka seluruh bucket.

### Lapis 1: Path jail di aplikasi

Semua path dari Claude adalah **path relatif terhadap root**. Claude tidak pernah melihat atau mengirim key S3 penuh.

Aturan `resolveKey(userPath)` di `src/paths.ts`:

1. Tolak jika mengandung karakter NUL atau control character.
2. Tolak jika mengandung backslash `\`.
3. Hapus `/` di awal (path absolut dianggap relatif ke root).
4. Pecah per `/`. Tolak jika ada segmen `.` atau `..`.
5. Tolak segmen kosong di tengah (`a//b`).
6. Jangan URL-decode input. `%2e%2e` diperlakukan sebagai teks literal.
7. Gabungkan: `key = ROOT_PREFIX + "/".join(segments)`.
8. Assert `key.startswith(ROOT_PREFIX)`.
9. Tolak jika panjang key > 1024 byte UTF-8 (batas S3).

Kenapa `..` ditolak walau S3 menganggapnya literal: HTTP client, proxy, atau storage S3-compatible bisa menormalisasi `/bucket/root/../secret` menjadi `/bucket/secret`. Lebih aman ditolak.

Aturan `ROOT_PREFIX` (divalidasi saat startup, server gagal start jika tidak valid):

- Wajib diisi, tidak boleh kosong (tidak ada mode "seluruh bucket").
- Wajib diakhiri `/`. Tanpa `/`, prefix `data` juga cocok dengan `data-backup/...`.
- Tidak boleh mengandung `.` atau `..` sebagai segmen.

Aturan output:

- Semua key di respons dikembalikan **relatif** (prefix root dibuang).
- Key hasil list yang tidak diawali `ROOT_PREFIX` dibuang (defensif).
- Pesan error tidak boleh membocorkan nama bucket atau root prefix lengkap.

Operasi dua path (`copy_object`, `move_object`): **source dan destination** sama-sama lewat `resolveKey`.

Kerangka implementasi:

```ts
export class PathOutsideRootError extends Error {}

export function resolveKey(root: string, userPath: string, opts: { dir?: boolean } = {}): string {
  if (/[\u0000-\u001f\u007f]/.test(userPath)) throw new PathOutsideRootError("invalid character");
  if (userPath.includes("\\")) throw new PathOutsideRootError("backslash not allowed");

  const trimmed = userPath.replace(/^\/+/, "");
  const segments = trimmed === "" ? [] : trimmed.split("/");
  const last = segments.length - 1;

  segments.forEach((s, i) => {
    if (s === "." || s === "..") throw new PathOutsideRootError("relative segment");
    // Izinkan "/" di akhir (folder), tolak segmen kosong di tengah
    if (s === "" && i !== last) throw new PathOutsideRootError("empty segment");
  });

  let key = root + segments.filter(Boolean).join("/");
  if (opts.dir && segments.length > 0 && !key.endsWith("/")) key += "/";

  if (!key.startsWith(root)) throw new PathOutsideRootError("outside root");
  if (Buffer.byteLength(key, "utf8") > 1024) throw new PathOutsideRootError("key too long");
  return key;
}

export function toRelative(root: string, key: string): string | null {
  return key.startsWith(root) ? key.slice(root.length) : null; // null = buang
}
```

Catatan SDK v3: parameter `CopySource` di `CopyObjectCommand` berformat `bucket/key` dan harus di-URL-encode per segmen.

### Lapis 2: IAM policy least-privilege

Credential yang dipakai server hanya boleh menyentuh root prefix. Contoh untuk bucket `my-bucket` dan root `claude-workspace/`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListOnlyUnderRoot",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::my-bucket",
      "Condition": {
        "StringLike": {
          "s3:prefix": ["claude-workspace/", "claude-workspace/*"]
        }
      }
    },
    {
      "Sid": "ReadUnderRoot",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/claude-workspace/*"
    },
    {
      "Sid": "WriteUnderRoot",
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::my-bucket/claude-workspace/*"
    }
  ]
}
```

Catatan:

- `HeadObject` memakai izin `s3:GetObject`.
- `CopyObject` butuh `GetObject` di source dan `PutObject` di destination. Keduanya sudah tercakup.
- Untuk mode read-only, hapus statement `WriteUnderRoot`.
- Untuk MinIO/R2, pakai mekanisme policy masing-masing dengan prinsip yang sama.
- Aktifkan **bucket versioning** jika write/delete diizinkan, supaya kesalahan bisa di-rollback.

## 4. Konfigurasi (Environment Variable)

| Variable | Wajib | Default | Keterangan |
| --- | --- | --- | --- |
| `S3_BUCKET` | ya | - | Nama bucket |
| `S3_ROOT_PREFIX` | ya | - | Root prefix, wajib diakhiri `/` |
| `AWS_REGION` | ya | - | Region bucket |
| `AWS_PROFILE` | tidak | - | Profile di `~/.aws/credentials` (disarankan) |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | tidak | - | Alternatif dari profile |
| `S3_ENDPOINT_URL` | tidak | - | Untuk MinIO/R2/dll. |
| `S3_FORCE_PATH_STYLE` | tidak | `false` | Biasanya `true` untuk MinIO |
| `MCP_S3_READ_ONLY` | tidak | `true` | Jika `true`, tool tulis tidak didaftarkan |
| `MCP_S3_ALLOW_DELETE` | tidak | `false` | Jika `false`, `delete_object` dan `move_object` tidak didaftarkan |
| `MCP_S3_MAX_READ_BYTES` | tidak | `1048576` (1 MiB) | Batas byte per baca |
| `MCP_S3_MAX_WRITE_BYTES` | tidak | `5242880` (5 MiB) | Batas byte per tulis |
| `MCP_S3_MAX_LIST_KEYS` | tidak | `200` | Batas item per halaman list |
| `MCP_S3_TRANSPORT` | tidak | `stdio` | `stdio` atau `http` |
| `MCP_S3_LOG_LEVEL` | tidak | `INFO` | Log ke stderr |
| `MCP_S3_TOKEN_KEY` | wajib jika `http` | acak per proses (stdio) | Kunci AES-256-GCM 32 byte (base64) untuk mengenkripsi `next_token`, juga sumber kunci OAuth lewat HKDF. Wajib di mode HTTP supaya token tetap valid setelah restart dan di semua instance. Rahasia: jangan di-commit atau di-log |
| `MCP_S3_HTTP_HOST` | tidak | `127.0.0.1` | Alamat bind mode HTTP |
| `MCP_S3_HTTP_PORT` | tidak | `3000` | Port mode HTTP (1-65535) |
| `MCP_S3_PUBLIC_URL` | wajib jika host bukan loopback | `http://localhost:<port>` | Origin publik sekaligus OAuth issuer. Wajib `https`, kecuali localhost/127.0.0.1. Tanpa path, query, atau fragment |
| `MCP_S3_AUTH_USERNAME` | wajib jika `http` | - | Username admin OAuth |
| `MCP_S3_AUTH_PASSWORD` | wajib jika `http` | - | Password admin OAuth, minimal 12 karakter. Rahasia |
| `MCP_S3_OAUTH_CLIENT_ID` | tidak | - | Client OAuth statis, `[A-Za-z0-9._~-]{1,128}`. Diisi bersama secret |
| `MCP_S3_OAUTH_CLIENT_SECRET` | wajib jika `CLIENT_ID` diisi | - | Minimal 32 karakter ASCII printable. Rahasia |
| `MCP_S3_OAUTH_REDIRECT_URIS` | tidak | `https://claude.ai/api/mcp/auth_callback` | Allowlist exact untuk DCR dan client statis. Mengganti default. URI loopback selalu diterima untuk DCR |
| `MCP_S3_OAUTH_DYNAMIC_REGISTRATION` | tidak | `true` | `false` mematikan `/register`, butuh client statis |
| `MCP_S3_TRUST_PROXY` | tidak | `0` | Jumlah hop proxy yang dipercaya (0-10), untuk `req.ip` dan rate limit login |

Default aman: read-only, tanpa delete. Fitur tulis harus diaktifkan secara eksplisit.

## 5. Daftar Tool MCP

Semua parameter `path` relatif terhadap root. String kosong `""` berarti root itu sendiri.

### Read (selalu aktif)

| Tool | Parameter | Hasil | Annotation |
| --- | --- | --- | --- |
| `list_objects` | `path=""`, `recursive=false`, `max_keys`, `continuation_token` | `folders[]`, `files[]` (path, size, last_modified), `next_token` | `readOnlyHint` |
| `get_object_info` | `path` | size, content_type, last_modified, etag, metadata | `readOnlyHint` |
| `read_object` | `path`, `offset=0`, `length` | Teks UTF-8, atau gambar (png/jpeg/gif/webp) sebagai image content, atau pesan "binary" untuk tipe lain | `readOnlyHint` |
| `search_objects` | `path=""`, `pattern` (glob, contoh `*.csv`), `max_results` | Daftar path yang cocok | `readOnlyHint` |

Detail `read_object`:

- Pakai HTTP Range (`offset`, `length`) untuk file besar.
- Jika ukuran melebihi `MCP_S3_MAX_READ_BYTES`, kembalikan potongan pertama plus info total ukuran dan cara membaca bagian berikutnya.
- Gambar dikembalikan sebagai content `{ type: "image", data: <base64>, mimeType }` supaya Claude bisa melihatnya.
- Body dibaca dengan `Body.transformToByteArray()`, lalu teks di-decode dengan `TextDecoder("utf-8", { fatal: true })`. Jika decode gagal, file dianggap binary.

### Write (aktif jika `MCP_S3_READ_ONLY=false`)

| Tool | Parameter | Annotation |
| --- | --- | --- |
| `write_object` | `path`, `content` (teks), `content_type`, `overwrite=false` | `destructiveHint` jika overwrite |
| `create_folder` | `path` (membuat placeholder key `path/`) | `idempotentHint` |
| `copy_object` | `source`, `destination`, `overwrite=false` | - |

### Delete (aktif jika `MCP_S3_ALLOW_DELETE=true` dan tidak read-only)

| Tool | Parameter | Annotation |
| --- | --- | --- |
| `delete_object` | `path` (satu key, tidak ada delete rekursif) | `destructiveHint` |
| `move_object` | `source`, `destination`, `overwrite=false` | `destructiveHint` |

`overwrite=false` default: pakai `PutObjectCommand` dengan `IfNoneMatch: "*"` (conditional write). Jika provider tidak mendukung, fallback ke `HeadObject` dulu.

Contoh registrasi tool:

```ts
server.registerTool(
  "read_object",
  {
    title: "Read object",
    description: "Read a file under the workspace root. Paths are relative to the root.",
    inputSchema: {
      path: z.string().describe("Path relative to the root, e.g. reports/q1.csv"),
      offset: z.number().int().min(0).default(0),
      length: z.number().int().positive().optional(),
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  async ({ path, offset, length }) => {
    const key = resolveKey(config.rootPrefix, path);
    // ... storage.getObject(key, { offset, length })
  },
);
```

### Resources (opsional, fase berikutnya)

Ekspos file sebagai MCP resource dengan URI `s3root://<path-relatif>` supaya bisa di-attach lewat menu `@` di Claude.

## 6. Struktur Proyek

```
mcp-s3/
├── PLAN.md
├── README.md
├── package.json         # "type": "module", "bin": { "mcp-s3": "dist/index.js" }
├── tsconfig.json        # strict, module/moduleResolution: NodeNext, outDir: dist
├── vitest.config.ts
├── docker-compose.yml   # MinIO untuk integration test
├── .env.example
├── iam-policy.example.json
├── Dockerfile           # multi-stage, user non-root, mode HTTP
├── deploy/              # contoh compose + Caddy (reverse proxy HTTPS)
├── src/
│   ├── index.ts         # entrypoint (#!/usr/bin/env node), load config, pilih transport
│   ├── config.ts        # zod schema env var, validasi ROOT_PREFIX
│   ├── paths.ts         # resolveKey(), toRelative(), PathOutsideRootError
│   ├── storage.ts       # wrapper S3Client: list, head, get (range), put, copy, delete
│   ├── server.ts        # createServer(config): McpServer + registrasi tool kondisional
│   ├── errors.ts        # map error S3 ke pesan generik (NotFound, AccessDenied, ...)
│   ├── audit.ts         # audit log terstruktur (JSON) ke stderr / file (Fase 2)
│   ├── logger.ts        # logger berlevel ke stderr (MCP_S3_LOG_LEVEL)
│   ├── glob.ts          # matcher glob dengan waktu terbatas untuk search_objects
│   ├── tokens.ts        # TokenCodec: next_token stateless AES-256-GCM
│   ├── secret.ts        # wrapper Secret: tidak pernah tercetak di log/JSON
│   ├── http/            # mode HTTP (Fase 3)
│   │   ├── app.ts       # app Express, /mcp stateless, error handler generik
│   │   ├── config.ts    # loadHttpConfig(): env HTTP dan OAuth
│   │   ├── oauth.ts     # S3OAuthProvider, ClientRegistry (client statis + DCR stateless)
│   │   ├── login.ts     # halaman login, CSRF, rate limit, CredentialChecker
│   │   ├── clientAuth.ts # cek secret client constant-time untuk /token dan /revoke
│   │   └── sealed.ts    # codec AES-256-GCM dengan kunci HKDF per jenis token
│   └── tools/
│       ├── read.ts      # list_objects, get_object_info, read_object, search_objects
│       ├── write.ts     # write_object, create_folder, copy_object (ditunda)
│       └── delete.ts    # delete_object, move_object (ditunda)
├── test/
│   ├── unit/
│   │   ├── paths.test.ts    # resolveKey, toRelative
│   │   ├── config.test.ts   # validasi env var
│   │   └── tools.test.ts    # handler tool dengan aws-sdk-client-mock
│   ├── integration/
│   │   └── storage.test.ts  # storage.ts dan tool ke MinIO
│   ├── e2e/
│   │   └── stdio.test.ts    # spawn dist/index.js lewat MCP client stdio
│   └── helpers/
│       └── minio.ts         # bucket unik per run, seed, cleanup
└── .claude/agents/
    ├── implementer.md       # menulis kode src/
    ├── reviewer.md          # review read-only
    └── test-writer.md       # test, lint, e2e
```

Script `package.json`:

| Script | Perintah |
| --- | --- |
| `build` | `tsc` |
| `dev` | `tsx src/index.ts` |
| `test` | `vitest run test/unit` (tanpa Docker) |
| `test:int` | `docker compose up -d --wait && vitest run test/integration` |
| `test:e2e` | `npm run build && docker compose up -d --wait && vitest run test/e2e` |
| `test:all` | `npm test && npm run test:int && npm run test:e2e` |
| `lint` | `eslint . && tsc --noEmit && tsc --noEmit -p test` |
| `minio:down` | matikan MinIO test |
| `inspect` | `npx @modelcontextprotocol/inspector node dist/index.js` |

Aturan penting di layer `tools/`: tool tidak pernah memakai `S3Client` langsung. Semua akses lewat `storage.ts`, dan `storage.ts` hanya menerima key hasil `resolveKey()`.

## 7. Cara Connect ke Claude

Build dulu sebelum connect:

```bash
cd /path/to/mcp-s3 && npm install && npm run build
```

### Claude Code (stdio)

```bash
claude mcp add s3 --transport stdio --scope project \
  -e S3_BUCKET=my-bucket \
  -e S3_ROOT_PREFIX=claude-workspace/ \
  -e AWS_REGION=ap-southeast-1 \
  -e AWS_PROFILE=mcp-s3 \
  -- node /path/to/mcp-s3/dist/index.js
```

Nama server (`s3`) wajib ditulis sebelum `-e`/`--env`. Opsi itu menerima banyak nilai, jadi nama yang ditaruh setelahnya ikut terbaca sebagai env dan gagal dengan `Invalid environment variable format: s3` (dicek 2026-11-26).

Atau tulis langsung `.mcp.json` di root proyek:

```json
{
  "mcpServers": {
    "s3": {
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

Jangan menaruh access key di `.mcp.json` yang di-commit. Pakai `AWS_PROFILE` atau ekspansi `${VAR}`. Default credential provider chain di SDK v3 sudah membaca `AWS_PROFILE`, jadi tidak perlu kode tambahan.

Opsional: izinkan tool read tanpa prompt di `.claude/settings.json`:

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

Tool write/delete tetap minta konfirmasi.

### Claude Desktop (stdio)

Tambahkan ke `claude_desktop_config.json`:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

Isi blok `mcpServers` sama seperti `.mcp.json` di atas. Restart Claude Desktop setelah edit.

### claude.ai (remote, opsional)

- Jalankan dengan `MCP_S3_TRANSPORT=http` (`StreamableHTTPServerTransport` dari `@modelcontextprotocol/sdk/server/streamableHttp.js`, endpoint `/mcp`).
- Wajib di balik HTTPS publik dan **wajib ada autentikasi** (OAuth sesuai spesifikasi MCP authorization).
- Tambahkan sebagai custom connector di pengaturan claude.ai.
- Jangan pernah expose server ini ke internet tanpa auth. Siapa pun yang tahu URL-nya akan mendapat akses ke root prefix.

### Testing manual

```bash
npx @modelcontextprotocol/inspector node /path/to/mcp-s3/dist/index.js
```

## 8. Penanganan Risiko

| Risiko | Mitigasi |
| --- | --- |
| Path traversal ke luar root | Path jail (lapis 1) + IAM prefix (lapis 2) |
| Prefix collision (`data` vs `data-backup`) | `ROOT_PREFIX` wajib diakhiri `/` |
| Prompt injection dari isi file S3 | Read-only default; tool destruktif minta konfirmasi di Claude; isi file diperlakukan sebagai data |
| Claude menghapus/menimpa data | `ALLOW_DELETE=false` default, `overwrite=false` default, bucket versioning, tidak ada delete rekursif |
| Context Claude kebanjiran | Batas `MAX_READ_BYTES`, `MAX_LIST_KEYS`, pagination |
| Credential bocor | `AWS_PROFILE`/role, tidak di-commit, tidak pernah ditulis ke log |
| stdout tercemar merusak protokol stdio | Semua log lewat `console.error` (stderr), tidak ada `console.log()`; aturan eslint `no-console` dengan pengecualian `error` |
| Error membocorkan struktur bucket | Error dipetakan ke pesan generik (`NotFound`, `AccessDenied`, `PathOutsideRoot`) |

## 9. Rencana Pengerjaan

### Fase 0: Persiapan

- [x] `npm init`, set `"type": "module"` dan `"bin"`.
- [x] `package.json`: `"engines": { "node": ">=24" }`, tambahkan `.nvmrc` berisi `24`.
- [x] Dependency: `npm i @modelcontextprotocol/sdk @aws-sdk/client-s3 zod picomatch`.
- [x] Dev dependency: `npm i -D typescript tsx vitest aws-sdk-client-mock eslint typescript-eslint @types/node@24 @types/picomatch`.
- [x] `tsconfig.json`: `strict: true`, `module` dan `moduleResolution` `NodeNext`, `target: ES2024`, `outDir: dist`.
- [x] `docker-compose.yml` dengan MinIO untuk test lokal.
- [ ] Buat IAM user/role khusus dengan policy di bagian 3, simpan sebagai profile `mcp-s3`.

### Fase 1: Core read-only

- [x] `config.ts`: parse env dengan zod, gagal start jika `S3_ROOT_PREFIX` tidak valid.
- [x] `paths.ts`: `resolveKey()` dan `toRelative()` beserta unit test lengkap (bagian 10).
- [x] `storage.ts`: `ListObjectsV2Command` (dengan `Delimiter: "/"`), `HeadObjectCommand`, `GetObjectCommand` dengan `Range`.
- [x] `errors.ts`: map `NoSuchKey`, `NotFound`, `AccessDenied` ke pesan generik.
- [x] `tools/read.ts`: `list_objects`, `get_object_info`, `read_object`, `search_objects`.
- [x] `server.ts` + `index.ts`: `McpServer` dengan `StdioServerTransport`, log ke stderr.
- [ ] Test dengan MCP Inspector.
- [ ] Connect ke Claude Code, coba skenario nyata.

### Fase 2: Write, delete, audit

Keputusan 2026-11-26: versi ini tetap read-only. Tool write dan delete ditunda (belum dibuat), jadi Fase 2 hanya mengerjakan audit log beserta test-nya. `MCP_S3_READ_ONLY=false` tetap hanya memberi WARN.

- [ ] (Ditunda) Tool write (`write_object`, `create_folder`, `copy_object`) di balik `MCP_S3_READ_ONLY`.
- [ ] (Ditunda) Tool delete (`delete_object`, `move_object`) di balik `MCP_S3_ALLOW_DELETE`.
- [x] Tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`).
- [x] `audit.ts`: log JSON per pemanggilan tool (waktu, tool, path relatif, hasil, ukuran).
- [x] Unit test tool dengan `aws-sdk-client-mock`.
- [x] Integration test ke MinIO untuk semua tool, termasuk kasus prefix collision.

### Fase 3: Remote (wajib, keputusan 2026-11-25)

Keputusan:

- Akses remote dibutuhkan (claude.ai, Claude Desktop, dan Claude Code di komputer lain).
- **Mode HTTP selalu read-only.** Jika `MCP_S3_TRANSPORT=http` digabung dengan `MCP_S3_READ_ONLY=false` atau `MCP_S3_ALLOW_DELETE=true`, server gagal start dengan pesan jelas di stderr. Tool write/delete hanya untuk mode stdio lokal.
- **Autentikasi: satu akun admin statis.** Server menjadi authorization server OAuth sendiri (memakai dukungan auth di `@modelcontextprotocol/sdk`). Halaman login OAuth memeriksa satu username dan password admin statis dari env `MCP_S3_AUTH_USERNAME` dan `MCP_S3_AUTH_PASSWORD`, dipakai bersama semua user. Tidak ada IdP eksternal dan tidak ada database user.
  - Kredensial tidak boleh di-hardcode di kode dan tidak di-commit. Tidak ada nilai default untuk password.
  - Jika `MCP_S3_TRANSPORT=http` dan salah satu env auth kosong, server gagal start.
  - Perbandingan username dan password memakai `crypto.timingSafeEqual`.
  - Password tidak pernah ditulis ke log atau respons.
- Konsekuensi akun bersama yang diterima: audit log tidak bisa membedakan user, mencabut akses satu orang berarti ganti kredensial untuk semua, dan kredensial bocor berarti semua akses terbuka.
- Server remote memakai IAM user/role terpisah dengan policy read-only (`s3:GetObject`, `s3:ListBucket` dibatasi ke root prefix), tidak memakai credential mode stdio yang bisa menulis.
- Domain dan HTTPS belum tersedia. Fase 3 dibangun dan dites di `http://localhost`, ditambah Dockerfile dan contoh deploy. Deploy nyata dan pendaftaran connector claude.ai ditunda sampai domain HTTPS ada.
- Env var tambahan untuk HTTP dan OAuth diusulkan implementer di laporan Fase 3, lalu dicatat di bagian 4.
- Dari review Fase 1: `next_token` diganti token stateless terenkripsi (dikerjakan sekalian di perbaikan Fase 1, keputusan 2026-11-26). Isinya `{s3Token, scope, exp}` dienkripsi AES-256-GCM dengan `MCP_S3_TOKEN_KEY`, supaya tetap valid setelah restart, sleep, atau scale-to-zero. Semua sesi HTTP juga harus memakai satu `Storage` (satu `S3Client`) bersama; ini tetap dikerjakan di Fase 3.
- Refresh token (keputusan 2026-11-26): umur 7 hari sliding, maksimal 90 hari sejak login. Deteksi reuse refresh token ditunda karena butuh state persisten. Risiko yang diterima: token hasil rotasi valid lagi setelah restart sampai kedaluwarsa. Mitigasi jika bocor: ganti password admin atau `MCP_S3_TOKEN_KEY`.
- Syarat custom connector claude.ai (help center Claude, dicek 2026-11-25): server dihubungi dari cloud Anthropic, jadi harus bisa dijangkau publik di HTTPS port 443 (port lain tidak didukung). Authorization server harus menerima redirect URI `https://claude.ai/api/mcp/auth_callback`. Claude menawarkan "Register automatically" atau "Use your own OAuth client" (Client ID dan Secret statis); server sebaiknya mendukung keduanya.

Checklist:

- [x] Transport Streamable HTTP, bind default ke `127.0.0.1`.
- [x] Mode HTTP memaksa read-only (gagal start jika write/delete diaktifkan).
- [x] Autentikasi OAuth dengan login admin statis (`MCP_S3_AUTH_USERNAME`, `MCP_S3_AUTH_PASSWORD`); endpoint `/mcp` menolak request tanpa token valid.
- [x] Dockerfile dan contoh deploy di balik reverse proxy HTTPS.
- [ ] Tes lokal: Claude Code dan MCP Inspector ke `http://localhost`, termasuk alur login OAuth.
- [ ] (Ditunda sampai domain HTTPS ada) Deploy dan daftarkan sebagai custom connector di claude.ai.

### Fase 4: Hardening dan dokumentasi

- [ ] README: instalasi, konfigurasi, contoh IAM, cara connect.
- [ ] `.env.example` dan `iam-policy.example.json`.
- [ ] Uji manual credential langsung (tanpa server) ke key di luar root, pastikan `AccessDenied`.

## 10. Test Case Wajib untuk Path Jail

Dengan `ROOT_PREFIX=claude-workspace/`:

| Input | Hasil yang diharapkan |
| --- | --- |
| `""` | `claude-workspace/` |
| `reports/q1.csv` | `claude-workspace/reports/q1.csv` |
| `/reports/q1.csv` | `claude-workspace/reports/q1.csv` |
| `../secret.txt` | Ditolak |
| `a/../../b` | Ditolak |
| `./a.txt` | Ditolak |
| `a\..\b` | Ditolak |
| `a//b` | Ditolak |
| `a\x00b` | Ditolak |
| `%2e%2e/x` | `claude-workspace/%2e%2e/x` (literal, tidak di-decode) |
| Key > 1024 byte | Ditolak |
| `copy_object(source="../x", destination="y")` | Ditolak |

Test tambahan:

- Bucket berisi `claude-workspace/a.txt` dan `claude-workspace-backup/b.txt`. `list_objects(recursive=true)` hanya mengembalikan `a.txt`.
- Tidak ada respons tool yang mengandung string `claude-workspace/` atau nama bucket.
- `ROOT_PREFIX` kosong, tanpa `/` di akhir, atau mengandung `..` membuat server gagal start.
- Mode read-only: tool write dan delete tidak muncul di `tools/list`.

## 11. Definition of Done (versi 1)

- [ ] Claude Code bisa list, baca, dan (jika diaktifkan) tulis file di root prefix.
- [ ] Semua test path jail lulus.
- [ ] Credential server terbukti `AccessDenied` di luar root prefix (lapis IAM).
- [ ] Default config adalah read-only.
- [ ] Tidak ada credential atau nama bucket di log dan respons tool.
- [ ] README cukup untuk orang lain setup dari nol.

## 12. Pertanyaan Terbuka

1. ~~Provider storage: AWS S3, MinIO, atau Cloudflare R2?~~ Terjawab 2026-11-26: AWS S3 untuk sementara. MinIO tetap dipakai untuk test lokal.
2. ~~Apakah butuh write/delete di versi 1, atau cukup read-only dulu?~~ Terjawab 2026-11-26: read-only dulu, write/delete ditunda.
3. ~~Apakah perlu akses dari claude.ai (remote), atau cukup Claude Code/Desktop lokal?~~ Terjawab 2026-11-25: remote dibutuhkan. Lihat keputusan di Fase 3.
4. Apakah satu root cukup, atau nanti butuh beberapa root dengan level akses berbeda? Untuk sekarang (2026-11-25): satu root, semua user remote hanya bisa view (read-only). Akses berbeda per user ditunda.
