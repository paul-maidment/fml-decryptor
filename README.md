# FML Decoder — C# Reference Implementation

Pure C# decoder for `.fml` files. No external dependencies beyond .NET 8.

## Build

```
dotnet build
```

## Run

```
dotnet run -- sample.fml [output_path]
```

If `output_path` is omitted, writes to `sample_decoded.dat`.

Example:

```
dotnet run --project FmlDecryptor.csproj -- SampleFiles\sample-1.fml
Decoded 1466 bytes -> 9407 bytes
Output: SampleFiles\sample-1_decoded.dat
VERIFIED: Output matches known-good decoded file
```

### Encoding

```
dotnet run -- --encode input.dat [output.fml] [--password hex] [--chunk-size N] [--phase1]
```

| Flag | Description |
|------|-------------|
| `--password` | 8-char hex password (default: random) |
| `--chunk-size` | Chunk size in bytes (default: 524288) |
| `--phase1` | Produce legacy Phase 1 file (no seed, static key `b67de657`) |

## Test

```
dotnet test FmlDecryptor.Tests
```

22 tests covering RIPEMD-128 vectors, Mixer vectors, ECL mode round-trips,
chunk CRC32 computation, single-chunk sample files, and multi-chunk sample files.

## File Format

### File Header (128 bytes)

```
[0..3]      Magic "AACS"
[4..7]      Flags (0x00000800)
[8..11]     Flags (0xC141F43F)
[12..15]    Chunk count (uint32 LE)
[16..27]    Fixed pattern (0x3F8F5C29 0x00010002 0x00000000)
[28..127]   Integrity check — 100 bytes of ECL-encrypted counter (0x00..0x63)
            Encrypted with the same AES key and ECL mode as the chunks.
            On load, decrypt and verify bytes equal 0,1,2,...,99.
            Required for MFME compatibility.
```

### Single-chunk files (smaller .fml)

```
[128..131]   csize (compressed/encrypted size)
[132..135]   dsize (decompressed size)
[136..139]   chunk_crc32 (CRC32 of decompressed chunk data, init=0, no final XOR)
[140..143]   next_header_offset (points to next chunk header, or last4 seed)
[144..]      encrypted + zlib payload (csize bytes)
[-4..]       last4 (password seed)
```

### Multi-chunk files (larger .fml)

Larger `.fml` files contain multiple independently-encrypted chunks, each
decompressing to a portion of the final output. The decoder processes all
chunks and concatenates the results.

```
chunk 1 header ─── embedded in file header [128..143]  (16 bytes: csize + dsize + chunk_crc32 + next_header_offset)
chunk 1 data   ── [144 .. 144+csize1-1]                 (encrypted zlib)
chunk 2 header ── [144+csize1 .. +15]                   (16 bytes)
chunk 2 data   ── [+16 .. +16+csize2-1]                 (encrypted zlib)
...
chunk N header ── ...                                   (16 bytes)
chunk N data   ── ...                                   (encrypted zlib)
[-4..]         ── last4 (password seed)
```

Each chunk header (16 bytes):
```
[0..3]    csize (encrypted data size)
[4..7]    dsize (decompressed data size)
[8..11]   chunk_crc32 (CRC32 of decompressed chunk, init=0, no final XOR)
[12..15]  next_header_offset (file offset of next chunk header)
```

All chunks use the same password-derived AES key and IV. Each chunk is
decrypted independently (ECL mode resets per chunk).

### Format Phases (Phase 1 / Phase 2)

Two generations of `.fml` files exist, reflecting the development history when the encryption and compression was added.

| Phase | Password | File layout | Detection |
|-------|----------|-------------|-----------|
| **Phase 1** (legacy) | Static key `b67de657` | Ends at EOF — no trailing seed | Last chunk `next_header_offset == file_size` |
| **Phase 2** (current) | Seed-derived via Mixer | 4-byte seed appended at EOF | Last chunk `next_header_offset == file_size - 4` |

The decoder automatically detects the password to use by walking the chunk header chain
and comparing the final `next_header_offset` to the file length.

### Pipeline

1. **Phase detection** — Walk chunk headers to determine Phase 1 vs Phase 2
2. **Mixer** — 100 iterations on `last4` → 8-char hex password (Phase 2 only)
3. **RIPEMD-128** — hash password bytes → 16-byte AES key
4. **IV** — `AES_ECB_encrypt(key, 16 × 0xFF)`
5. **ECL decrypt** — custom feedback mode, AES-ECB (per chunk)
6. **zlib decompress** (per chunk)
7. **CRC32 verify** — compare against `chunk_crc32` in header, warn on mismatch
8. **Trim** each chunk to its `dsize`
9. **Concatenate** all chunk outputs

## Files

| File | Purpose |
|------|---------|
| `FmlDecryptor.cs` | `Decrypt()`, `Mix()`, `EclDecrypt()` |
| `Ripemd128.cs` | `ComputeHash()` — RIPEMD-128 |
| `Program.cs` | CLI entry point |
| `SampleFiles/` | Test .fml files + expected .dat outputs |
| `FmlDecryptor.Tests/` | xUnit test project |

## License

Licensed under the GNU Affero General Public License, version 3 or later
(AGPL-3.0-or-later). See [LICENSE](LICENSE) for the full text.

Copyright (C) 2026 Paul Maidment.
