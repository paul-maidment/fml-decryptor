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

## Test

```
dotnet test FmlDecryptor.Tests
```

17 tests covering RIPEMD-128 vectors, Mixer vectors, ECL mode round-trips,
and byte-exact decode of all 4 sample files.

## File Format

### Single-chunk files (smaller .fml)

```
[0..127]     header fields
[128..131]   csize (compressed/encrypted size)
[132..135]   dsize (decompressed size)
[136..143]   unknown (chunk boundary marker, part of 16-byte chunk header)
[144..]      encrypted + zlib payload (csize bytes)
[-4..]       last4 (password seed)
```

### Multi-chunk files (larger .fml)

Larger `.fml` files contain multiple independently-encrypted chunks, each
decompressing to a portion of the final output. The decoder processes all
chunks and concatenates the results.

```
chunk 1 header ─── embedded in file header [128..143]  (16 bytes: csize + dsize + 8 unknown)
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
[8..15]   unknown (8 bytes)
```

All chunks use the same password-derived AES key and IV. Each chunk is
decrypted independently (ECL mode resets per chunk).

### Pipeline

1. **Mixer** — 100 iterations on `last4` → 8-char hex password
2. **RIPEMD-128** — hash password bytes → 16-byte AES key
3. **IV** — `AES_ECB_encrypt(key, 16 × 0xFF)`
4. **ECL decrypt** — custom feedback mode, AES-ECB (per chunk)
5. **zlib decompress** (per chunk)
6. **Trim** each chunk to its `dsize`
7. **Concatenate** all chunk outputs

## Files

| File | Purpose |
|------|---------|
| `FmlDecryptor.cs` | `Decrypt()`, `Mix()`, `EclDecrypt()` |
| `Ripemd128.cs` | `ComputeHash()` — RIPEMD-128 |
| `Program.cs` | CLI entry point |
| `SampleFiles/` | Test .fml files + expected .dat outputs |
| `FmlDecryptor.Tests/` | xUnit test project |
