using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace FmlDecryptor
{
    public static class FmlDecryptor
    {
        public static byte[] Decrypt(byte[] fmlBytes)
        {
            if (fmlBytes == null || fmlBytes.Length < 148)
                throw new ArgumentException("FML data too short");

            string password = DerivePassword(fmlBytes);

            try
            {
                return DecryptAllChunks(fmlBytes, password);
            }
            catch (Exception)
            {
                return DecryptAllChunks(fmlBytes, AltPassword);
            }
        }

        // Two file format phases exist:
        //   Phase 1 (legacy): static password "b67de657", last chunk's next_header_offset == EOF (no seed)
        //   Phase 2 (current): 4-byte seed at EOF, last chunk's next_header_offset == EOF - 4
        // We detect the phase by walking the chunk header chain and comparing the final
        // next_header_offset to the file length.
        private static string DerivePassword(byte[] fmlBytes)
        {
            uint lastNextOff = FindLastNextHeaderOffset(fmlBytes);

            if (lastNextOff == fmlBytes.Length)
                return AltPassword;

            if (lastNextOff == fmlBytes.Length - 4)
            {
                uint seed = BitConverter.ToUInt32(fmlBytes, fmlBytes.Length - 4);
                return Mix(seed).ToString("x8");
            }

            uint last4 = BitConverter.ToUInt32(fmlBytes, fmlBytes.Length - 4);
            return Mix(last4).ToString("x8");
        }

        // Walks the chunk header chain from offset 128, following each chunk's
        // next_header_offset field, and returns the final chunk's next_header_offset.
        private static uint FindLastNextHeaderOffset(byte[] fmlBytes)
        {
            int pos = 128;
            uint lastNextOff = 0;
            int maxChunks = 10000;

            while (pos + 16 <= fmlBytes.Length && maxChunks-- > 0)
            {
                uint csize = BitConverter.ToUInt32(fmlBytes, pos);
                uint nextOff = BitConverter.ToUInt32(fmlBytes, pos + 12);
                lastNextOff = nextOff;

                if (nextOff >= fmlBytes.Length || nextOff <= pos)
                    break;

                if (nextOff + 16 > fmlBytes.Length)
                    break;

                pos = (int)nextOff;
            }

            return lastNextOff;
        }

        public static byte[] DecryptWithPassword(byte[] fmlBytes, uint csize, uint dsize, string password)
        {
            byte[] aesKey = Ripemd128.ComputeHash(Encoding.ASCII.GetBytes(password));
            byte[] iv = EncryptEcb(aesKey, s_allFfBlock);

            int ctLen = (int)Math.Min(csize, (uint)(fmlBytes.Length - 144));
            byte[] ct = new byte[ctLen];
            Array.Copy(fmlBytes, 144, ct, 0, ctLen);

            byte[] compressed = EclDecrypt(ct, aesKey, iv);
            byte[] decompressed = ZlibDecompress(compressed);

            if (decompressed.Length > dsize)
            {
                byte[] trimmed = new byte[dsize];
                Array.Copy(decompressed, trimmed, dsize);
                return trimmed;
            }

            return decompressed;
        }

        private static byte[] DecryptAllChunks(byte[] fmlBytes, string password)
        {
            byte[] aesKey = Ripemd128.ComputeHash(Encoding.ASCII.GetBytes(password));
            byte[] iv = EncryptEcb(aesKey, s_allFfBlock);

            using (MemoryStream output = new MemoryStream())
            {
                uint csize = BitConverter.ToUInt32(fmlBytes, 128);
                uint dsize = BitConverter.ToUInt32(fmlBytes, 132);
                uint expectedCrc32 = BitConverter.ToUInt32(fmlBytes, 136);
                uint nextHeaderOffset = BitConverter.ToUInt32(fmlBytes, 140);
                int position = 144;
                int chunkIndex = 0;

                while (position < fmlBytes.Length - 4)
                {
                    int ctLen = (int)Math.Min(csize, (uint)(fmlBytes.Length - position));
                    byte[] ct = new byte[ctLen];
                    Array.Copy(fmlBytes, position, ct, 0, ctLen);

                    byte[] compressed = EclDecrypt(ct, aesKey, iv);
                    byte[] decompressed = ZlibDecompress(compressed);

                    int writeLen = decompressed.Length > dsize ? (int)dsize : decompressed.Length;
                    byte[] chunkOutput = new byte[writeLen];
                    Array.Copy(decompressed, chunkOutput, writeLen);
                    output.Write(chunkOutput, 0, writeLen);

                    uint actualCrc32 = ComputeChunkCrc32(chunkOutput);
                    if (actualCrc32 != expectedCrc32)
                        Console.Error.WriteLine($"WARNING: chunk {chunkIndex} CRC32 mismatch (expected 0x{expectedCrc32:X8}, computed 0x{actualCrc32:X8})");

                    position += (int)csize;

                    if (position + 16 > fmlBytes.Length - 4)
                        break;

                    csize = BitConverter.ToUInt32(fmlBytes, position);
                    dsize = BitConverter.ToUInt32(fmlBytes, position + 4);
                    expectedCrc32 = BitConverter.ToUInt32(fmlBytes, position + 8);
                    nextHeaderOffset = BitConverter.ToUInt32(fmlBytes, position + 12);
                    position += 16;
                    chunkIndex++;
                }

                return output.ToArray();
            }
        }

        public static uint Mix(uint last4)
        {
            uint result = last4;
            const uint addr = 0x00C59A00;
            for (int i = 0; i < 100; i++)
            {
                uint x = addr ^ result;
                uint v4 = (x >> 24) | (x << 24) | (x & 0x00FFFF00);
                result = (v4 << 3) | (v4 >> 29);
            }
            return result;
        }

        public static uint MixInverse(uint password)
        {
            uint result = password;
            const uint addr = 0x00C59A00;
            for (int i = 0; i < 100; i++)
            {
                uint v4 = (result >> 3) | (result << 29);
                uint v = (v4 >> 24) | (v4 << 24) | (v4 & 0x00FFFF00);
                result = addr ^ v;
            }
            return result;
        }

        private static byte[] EncryptEcb(byte[] key, byte[] plaintext)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.Key = key;
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    byte[] output = new byte[plaintext.Length];
                    encryptor.TransformBlock(plaintext, 0, plaintext.Length, output, 0);
                    return output;
                }
            }
        }

        public static byte[] EclDecrypt(byte[] ct, byte[] key, byte[] iv)
        {
            byte[] fb_d = new byte[16];
            byte[] fb_b = new byte[16];
            Array.Copy(iv, fb_d, 16);

            int fullBlocks = ct.Length - (ct.Length % 16);
            byte[] result = new byte[fullBlocks + (ct.Length % 16)];
            int resultPos = 0;

            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.Key = key;

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    for (int i = 0; i < fullBlocks; i += 16)
                    {
                        for (int j = 0; j < 16; j++)
                            fb_b[j] = (byte)(ct[i + j] ^ fb_d[j]);

                        byte[] dec = new byte[16];
                        decryptor.TransformBlock(ct, i, 16, dec, 0);

                        for (int j = 0; j < 16; j++)
                            result[resultPos++] = (byte)(dec[j] ^ fb_d[j]);

                        byte[] tmp = fb_d;
                        fb_d = fb_b;
                        fb_b = tmp;
                    }

                    int rem = ct.Length % 16;
                    if (rem > 0)
                    {
                        byte[] keystream = new byte[16];
                        encryptor.TransformBlock(fb_d, 0, 16, keystream, 0);

                        for (int j = 0; j < rem; j++)
                            result[resultPos++] = (byte)(ct[fullBlocks + j] ^ keystream[j]);
                    }
                }
            }

            return result;
        }

        private static byte[] ZlibDecompress(byte[] data)
        {
            using (MemoryStream output = new MemoryStream())
            {
                using (MemoryStream compressed = new MemoryStream(data))
                using (ZLibStream zlib = new ZLibStream(compressed, CompressionMode.Decompress))
                {
                    byte[] buffer = new byte[65536];
                    int bytesRead;
                    while ((bytesRead = zlib.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        output.Write(buffer, 0, bytesRead);
                    }
                }
                return output.ToArray();
            }
        }

        public static uint ComputeChunkCrc32(byte[] decompressedData)
        {
            uint crc = 0;
            foreach (byte b in decompressedData)
            {
                crc ^= b;
                for (int j = 0; j < 8; j++)
                    crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320 : crc >> 1;
            }
            return crc;
        }

        public static byte[] EclEncrypt(byte[] plaintext, byte[] key, byte[] iv)
        {
            byte[] fb_d = new byte[16];
            byte[] fb_b = new byte[16];
            Array.Copy(iv, fb_d, 16);

            int fullBlocks = plaintext.Length - (plaintext.Length % 16);
            byte[] result = new byte[fullBlocks + (plaintext.Length % 16)];
            int resultPos = 0;

            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.Key = key;

                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    byte[] block = new byte[16];
                    for (int i = 0; i < fullBlocks; i += 16)
                    {
                        for (int j = 0; j < 16; j++)
                            block[j] = (byte)(plaintext[i + j] ^ fb_d[j]);

                        byte[] ct = new byte[16];
                        encryptor.TransformBlock(block, 0, 16, ct, 0);

                        for (int j = 0; j < 16; j++)
                            result[resultPos++] = ct[j];

                        for (int j = 0; j < 16; j++)
                            fb_b[j] = (byte)(ct[j] ^ fb_d[j]);

                        byte[] tmp = fb_d;
                        fb_d = fb_b;
                        fb_b = tmp;
                    }

                    int rem = plaintext.Length % 16;
                    if (rem > 0)
                    {
                        byte[] keystream = new byte[16];
                        encryptor.TransformBlock(fb_d, 0, 16, keystream, 0);
                        for (int j = 0; j < rem; j++)
                            result[resultPos++] = (byte)(plaintext[fullBlocks + j] ^ keystream[j]);
                    }
                }
            }

            return result;
        }

        public static byte[] Encode(byte[] plaintext, string password, int chunkSize = 524288, bool phase1 = false)
        {
            if (plaintext == null || plaintext.Length == 0)
                throw new ArgumentException("Plaintext is null or empty");

            if (password.Length != 8)
                throw new ArgumentException("Password must be an 8-character hex string (e.g. \"01279247\")");

            uint passwordVal = uint.Parse(password, System.Globalization.NumberStyles.HexNumber);
            uint seed = MixInverse(passwordVal);

            byte[] aesKey = Ripemd128.ComputeHash(Encoding.ASCII.GetBytes(password));
            byte[] iv = EncryptEcb(aesKey, s_allFfBlock);

            using (MemoryStream output = new MemoryStream())
            {
                int totalChunks = (plaintext.Length + chunkSize - 1) / chunkSize;

                output.Write(s_fileHeaderPrefix, 0, 12);
                output.Write(BitConverter.GetBytes((uint)totalChunks), 0, 4);
                output.Write(s_fileHeaderPrefix, 16, 12);

                byte[] counter = new byte[100];
                for (int i = 0; i < 100; i++)
                    counter[i] = (byte)i;
                byte[] encryptedCounter = EclEncrypt(counter, aesKey, iv);
                output.Write(encryptedCounter, 0, 100);

                int offset = 0;

                for (int chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++)
                {
                    int thisChunkSize = Math.Min(chunkSize, plaintext.Length - offset);
                    byte[] chunkPlain = new byte[thisChunkSize];
                    Array.Copy(plaintext, offset, chunkPlain, 0, thisChunkSize);

                    uint crc32 = ComputeChunkCrc32(chunkPlain);
                    byte[] compressed = ZlibCompress(chunkPlain);
                    byte[] encrypted = EclEncrypt(compressed, aesKey, iv);

                    int headerStart = 128;
                    if (chunkIndex > 0)
                        headerStart = (int)output.Length;

                    output.Write(BitConverter.GetBytes((uint)encrypted.Length), 0, 4);
                    output.Write(BitConverter.GetBytes((uint)thisChunkSize), 0, 4);
                    output.Write(BitConverter.GetBytes(crc32), 0, 4);

                    uint nextOff = (uint)(output.Length + 4 + encrypted.Length);
                    output.Write(BitConverter.GetBytes(nextOff), 0, 4);

                    output.Write(encrypted, 0, encrypted.Length);

                    offset += thisChunkSize;
                }

                if (!phase1)
                    output.Write(BitConverter.GetBytes(seed), 0, 4);

                return output.ToArray();
            }
        }

        private static byte[] ZlibCompress(byte[] data)
        {
            using (MemoryStream output = new MemoryStream())
            {
                using (ZLibStream zlib = new ZLibStream(output, CompressionMode.Compress, true))
                {
                    zlib.Write(data, 0, data.Length);
                }
                return output.ToArray();
            }
        }

        private const string AltPassword = "b67de657";

        private static readonly byte[] s_fileHeaderPrefix = new byte[28]
        {
            0x41, 0x41, 0x43, 0x53, 0x00, 0x00, 0x08, 0x00,
            0x3F, 0xF4, 0x41, 0xC1, 0x01, 0x00, 0x00, 0x00,
            0x29, 0x5C, 0x8F, 0x3F, 0x02, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00
        };

        private static readonly byte[] s_allFfBlock = new byte[16]
        {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        };
    }
}
