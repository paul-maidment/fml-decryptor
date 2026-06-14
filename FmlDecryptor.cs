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

            uint last4 = BitConverter.ToUInt32(fmlBytes, fmlBytes.Length - 4);
            string password = Mix(last4).ToString("x8");

            try
            {
                return DecryptAllChunks(fmlBytes, password);
            }
            catch (Exception)
            {
                return DecryptAllChunks(fmlBytes, AltPassword);
            }
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

        private const string AltPassword = "b67de657";

        private static readonly byte[] s_allFfBlock = new byte[16]
        {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        };
    }
}
