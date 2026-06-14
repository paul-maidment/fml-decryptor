using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using FmlDecryptor;
using Xunit;
using Dec = FmlDecryptor.FmlDecryptor;

public class FmlDecryptorTests
{
    [Fact]
    public void Ripemd128_KnownVector_1()
    {
        Assert.Equal(
            "0e751ef3533305c26ac67b1a39204ac8",
            ToHex(Ripemd128.ComputeHash(Encoding.ASCII.GetBytes("01279247"))));
    }

    [Fact]
    public void Ripemd128_KnownVector_2()
    {
        Assert.Equal(
            "d1f6109144b92b6ec44e8c4829e5ea9e",
            ToHex(Ripemd128.ComputeHash(Encoding.ASCII.GetBytes("0098ffef"))));
    }

    [Fact]
    public void Ripemd128_KnownVector_3()
    {
        Assert.Equal(
            "00fa20bde36860aa74c63dbc2bdd0b78",
            ToHex(Ripemd128.ComputeHash(Encoding.ASCII.GetBytes("276c4849"))));
    }

    [Fact]
    public void Ripemd128_KnownVector_4()
    {
        Assert.Equal(
            "1b248a40f86bdc69effbe9bc5865fe96",
            ToHex(Ripemd128.ComputeHash(Encoding.ASCII.GetBytes("5ac7da74"))));
    }

    [Fact]
    public void Ripemd128_EmptyString()
    {
        Assert.Equal(
            "cdf26213a150dc3ecb610f18f6b38b46",
            ToHex(Ripemd128.ComputeHash(Array.Empty<byte>())));
    }

    [Fact]
    public void Ripemd128_SingleChar()
    {
        Assert.Equal(
            "86be7afa339d0fc7cfc785e72f578d33",
            ToHex(Ripemd128.ComputeHash(Encoding.ASCII.GetBytes("a"))));
    }

    [Fact]
    public void Ripemd128_Abc()
    {
        Assert.Equal(
            "c14a12199c66e4ba84636b0f69144c77",
            ToHex(Ripemd128.ComputeHash(Encoding.ASCII.GetBytes("abc"))));
    }

    [Fact]
    public void Mixer_KnownVector_1()
    {
        Assert.Equal(0x01279247u, Dec.Mix(0x84EE4F7C));
    }

    [Fact]
    public void Mixer_KnownVector_2()
    {
        Assert.Equal(0x0098FFEFu, Dec.Mix(0x7EACD4E8));
    }

    [Fact]
    public void Mixer_KnownVector_3()
    {
        Assert.Equal(0x276C4849u, Dec.Mix(0x25CEAB82));
    }

    [Fact]
    public void Mixer_KnownVector_4()
    {
        Assert.Equal(0x5AC7DA74u, Dec.Mix(0x847971D9));
    }

    [Fact]
    public void Decode_Sample1()
    {
        DecodeAndVerify(1);
    }

    [Fact]
    public void Decode_Sample2()
    {
        DecodeAndVerify(2);
    }

    [Fact]
    public void Decode_Sample3()
    {
        DecodeAndVerify(3);
    }

    [Fact]
    public void Decode_Sample4()
    {
        DecodeAndVerify(4);
    }

    [Fact]
    public void ECL_Decrypt_ExactBlock()
    {
        byte[] key = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        byte[] iv = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        byte[] pt = Encoding.ASCII.GetBytes("Hello World! 123");
        byte[] ct = EclEncrypt(pt, key, iv);
        byte[] dec = Dec.EclDecrypt(ct, key, iv);
        Assert.Equal(pt, dec);
    }

    [Fact]
    public void ECL_Decrypt_WithPartialBlock()
    {
        byte[] key = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        byte[] iv = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        byte[] pt = Encoding.ASCII.GetBytes("Hello World! Hello World! Hello!?");
        byte[] ct = EclEncrypt(pt, key, iv);
        byte[] dec = Dec.EclDecrypt(ct, key, iv);
        Assert.Equal(pt, dec);
    }

    private static byte[] EclEncrypt(byte[] pt, byte[] key, byte[] iv)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = key;

            byte[] fb_d = new byte[16];
            byte[] fb_b = new byte[16];
            Array.Copy(iv, fb_d, 16);

            int fullBlocks = pt.Length - (pt.Length % 16);
            byte[] result = new byte[fullBlocks + (pt.Length % 16)];
            int pos = 0;

            using (var encryptor = aes.CreateEncryptor())
            {
                byte[] block = new byte[16];
                for (int i = 0; i < fullBlocks; i += 16)
                {
                    for (int j = 0; j < 16; j++)
                        block[j] = (byte)(pt[i + j] ^ fb_d[j]);

                    byte[] ct = new byte[16];
                    encryptor.TransformBlock(block, 0, 16, ct, 0);

                    for (int j = 0; j < 16; j++)
                        result[pos++] = ct[j];

                    for (int j = 0; j < 16; j++)
                        fb_b[j] = (byte)(ct[j] ^ fb_d[j]);

                    byte[] tmp = fb_d;
                    fb_d = fb_b;
                    fb_b = tmp;
                }

                int rem = pt.Length % 16;
                if (rem > 0)
                {
                    byte[] keystream = new byte[16];
                    encryptor.TransformBlock(fb_d, 0, 16, keystream, 0);
                    for (int j = 0; j < rem; j++)
                        result[pos++] = (byte)(pt[fullBlocks + j] ^ keystream[j]);
                }
            }

            return result;
        }
    }

    private static void DecodeAndVerify(int sampleNum)
    {
        string root = Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..", "SampleFiles");
        if (!Directory.Exists(root))
            root = Path.Combine(AppContext.BaseDirectory, "SampleFiles");

        string fmlPath = Path.Combine(root, $"sample-{sampleNum}.fml");
        string expectedPath = Path.Combine(root, $"sample-{sampleNum}_decoded.dat");

        byte[] actual = Dec.Decrypt(File.ReadAllBytes(fmlPath));
        byte[] expected = File.ReadAllBytes(expectedPath);

        Assert.Equal(expected.Length, actual.Length);
        for (int i = 0; i < expected.Length; i++)
            if (expected[i] != actual[i])
                Assert.Fail($"Byte mismatch at offset {i}: expected 0x{expected[i]:X2}, got 0x{actual[i]:X2}");
    }

    private static string ToHex(byte[] bytes)
    {
        return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
    }
}
