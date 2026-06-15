using System;
using System.IO;

namespace FmlDecryptor
{
    internal static class AppMain
    {
        public static int Main(string[] args)
        {
            if (args.Length < 1)
            {
                PrintUsage();
                return 1;
            }

            bool encode = false;
            bool phase1 = false;
            string password = null;
            int chunkSize = 524288;
            string inputPath = null;
            string outputPath = null;

            int i = 0;
            while (i < args.Length)
            {
                switch (args[i].ToLowerInvariant())
                {
                    case "--encode":
                        encode = true;
                        break;
                    case "--phase1":
                        phase1 = true;
                        break;
                    case "--password":
                        if (i + 1 >= args.Length) { Console.Error.WriteLine("--password requires a value"); return 1; }
                        password = args[++i];
                        break;
                    case "--chunk-size":
                        if (i + 1 >= args.Length) { Console.Error.WriteLine("--chunk-size requires a value"); return 1; }
                        if (!int.TryParse(args[++i], out chunkSize) || chunkSize < 1)
                        { Console.Error.WriteLine("Invalid chunk size"); return 1; }
                        break;
                    default:
                        if (inputPath == null) inputPath = args[i];
                        else if (outputPath == null) outputPath = args[i];
                        else { Console.Error.WriteLine("Unexpected argument: {0}", args[i]); return 1; }
                        break;
                }
                i++;
            }

            if (inputPath == null)
            {
                PrintUsage();
                return 1;
            }

            if (!File.Exists(inputPath))
            {
                Console.Error.WriteLine("File not found: {0}", inputPath);
                return 1;
            }

            try
            {
                if (encode)
                {
                    if (password == null)
                    {
                        uint randomPwd = (uint)System.Random.Shared.NextInt64(0x100000000);
                        password = randomPwd.ToString("x8");
                        Console.WriteLine("Password: {0}", password);
                    }

                    byte[] plaintext = File.ReadAllBytes(inputPath);
                    byte[] fmlData = FmlDecryptor.Encode(plaintext, password, chunkSize, phase1);

                    outputPath = outputPath ?? Path.ChangeExtension(inputPath, null) + ".fml";
                    File.WriteAllBytes(outputPath, fmlData);

                    Console.WriteLine("Encoded {0} bytes -> {1} bytes", plaintext.Length, fmlData.Length);
                    Console.WriteLine("Output: {0}", outputPath);
                }
                else
                {
                    byte[] fmlData = File.ReadAllBytes(inputPath);
                    byte[] result = FmlDecryptor.Decrypt(fmlData);

                    outputPath = outputPath ?? Path.ChangeExtension(inputPath, null) + "_decoded.dat";
                    File.WriteAllBytes(outputPath, result);

                    Console.WriteLine("Decoded {0} bytes -> {1} bytes", fmlData.Length, result.Length);
                    Console.WriteLine("Output: {0}", outputPath);
                }
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("ERROR: {0}", ex.Message);
                return 1;
            }
        }

        private static void PrintUsage()
        {
            Console.Error.WriteLine("Usage:");
            Console.Error.WriteLine("  Decode: FmlDecoder.Reference sample.fml [output_path]");
            Console.Error.WriteLine("  Encode: FmlDecoder.Reference --encode input.dat [output.fml] [--password hex] [--chunk-size N] [--phase1]");
            Console.Error.WriteLine();
            Console.Error.WriteLine("Options:");
            Console.Error.WriteLine("  --password    8-char hex password for encoding (default: random)");
            Console.Error.WriteLine("  --chunk-size  Chunk size in bytes for encoding (default: 524288)");
            Console.Error.WriteLine("  --template    Copy 128-byte file header from an existing .fml file");
        }
    }
}
