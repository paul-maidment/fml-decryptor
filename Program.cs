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
                Console.Error.WriteLine("Usage: FmlDecoder.Reference sample.fml [output_path]");
                Console.Error.WriteLine("  If output_path is omitted, writes to sample_decoded.dat");
                return 1;
            }

            string fmlPath = args[0];
            if (!File.Exists(fmlPath))
            {
                Console.Error.WriteLine("File not found: {0}", fmlPath);
                return 1;
            }

            try
            {
                byte[] fmlData = File.ReadAllBytes(fmlPath);
                byte[] result = FmlDecryptor.Decrypt(fmlData);

                string outPath = args.Length >= 2
                    ? args[1]
                    : Path.ChangeExtension(fmlPath, null) + "_decoded.dat";

                File.WriteAllBytes(outPath, result);

                Console.WriteLine("Decoded {0} bytes -> {1} bytes", fmlData.Length, result.Length);
                Console.WriteLine("Output: {0}", outPath);
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("ERROR: {0}", ex.Message);
                return 1;
            }
        }

    }
}
