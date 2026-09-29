using System.IO.Compression;
using System.Text;
using NetworkMonitor.Utils;

if (args.Length != 1) throw new ArgumentException("Supply the C test vector directory");
var files = Directory.GetFiles(args[0], "*.br");
if (files.Length != 78) throw new Exception("Expected 78 generated test vectors");
foreach (var file in files)
{
    byte[] encoded = File.ReadAllBytes(file);
    byte[] expected = File.ReadAllBytes(Path.ChangeExtension(file, ".raw"));
    using var stream = new BrotliStream(new MemoryStream(encoded), CompressionMode.Decompress);
    using var decoded = new MemoryStream();
    stream.CopyTo(decoded);
    if (!expected.SequenceEqual(decoded.ToArray())) throw new Exception(file);
    // Exercise the actual shared backend helper, including its Base64 overload.
    string text = Encoding.UTF8.GetString(expected);
    if (StringCompressor.Decompress(encoded) != text ||
        StringCompressor.Decompress(Convert.ToBase64String(encoded)) != text)
        throw new Exception($"Backend helper mismatch: {file}");
}
Console.WriteLine("78 vectors decoded byte-for-byte; 156 shared backend helper checks passed");
