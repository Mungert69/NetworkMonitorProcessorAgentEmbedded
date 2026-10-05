using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using NetworkMonitor.Connection;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.Factory;

// Execute the real sibling library. No network, broker, radio or credentials.
string root = Path.GetFullPath(args[0]);
string target = Path.GetFullPath(args[1]);
using var http = new HttpClient();
string[] supported = ["icmp", "dns", "rawconnect", "http", "httphtml", "https",
    "quantum", "quantumcert", "nmap", "blebroadcast", "blebroadcastlisten"];
var durationCases = supported.Select(type => {
    var connect = (NetConnect)EndPointTypeFactory.CreateNetConnect(type, http, http, [], "", "", NullLogger.Instance);
    // Targeted BLE currently sets ExtendTimeout at Connect entry; the absent
    // provider exits before any I/O, but executes that real configuration path.
    if (type == "blebroadcast") connect.Connect().GetAwaiter().GetResult();
    bool extended = (bool)typeof(NetConnect).GetProperty("ExtendTimeout", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(connect)!;
    int multiplier = extended ? (int)typeof(NetConnect).GetProperty("ExtendTimeoutMultiplier", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(connect)! : 1;
    var measurement = EndpointMeasurementDefaults.Get(type);
    connect.Cts.Dispose();
    long[] elapsed = [0, 1, 9, 10, 59_000, 70_009, 590_000];
    return new { Type = type, measurement.Unit, measurement.Scale, measurement.Offset,
        measurement.AnalysisKind, measurement.TimingRatingThresholds, TimeoutMultiplier = multiplier,
        Samples = elapsed.Select(ms => new { Elapsed = ms, Sample = unchecked((ushort)(ms / (long)measurement.Scale)) }).ToArray() };
}).ToArray();

var bleCases = new List<object>();
void AddBle(string name, string format, string payloadType, string payload, string metric, string key = "", string address = "AA:BB:CC:DD:EE:FF") {
    var decoder = BlePayloadDecoderRegistry.Default.Find(format)!;
    bool ok = decoder.TryDecodeReadings(new BlePayload(address, payloadType, Convert.FromHexString(payload)),
        Convert.FromHexString(key), out var decoded, out _);
    var readings = decoded.Readings.Where(r => r.Metric == BleMetricSelector.Canonical(metric)).ToArray();
    ushort sample = 0;
    bool encoded = ok && readings.Length == 1 && readings[0].Value.HasValue &&
        BleMetricCatalogue.Find(format, metric)!.TryEncode(readings[0].Value!.Value, out sample);
    bleCases.Add(new { Name = name, Format = format, PayloadType = payloadType, Payload = payload,
        Address = address, Key = key, Metric = metric, DecodeOk = ok, Matches = readings.Length,
        Value = readings.Length == 1 ? readings[0].Value : null, Encoded = encoded, Sample = sample });
}
AddBle("ruuvi-temperature", "ruuvi", "raw_input", "0512FC5394C37C0004FFFC040CAC364200CDCBB8334C884F", "temperature");
AddBle("ruuvi-pressure", "ruuvi", "raw_input", "0512FC5394C37C0004FFFC040CAC364200CDCBB8334C884F", "pressure");
AddBle("bthome-temperature", "bthome", "raw_input", "D2FC4002C409037713", "temperature");
AddBle("bthome-negative", "bthome", "raw_input", "40020CFE", "temperature");
AddBle("bthome-repeat", "bthome", "raw_input", "4002C409020CFE", "temperature_2");
AddBle("bthome-truncated", "bthome", "raw_input", "4002C4", "temperature");
AddBle("bthome-encrypted", "bthome", "raw_input", "D2FC41E445F3C9962B332211006C7C4519", "temperature",
    "231D39C1D7CC1AB1AEE224CD096DB932", "54:48:E6:8F:80:A5");
AddBle("bthome-wrong-address", "bthome", "raw_input", "D2FC41E445F3C9962B332211006C7C4519", "temperature",
    "231D39C1D7CC1AB1AEE224CD096DB932", "54:48:E6:8F:80:A6");
// Independent public/synthetic solar vector; framing and decoder are real .NET code.
string solarKey = "A00102030405060708090A0B0C0D0E0F";
using var aes = Aes.Create();
aes.Key = Convert.FromHexString(solarKey);
byte[] counter = new byte[16]; counter[0] = 0x34; counter[1] = 0x12;
byte[] stream = aes.EncryptEcb(counter, PaddingMode.None);
byte[] plain = Convert.FromHexString("0000D20419002C017B001E00");
string SolarPayload(byte[] data) => "013412A0" + Convert.ToHexString(data.Select((b, i) => (byte)(b ^ stream[i])).ToArray());
AddBle("victron-pv", "victron", "raw_input", SolarPayload(plain), "pv_power", solarKey);
AddBle("victron-voltage", "victron", "raw_input", SolarPayload(plain), "battery_voltage", solarKey);
plain[8] = 0xff; plain[9] = 0xff;
AddBle("victron-pv-unavailable", "victron", "raw_input", SolarPayload(plain), "pv_power", solarKey);

string[] sources = ["Objects/Factory/EndPointTypeFactory.cs", "Objects/Connection/NetConnect.cs",
    "Objects/Connection/EndpointMeasurementDefaults.cs", "Objects/Connection/NmapCmdConnect.cs",
    "Objects/Connection/BleBroadcastListenConnect.cs", "Objects/Connection/BleBroadcastConnect.cs",
    "Objects/Connection/HTTPConnect.cs", "Objects/Connection/DNSConnect.cs", "Objects/Connection/ICMPConnect.cs",
    "Objects/Connection/SocketConnect.cs", "Objects/Connection/QuantumConnect.cs", "Objects/Connection/QuantumCertConnect.cs"];
sources = sources.Concat(Directory.GetFiles(Path.Combine(root, "Objects/Connection/Ble"), "*.cs")
    .Select(p => Path.GetRelativePath(root, p))).Order(StringComparer.Ordinal).ToArray();
var httpStatuses = Enumerable.Range(100, 900).Select(code => new { Code = code, Status = ((System.Net.HttpStatusCode)code).ToString() }).ToArray();
var hashes = sources.ToDictionary(p => p, p => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(root, p)))));
string json = JsonSerializer.Serialize(new { SourceHashes = hashes, DurationCases = durationCases, BleCases = bleCases, HttpStatuses = httpStatuses },
    new JsonSerializerOptions { WriteIndented = true }) + "\n";
if (args.Contains("--check")) {
    if (!File.Exists(target) || File.ReadAllText(target) != json) throw new Exception("Endpoint fixtures changed; review .NET/C behavior before regenerating.");
} else File.WriteAllText(target, json);
Console.WriteLine($"Endpoint oracle: {durationCases.Length} policies and {bleCases.Count} actual decoder cases {(args.Contains("--check") ? "match" : "generated")}.");
