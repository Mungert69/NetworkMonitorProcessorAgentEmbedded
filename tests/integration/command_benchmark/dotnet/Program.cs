using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.Repository;
using NetworkMonitor.Objects.Repository.Helpers;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Utils;

if (args.Length != 4) throw new ArgumentException("OUTPUT PROFILE APPID MLDSA_PRIVATE_KEY_PATH");
string output = Path.GetFullPath(args[0]), appId = args[2];
Directory.CreateDirectory(output);
using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
string keyPath = Path.Combine(output, "ephemeral-private.pem");
File.WriteAllText(keyPath, key.ExportPkcs8PrivateKeyPem());
File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
    ["ProcessorCommandSigning:PrivateKeyPath"] = keyPath,
    ["AuthKeySigning:PrivateKeyPath"] = args[3],
    ["AuthKeySigning:OpenSslPath"] = "/usr/bin/openssl"
}).Build();
var state = new ProcessorState();
state.ConcurrentProcessorList.Add(new ProcessorObj { AppID = appId, IsQuantumCapable = false });
var ecdsa = new EcdsaProcessorCommandSigner(config, state);
var mldsa = new BackendMessageSignatureService(config, NullLogger.Instance);
string target = ProcessorRabbitTopology.GetRoutingId(appId);
using var profile = JsonDocument.Parse(File.ReadAllText(args[1]));
var monitors = JsonSerializer.Deserialize<List<MonitorIP>>(profile.RootElement.GetProperty("MonitorIPs").GetRawText())!;
if (monitors.Count != 50) throw new InvalidOperationException("Exactly 50 hosts required");
for (int i = 0; i < monitors.Count; i++) {
    monitors[i].ID = 1900000000 + i; monitors[i].AppID = appId;
    monitors[i].Enabled = true; monitors[i].Timeout = 3000;
}
var init = new ProcessorInitObj { AppID = appId, AuthKey = "benchmark-only", MonitorIPs = monitors,
    TotalReset = true, PingParams = new PingParams() };
File.WriteAllText(Path.Combine(output, "public.pem"), key.ExportSubjectPublicKeyInfoPem());
File.WriteAllText(Path.Combine(output, "mldsa-public.pem"), BackendSigningTrustAnchor.PublicKeyPem);
File.WriteAllText(Path.Combine(output, "target.txt"), target);
foreach (int count in new[] { 0, 50 }) {
    init.MonitorIPs = monitors.Take(count).ToList();
    var envelope = ecdsa.Sign("processorInit", target, init);
    File.WriteAllText(Path.Combine(output, $"ecdsa-{count}.json"), JsonSerializer.Serialize(envelope));
    byte[] packed = BackendMessageSignaturePayload.Create("processorInit", target, init);
    File.WriteAllBytes(Path.Combine(output, $"payload-{count}.bin"), packed);
    init.BackendSignature = await mldsa.SignAsync("processorInit", target, init);
    var cloud = new CloudEvent { type = "ProcessorInitObj", data = init };
    File.WriteAllText(Path.Combine(output, $"mldsa-{count}.json"), JsonSerializer.Serialize(cloud));
    init.BackendSignature = "";
}
File.Delete(keyPath);
Console.WriteLine("Generated production .NET ECDSA/ML-DSA fixtures for 0 and 50 hosts (no credentials).");
