using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.Repository.Helpers;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Utils;

if (args.Length != 3) throw new ArgumentException("PRIVATE_CONFIG OUTPUT MLDSA_PRIVATE_KEY");
var output = Path.GetFullPath(args[1]);
Directory.CreateDirectory(output);
File.SetUnixFileMode(output, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
using var json = JsonDocument.Parse(File.ReadAllText(args[0]));
string appId = json.RootElement.GetProperty("app_id").GetString()!;
string authKey = json.RootElement.GetProperty("auth_key").GetString()!;
var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
    ["AuthKeySigning:PrivateKeyPath"] = args[2], ["AuthKeySigning:OpenSslPath"] = "/usr/bin/openssl"
}).Build();
var signer = new BackendMessageSignatureService(config, NullLogger.Instance);
string routingId = ProcessorRabbitTopology.GetRoutingId(appId);
foreach (var (name, operation, type, arguments) in new[] {
    ("list", "getCmdProcessorList", "QuantumCert", ""),
    ("help", "getCmdProcessorHelp", "QuantumCert", ""),
    ("pqc", "processorCommand", "QuantumCert", "--target quantum.readyforquantum.com --port 4433 --timeout 30000"),
    ("classical", "processorCommand", "QuantumCert", "--target 1.1.1.1 --timeout 30000"),
    ("invalid", "processorCommand", "QuantumCert", "--target example.com --port 999999"),
    ("timeout", "processorCommand", "QuantumCert", "--target 192.168.1.238 --port 45678 --timeout 1000"),
    ("cancel", "processorCommand", "QuantumCert", "--target 192.168.1.238 --port 45678 --timeout 30000"),
    ("cancel-request", "cancelCommand", "QuantumCert", ""),
    ("connect", "processorCommand", "QuantumConnect", "--target 1.1.1.1 --algorithms X25519MLKEM768 --timeout 30000"),
    ("connect-default", "processorCommand", "QuantumConnect", "--target 1.1.1.1 --timeout 30000"),
    ("scan", "processorCommand", "QuantumPortScanner", "--target 1.1.1.1 --ports 443 --timeout 30000"),
    ("scan-discovery", "processorCommand", "QuantumPortScanner", "--target 1.1.1.1 --timeout 30000"),
    ("info", "processorCommand", "QuantumInfo", "--algorithm kyber768"),
    ("info-broad", "processorCommand", "QuantumInfo", "--algorithm mlkem"),
    ("info-signature", "processorCommand", "QuantumInfo", "--algorithm dilithium3"),
    ("info-missing", "processorCommand", "QuantumInfo", "--algorithm notarealalgorithm"),
    ("openssl", "processorCommand", "Openssl", "s_client -connect quantum.readyforquantum.com:4433 -showcerts -groups MLKEM768:X25519MLKEM768"),
    ("openssl-unsupported", "processorCommand", "Openssl", "s_client -connect 1.1.1.1:443 -tls1_2"),
    ("openssl-groups", "processorCommand", "Openssl", "list -tls-groups"),
    ("openssl-verified", "processorCommand", "Openssl", "s_client -connect 1.1.1.1:443 -groups X25519 -verify_return_error"),
    ("nmap", "processorCommand", "Nmap", "-sT -Pn --open -p 45678 192.168.1.238"),
    ("nmap-range", "processorCommand", "Nmap", "-sT -Pn --open -p 45678-45679 192.168.1.238"),
    ("nmap-unsupported", "processorCommand", "Nmap", "--script vuln 192.168.1.238") }) {
    var message = new ProcessorScanDataObj {
        AgentID = appId, AuthKey = authKey, Type = type, Arguments = arguments,
        MessageID = "quantumcmd-test-" + (name == "cancel-request" ? "cancel" : name),
        CallingService = "llmServiceRanScanCommand", TimeoutSeconds = 60,
        LlmServiceObj = new LLMServiceObj { MessageID = "quantumcmd-test-root" }
    };
    message.BackendSignature = await signer.SignAsync(operation, routingId, message);
    var cloud = new CloudEvent { type = "ProcessorScanDataObj", data = message };
    string path = Path.Combine(output, name + ".json");
    await File.WriteAllTextAsync(path, JsonSerializer.Serialize(cloud));
    File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
}
Console.WriteLine("Signed original .NET ProcessorScanDataObj fixtures generated; values hidden.");
