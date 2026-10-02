using System.Text.Json;
using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.Repository.Helpers;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Utils;

if (args.Length is not (5 or 6))
    throw new ArgumentException("PRIVATE_CONFIG OUTPUT MLDSA_PRIVATE_KEY TARGET PORT [DNS_TARGET]");

var output = Path.GetFullPath(args[1]);
Directory.CreateDirectory(output);
if (!OperatingSystem.IsWindows())
    File.SetUnixFileMode(output, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
using var configJson = JsonDocument.Parse(File.ReadAllText(args[0]));
string appId = configJson.RootElement.GetProperty("app_id").GetString()!;
string authKey = configJson.RootElement.GetProperty("auth_key").GetString()!;
string target = args[3];
if (target.Length is < 1 or > 253 || target.Any(char.IsWhiteSpace))
    throw new ArgumentException("TARGET must be one hostname or IPv4 address");
if (!ushort.TryParse(args[4], out ushort port) || port == 0)
    throw new ArgumentException("PORT must be from 1 through 65535");
string registryPath = Path.GetFullPath("firmware/main/service-hints.csv");
if (!File.Exists(registryPath))
    throw new ArgumentException("Run the fixture generator from the repository root");
string portService = File.ReadLines(registryPath)
    .Where(line => !line.StartsWith('#'))
    .Select(line => line.Split(','))
    .Where(fields => fields.Length == 2 && fields[0] == port.ToString())
    .Select(fields => fields[1]).FirstOrDefault() ?? "unknown";
string? dnsTarget = args.Length == 6 ? args[5] : null;

var signingConfig = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
    ["AuthKeySigning:PrivateKeyPath"] = args[2], ["AuthKeySigning:OpenSslPath"] = "/usr/bin/openssl"
}).Build();
var signer = new BackendMessageSignatureService(signingConfig, NullLogger.Instance);
string routingId = ProcessorRabbitTopology.GetRoutingId(appId);
string runId = Guid.NewGuid().ToString("N");
var cases = new List<(string Name, string Arguments, bool Success, string Expected)> {
    ("single-target-default", target, true, "Nmap scan report for"),
    ("tcp-connect-explicit-port", $"-sT -p {port} {target}", true, $"{port}/tcp"),
    ("fast-mode-explicit-port", $"-F -p {port} {target}", true, $"{port}/tcp"),
    ("no-ping-open-filter", $"-Pn --open -p {port} {target}", true, $"{port}/tcp open"),
    ("reason-and-verbose", $"-v --reason -p {port} {target}", true, "REASON"),
    ("service-version-hint", $"-sV -p {port} {target}", true, portService),
    ("comma-separated-ports", $"-p {port},{Math.Min(port + 1, ushort.MaxValue)} {target}", true, $"{port}/tcp open"),
    ("tcp-port-range", $"-p {port}-{Math.Min(port + 1, ushort.MaxValue)} {target}", true, $"{port}/tcp open"),
    ("unsupported-nse", $"--script vuln {target}", false, "unsupported")
};
cases.Add(("fast-default-ports", $"-F {target}", true, "Nmap scan report for"));
cases.Add(("conflicting-discovery-options", $"-sn -sT {target}", false, "Invalid or unsupported"));
cases.Add(("empty-token", $"\"\" {target}", false, "Invalid or unsupported"));
cases.Add(("expanded-service-ldap", $"-Pn -sV -p 389,{port} {target}", true, "ldap"));
cases.Add(("expanded-service-submissions", $"-Pn -sV -p 465,{port} {target}", true, "submissions"));
cases.Add(("expanded-service-mqtt-tls", $"-Pn -sV -p 8883,{port} {target}", true, "secure-mqtt"));
cases.Add(("service-registry-first-port", $"-Pn -sV -p 1,{port} {target}", true, "tcpmux"));
cases.Add(("service-registry-last-port", $"-Pn -sV -p 49150,{port} {target}", true, "inspider"));
cases.Add(("dynamic-service-unknown", $"-Pn -sV -p 65535,{port} {target}", true, "unknown"));
if (IPAddress.TryParse(target, out var targetAddress) && targetAddress.AddressFamily ==
    System.Net.Sockets.AddressFamily.InterNetwork) {
    byte[] octets = targetAddress.GetAddressBytes();
    cases.Add(("fresh-local-arp", $"-sn -PR --reason {target}", true, "arp-response"));
    cases.Add(("arp-before-tcp", $"-PR -p {port} {target}", true, $"{port}/tcp open"));
    cases.Add(("arp-off-link-rejected", "-sn -PR 192.0.2.1", false, "local"));
    string subnet = $"{octets[0]}.{octets[1]}.{octets[2]}.0/24";
    string oversizedSubnet = $"{octets[0]}.{octets[1]}.0.0/23";
    cases.Add(("bounded-cidr-host-discovery", $"-sn {subnet}", true,
        "Nmap done: 254 IP addresses"));
    cases.Add(("discovery-cancel", $"-sn {subnet}", false, "cancel"));
    cases.Add(("cidr-over-device-limit", $"-sn {oversizedSubnet}", false,
        "Invalid or unsupported embedded Nmap arguments"));
}
if (dnsTarget != null)
    cases.Add(("system-dns", $"--system-dns -p {port} {dnsTarget}", true, $"{port}/tcp open"));

foreach (var (name, arguments, expectedSuccess, expectedText) in cases) {
    var message = new ProcessorScanDataObj {
        AgentID = appId,
        AuthKey = authKey,
        Type = "Nmap",
        Arguments = arguments,
        LineLimit = -2,
        MessageID = "nmap-" + runId + "-" + name,
        CallingService = "llmServiceRanScanCommand",
        TimeoutSeconds = 60,
        LlmServiceObj = new LLMServiceObj { MessageID = "nmap-live-test-root" }
    };
    message.BackendSignature = await signer.SignAsync("processorCommand", routingId, message);
    var cloud = new CloudEvent { type = "ProcessorScanDataObj", data = message };
    string path = Path.Combine(output, name + ".json");
    await File.WriteAllTextAsync(path, JsonSerializer.Serialize(cloud));
    if (!OperatingSystem.IsWindows())
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    string expectationPath = Path.Combine(output, name + ".expect.json");
    Dictionary<string, string>? services = name switch {
        "service-version-hint" => new() { [$"{port}/tcp"] = portService },
        "expanded-service-ldap" => new() { ["389/tcp"] = "ldap" },
        "expanded-service-submissions" => new() { ["465/tcp"] = "submissions" },
        "expanded-service-mqtt-tls" => new() { ["8883/tcp"] = "secure-mqtt" },
        "service-registry-first-port" => new() { ["1/tcp"] = "tcpmux" },
        "service-registry-last-port" => new() { ["49150/tcp"] = "inspider" },
        "dynamic-service-unknown" => new() { ["65535/tcp"] = "unknown" },
        _ => null
    };
    await File.WriteAllTextAsync(expectationPath, JsonSerializer.Serialize(new {
        success = expectedSuccess, contains = expectedText, services
    }));
    if (!OperatingSystem.IsWindows())
        File.SetUnixFileMode(expectationPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    if (name == "discovery-cancel") {
        message.Arguments = "";
        message.BackendSignature = string.Empty;
        message.BackendSignature = await signer.SignAsync("cancelCommand", routingId, message);
        string cancelPath = Path.Combine(output, "cancel-request.json");
        await File.WriteAllTextAsync(cancelPath, JsonSerializer.Serialize(cloud));
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(cancelPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
}

Console.WriteLine($"Generated {cases.Count} signed Nmap fixtures; secret values hidden.");
