using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkMonitor.Objects;

if (args.Length is < 2 or > 3 || (args.Length == 3 && args[2] != "--check"))
    throw new ArgumentException("Usage: JsonParity <NetworkMonitorLib root> <output directory> [--check]");

string libRoot = Path.GetFullPath(args[0]);
string outputRoot = Path.GetFullPath(args[1]);
bool check = args.Length == 3;
// Deliberately not JsonSerializerDefaults.Web. These settings define this oracle profile.
var options = new JsonSerializerOptions
{
    WriteIndented = true,
    PropertyNameCaseInsensitive = false,
    NumberHandling = JsonNumberHandling.Strict,
    DefaultIgnoreCondition = JsonIgnoreCondition.Never
};
var generated = new Dictionary<string, string>(StringComparer.Ordinal);
void Require(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}
void Emit<T>(string name, T value)
{
    generated.Add(name, JsonSerializer.Serialize(value, options) + "\n");
}
void AssertRoundTrip<T>(T value)
{
    string json = JsonSerializer.Serialize(value, options);
    T? decoded = JsonSerializer.Deserialize<T>(json, options);
    Require(JsonSerializer.Serialize(decoded, options) == json, $"Round-trip mismatch for {typeof(T).Name}");
}

ulong[] ids = [0, 1, 2147483647, 2147483648, 2147483649, 4294967295,
    9007199254740992, 9007199254740993, ulong.MaxValue];
uint[] dates = [0, 1, 2147483647, 2147483648, 2147483649, uint.MaxValue];
ushort?[] times = [null, 0, 1, 65534, ushort.MaxValue];
var pings = ids.Select((id, index) => new PingInfo
{
    ID = id,
    DateSentInt = dates[index % dates.Length],
    Status = index % 2 == 0 ? null : "ok \"quoted\" \\ slash\n\t<>& café 😀",
    StatusID = index % 2 == 0 ? (ushort)0 : ushort.MaxValue,
    RoundTripTime = times[index % times.Length],
    RoundTripTimeInt = index % 2 == 0 ? int.MinValue : int.MaxValue,
    MonitorPingInfoID = index % 2 == 0 ? int.MinValue : int.MaxValue
}).ToArray();
var removals = ids.Select((id, index) => new RemovePingInfo
{
    ID = id, MonitorPingInfoID = index % 2 == 0 ? int.MinValue : int.MaxValue
}).ToArray();
var swaps = new[]
{
    new SwapMonitorPingInfo(),
    new SwapMonitorPingInfo { ID = int.MinValue, AppID = "" },
    new SwapMonitorPingInfo { ID = int.MaxValue, AppID = "agent-\"\\\n<>& café 😀" }
};
Emit("ping-info.json", pings);
Emit("remove-ping-info.json", removals);
Emit("swap-monitor-ping-info.json", swaps);
Emit("ping-params.json", new[] { new PingParams(), new PingParams
    { Timeout = int.MaxValue, AlertThreshold = int.MinValue, HostLimit = 1 } });
Emit("alert-flag-obj.json", new[] { new AlertFlagObj(), new AlertFlagObj
    { ID = int.MaxValue, AppID = "agent-<>& café 😀" } });
Emit("readiness-state.json", new[] { new ReadinessState(), new ReadinessState
    { IsReady = true, Reason = "ready\n\"yes\"" } });
foreach (var ping in pings)
{
    AssertRoundTrip(ping);
    var json = JsonSerializer.SerializeToElement(ping, options);
    Require(json.GetProperty("ID").GetUInt64() == ping.ID, "ulong precision lost");
    Require(json.GetProperty("DateSentInt").GetUInt32() == ping.DateSentInt, "uint precision lost");
    Require(json.GetProperty("DateSent").GetDateTime() ==
        new DateTime(2022, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(ping.DateSentInt), "DateSent epoch changed");
}
foreach (var item in removals) AssertRoundTrip(item);
foreach (var item in swaps) AssertRoundTrip(item);

var probes = new List<Probe>();
void Probe<T>(string name, string input, bool expectedAccepted, Action<T?>? assertion = null)
{
    try
    {
        T? value = JsonSerializer.Deserialize<T>(input, options);
        Require(expectedAccepted, $"{name}: unexpectedly accepted {input}");
        assertion?.Invoke(value);
        probes.Add(new(name, typeof(T).Name, input, true,
            JsonSerializer.SerializeToElement(value, options), null, null));
    }
    catch (JsonException exception)
    {
        Require(!expectedAccepted, $"{name}: unexpectedly rejected {input}: {exception.Message}");
        probes.Add(new(name, typeof(T).Name, input, false, null,
            nameof(JsonException), exception.Path));
    }
}
// Check every critical boundary independently of the representative serialization array.
foreach (ulong id in ids)
{
    string token = id.ToString(CultureInfo.InvariantCulture);
    Probe<PingInfo>($"ping-id-{token}", "{\"ID\":" + token + "}", true,
        value => Require(value!.ID == id, "PingInfo ID mismatch"));
    Probe<RemovePingInfo>($"remove-id-{token}", "{\"ID\":" + token + "}", true,
        value => Require(value!.ID == id, "RemovePingInfo ID mismatch"));
}
foreach (uint date in dates)
    Probe<PingInfo>($"date-{date}", "{\"DateSentInt\":" + date.ToString(CultureInfo.InvariantCulture) + "}", true,
        value => Require(value!.DateSentInt == date, "DateSentInt mismatch"));
foreach (ushort? time in times)
{
    string token = time?.ToString(CultureInfo.InvariantCulture) ?? "null";
    Probe<PingInfo>($"round-trip-time-{token}", "{\"RoundTripTime\":" + token + "}", true,
        value => Require(value!.RoundTripTime == time, "RoundTripTime mismatch"));
}
// Invalid types, integer lexical forms, signedness and overflow; inputs remain strings
// so downstream consumers can parse the original token without a double conversion.
string[] invalidNumeric = ["\"1\"", "true", "{}", "[]", "1.0", "1e0"];
foreach (string field in new[] { "ID", "DateSentInt", "StatusID", "RoundTripTime", "MonitorPingInfoID" })
    foreach (var (token, index) in invalidNumeric.Select((token, index) => (token, index)))
        Probe<PingInfo>($"ping-{field}-invalid-type-{index}", "{\"" + field + "\":" + token + "}", false);
foreach (var (field, tokens) in new (string, string[])[]
{
    ("ID", ["-1", "18446744073709551616", "null"]),
    ("DateSentInt", ["-1", "4294967296", "null"]),
    ("StatusID", ["-1", "65536", "null"]),
    ("RoundTripTime", ["-1", "65536"]),
    ("MonitorPingInfoID", ["-2147483649", "2147483648", "null"])
})
    foreach (var (token, index) in tokens.Select((token, index) => (token, index)))
        Probe<PingInfo>($"ping-{field}-out-of-range-{index}", "{\"" + field + "\":" + token + "}", false);
foreach (var (token, index) in invalidNumeric.Concat(new[] { "-1", "18446744073709551616", "null" })
    .Select((token, index) => (token, index)))
    Probe<RemovePingInfo>($"remove-invalid-id-{index}", "{\"ID\":" + token + "}", false);
foreach (string token in new[] { "2147483648", "2147483649", "4294967295", "9007199254740992",
    "9007199254740993", "18446744073709551615", "-2147483649" })
    Probe<SwapMonitorPingInfo>($"swap-id-overflow-{token}", "{\"ID\":" + token + "}", false);
Probe<SwapMonitorPingInfo>("swap-min", "{\"ID\":-2147483648}", true);
Probe<SwapMonitorPingInfo>("swap-max", "{\"ID\":2147483647}", true);
Probe<SwapMonitorPingInfo>("swap-numeric-app-id", "{\"AppID\":123}", false);
Probe<SwapMonitorPingInfo>("swap-null-app-id", "{\"AppID\":null}", true,
    value => Require(value!.AppID is null, "Default STJ nullable annotation handling changed"));
Probe<PingInfo>("ping-defaults", "{}", true);
Probe<RemovePingInfo>("remove-defaults", "{}", true);
Probe<SwapMonitorPingInfo>("swap-defaults", "{}", true);
Probe<PingInfo>("ping-null-root", "null", true, value => Require(value is null, "Expected null root"));
Probe<PingInfo>("ping-array-root", "[]", false);
Probe<PingInfo>("ping-number-root", "1", false);
Probe<PingInfo>("ping-numeric-status", "{\"Status\":1}", false);
Probe<PingInfo>("ping-trailing-comma", "{\"ID\":1,}", false);
Probe<PingInfo>("ping-comment", "{/*comment*/\"ID\":1}", false);
Probe<PingInfo>("ping-wrong-case", "{\"id\":42}", true,
    value => Require(value!.ID == 0, "Property matching should be case-sensitive"));
Probe<PingInfo>("ping-unknown-property", "{\"ID\":1,\"Unknown\":42}", true);
Probe<PingInfo>("ping-duplicate-id", "{\"ID\":1,\"ID\":9007199254740993}", true,
    value => Require(value!.ID == 9007199254740993, "Last duplicate property should win"));
Probe<PingInfo>("ping-date-int-last", "{\"DateSent\":\"2022-01-01T00:00:01Z\",\"DateSentInt\":2}", true,
    value => Require(value!.DateSentInt == 2, "DateSentInt setter should win"));
Probe<PingInfo>("ping-date-last", "{\"DateSentInt\":2,\"DateSent\":\"2022-01-01T00:00:01Z\"}", true,
    value => Require(value!.DateSentInt == 1, "DateSent setter should win"));
Probe<PingParams>("params-defaults", "{}", true);
Probe<PingParams>("params-timeout-overflow", "{\"Timeout\":2147483648}", false);
Probe<AlertFlagObj>("alert-defaults", "{}", true);
Probe<AlertFlagObj>("alert-id-overflow", "{\"ID\":2147483648}", false);
Probe<ReadinessState>("readiness-defaults", "{}", true);
Probe<ReadinessState>("readiness-string-bool", "{\"IsReady\":\"true\"}", false);
Require(probes.Select(p => p.Name).Distinct().Count() == probes.Count, "Duplicate probe names");
Emit("deserialization-cases.json", probes);

string Git(params string[] arguments)
{
    var start = new ProcessStartInfo("git") { RedirectStandardOutput = true, RedirectStandardError = true };
    start.ArgumentList.Add("-C");
    start.ArgumentList.Add(libRoot);
    foreach (string argument in arguments) start.ArgumentList.Add(argument);
    using var process = Process.Start(start)!;
    string result = process.StandardOutput.ReadToEnd().TrimEnd();
    string error = process.StandardError.ReadToEnd();
    process.WaitForExit();
    Require(process.ExitCode == 0, $"git failed: {error}");
    return result;
}
string[] sources = ["Objects/PingInfo.cs", "Objects/RemovePingInfo.cs", "Objects/SwapMonitorPingInfo.cs",
    "Objects/PingParams.cs", "Objects/AlertFlagObj.cs", "Objects/ReadyState.cs"];
Emit("manifest.json", new
{
    SchemaVersion = 1,
    Generator = "tests/dotnet/JsonParity",
    TargetFramework = "net10.0",
    RuntimeVersion = Environment.Version.ToString(),
    Serializer = "System.Text.Json",
    SerializerAssemblyVersion = typeof(JsonSerializer).Assembly.GetName().Version!.ToString(),
    Profile = new { PropertyNamingPolicy = "none (PascalCase CLR property names)",
        PropertyNameCaseInsensitive = false, NumberHandling = "Strict", DefaultIgnoreCondition = "Never",
        UnmappedMemberHandling = "Skip", RespectNullableAnnotations = false, AllowTrailingCommas = false,
        ReadCommentHandling = "Disallow", Encoder = "default", WriteIndented = true },
    SourceRepository = "NetworkMonitorLib (sibling checkout)",
    SourceCommit = Git("rev-parse", "HEAD"),
    SourceWorkingTreeStatus = Git(["status", "--porcelain", "--", .. sources]),
    Sources = sources.Select(path => new { Path = path,
        Sha256 = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(Path.Combine(libRoot, path)))) }).ToArray(),
    Files = generated.Keys.ToArray(),
    DeserializationCaseCount = probes.Count
});

// Validate all output before writing anything, or compare without changing fixtures.
if (check)
{
    var mismatches = generated.Where(pair => !File.Exists(Path.Combine(outputRoot, pair.Key)) ||
        File.ReadAllText(Path.Combine(outputRoot, pair.Key)) != pair.Value).Select(pair => pair.Key).ToArray();
    Require(mismatches.Length == 0, "Fixture drift: " + string.Join(", ", mismatches));
}
else
{
    Directory.CreateDirectory(outputRoot);
    foreach (var (name, content) in generated) File.WriteAllText(Path.Combine(outputRoot, name), content);
}
Console.WriteLine($"{(check ? "Verified" : "Generated")} {generated.Count} fixture files; {probes.Count} deserialization assertions passed.");

internal sealed record Probe(string Name, string Model, string Input, bool Accepted,
    JsonElement? Normalized, string? Exception, string? ExceptionPath);
