"""Check shipped capability lists against the shared .NET catalogs."""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
LIB = ROOT.parent / "NetworkMonitorLib"
SUPPORTED = {"icmp", "dns", "rawconnect", "http", "httphtml", "https", "blebroadcast", "blebroadcastlisten", "quantum", "quantumcert", "nmap"}

class CapabilityCatalogTests(unittest.TestCase):
    def test_supported_endpoints_have_current_contract_fixtures(self):
        fixture = json.loads((ROOT / "tests/fixtures/endpoint-contracts.json").read_text())
        self.assertEqual({entry["Type"] for entry in fixture["DurationCases"]}, SUPPORTED)
        dispatch = (ROOT / "firmware/main/endpoints.c").read_text().split("nm_esp_result nm_esp_endpoint_run", 1)[0]
        self.assertEqual(set(re.findall(r'strcmp\(type, "([^"]+)"\)', dispatch)), SUPPORTED)
        snapshot = LIB / "Objects/Connection/Ble/metric-encodings-v2.json"
        if snapshot.is_file():
            self.assertEqual((ROOT / "tests/fixtures/ble-metric-encodings-v2.json").read_bytes(),
                             snapshot.read_bytes())

    def test_templates_match_runtime_defaults(self):
        header = (ROOT / "firmware/main/nm_capability_defaults.h").read_text()
        defaults = {}
        for name, literal in re.findall(r'^#define (NM_DISABLED_\w+_JSON) (".*")$', header, re.M):
            defaults[name] = json.loads(json.loads(literal))
        directory = ROOT / "firmware/config"
        for environment in ("dev", "live"):
            settings = json.loads((directory / f"appsettings-{environment}.json").read_text())
            # BLE is compiled into the main firmware profile, so it must not
            # be an explicit appsettings restriction.
            endpoint_defaults = set(defaults["NM_DISABLED_ENDPOINTS_JSON"])
            endpoint_defaults.discard("blebroadcast")
            endpoint_defaults.discard("blebroadcastlisten")
            self.assertEqual(set(settings["DisabledEndpointTypes"]), endpoint_defaults)
            self.assertEqual(settings["DisabledCommands"], defaults["NM_DISABLED_COMMANDS_JSON"])
            self.assertFalse(SUPPORTED.intersection(settings["DisabledEndpointTypes"]))
        if not (LIB / "Objects/Factory/EndPointTypeFactory.cs").is_file():
            self.skipTest("Sibling NetworkMonitorLib needed for catalog drift check")
        factory = (LIB / "Objects/Factory/EndPointTypeFactory.cs").read_text()
        endpoints = set(re.findall(r'new EndpointType\(\s*"([^"]+)"', factory))
        self.assertEqual(endpoints - SUPPORTED,
                         set(defaults["NM_DISABLED_ENDPOINTS_JSON"]) -
                         {"blebroadcast", "blebroadcastlisten"})
        provider = (LIB / "Objects/Connection/CommandProcessors/CmdProcessorProvider.cs").read_text()
        core = provider.split("_coreProcessorTypes = new()", 1)[1].split("};", 1)[0]
        commands = {x.lower() for x in re.findall(r'"([^"]+)"', core)}
        self.assertFalse(commands - {"quantumcert", "quantumconnect", "quantumportscanner", "quantuminfo", "openssl", "nmap"} - set(defaults["NM_DISABLED_COMMANDS_JSON"]))
        self.assertNotIn("quantumcert", defaults["NM_DISABLED_COMMANDS_JSON"])
        self.assertNotIn("quantum-cert", defaults["NM_DISABLED_COMMANDS_JSON"])

if __name__ == "__main__":
    unittest.main()
