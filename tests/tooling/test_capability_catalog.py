"""Check shipped capability lists against the shared .NET catalogs."""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
LIB = ROOT.parent / "NetworkMonitorLib"
SUPPORTED = {"icmp", "dns", "rawconnect", "http", "httphtml", "https", "blebroadcast", "blebroadcastlisten", "quantum", "quantumcert", "nmap"}

class CapabilityCatalogTests(unittest.TestCase):
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
