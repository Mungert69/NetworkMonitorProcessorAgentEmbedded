"""Detect naming/default drift against original .NET command processors.

This checks contracts, not command execution. A missing reference checkout is
an explicit skip, never evidence of parity.
"""
from pathlib import Path
import re
import unittest
import json

ROOT = Path(__file__).resolve().parents[2]
LIB = ROOT.parent / "NetworkMonitorLib"
AGENT = ROOT.parent / "NetworkMonitorProcessorAgent"


class CmdProcessorContractTests(unittest.TestCase):
    def test_all_embedded_types_match_dotnet_catalog(self):
        directory = LIB / "Objects/Connection/CommandProcessors"
        if not directory.is_dir():
            self.skipTest("Sibling NetworkMonitorLib required")
        source = (ROOT / "firmware/main/cmd_processor_catalog.c").read_text()
        declared = re.search(r'types\[\]\s*=\s*\{([^}]+)', source).group(1)
        for name in re.findall(r'"([^"]+)"', declared):
            reference = (directory / (name + "CmdProcessor.cs")).read_text()
            self.assertRegex(reference, rf'class\s+{name}CmdProcessor\s*:')
        for processor, command, display in (("QuantumConnect", "quantum", "Quantum Security Check"),
                                            ("QuantumPortScanner", "quantum-scan", "Quantum Security Scanner")):
            reference = (directory / (processor + "CmdProcessor.cs")).read_text()
            self.assertRegex(reference, rf'"{command}",\s*"{display}"')
            self.assertIn('"' + command + '"', source)

    def test_quantum_algorithm_metadata_matches_dotnet(self):
        reference = ROOT.parent / "NetworkMonitorProcessorAgent/openssl/lib64/algo_info.json"
        if not reference.is_file():
            self.skipTest("Sibling .NET processor algorithm catalog required")
        header = (ROOT / "firmware/main/quantum_algorithm_data.h").read_text()
        records = [json.loads(json.loads(line.rstrip(","))) for line in
                   header.split("nm_quantum_algorithm_data[] = {", 1)[1].split("};", 1)[0].splitlines()
                   if line.strip()]
        self.assertEqual(records, json.loads(reference.read_text())["algorithms"])

    def test_quantum_connect_names_match_dotnet(self):
        directory = LIB / "Objects/Connection/CommandProcessors"
        reference = directory / "QuantumConnectCmdProcessor.cs"
        if not reference.is_file():
            self.skipTest("Sibling NetworkMonitorLib required for contract check")
        source = reference.read_text()
        header = (ROOT / "firmware/main/quantum_connect_cmd_processor.h").read_text()
        self.assertIn('"QuantumConnect"', header)
        self.assertRegex(source, r'"quantum",\s*"Quantum Security Check"')
        self.assertIn('#define NM_QUANTUM_CONNECT_CMD_NAME "quantum"', header)
        self.assertIn('#define NM_QUANTUM_CONNECT_DISPLAY_NAME "Quantum Security Check"', header)
        self.assertEqual(set(re.findall(r'Key\s*=\s*"([^"]+)"', source)),
                         {"target", "algorithms", "port", "timeout"})

    def test_quantum_cert_names_and_defaults_match_dotnet(self):
        directory = LIB / "Objects/Connection/CommandProcessors"
        reference = directory / "QuantumCertCmdProcessor.cs"
        if not reference.is_file():
            self.skipTest("Sibling NetworkMonitorLib required for contract check")
        source = reference.read_text()
        provider = (directory / "CmdProcessorProvider.cs").read_text()
        header = (ROOT / "firmware/main/quantum_cert_cmd_processor.h").read_text()
        strings = dict(re.findall(r'^#define (NM_\w+) "([^"]+)"$', header, re.M))
        numbers = dict(re.findall(r'^#define (NM_\w+) (\d+)$', header, re.M))
        processor_type = strings["NM_QUANTUM_CERT_PROCESSOR_TYPE"]
        self.assertRegex(source, rf'class\s+{re.escape(processor_type)}CmdProcessor\s*:')
        catalog = provider.split("_coreProcessorTypes = new()", 1)[1].split("};", 1)[0]
        self.assertIn(processor_type, re.findall(r'"([^"]+)"', catalog))
        for field, macro in (("CmdName", "NM_QUANTUM_CERT_CMD_NAME"),
                             ("CmdDisplayName", "NM_QUANTUM_CERT_DISPLAY_NAME")):
            actual = re.search(rf'\.{field}\s*=\s*"([^"]+)"', source)
            self.assertIsNotNone(actual)
            self.assertEqual(actual.group(1), strings[macro])
        self.assertEqual(set(re.findall(r'Key\s*=\s*"([^"]+)"', source)),
                         {strings[f"NM_QUANTUM_CERT_{arg}_ARGUMENT"]
                          for arg in ("TARGET", "PORT", "TIMEOUT")})
        port = re.search(r'const int DefaultPort\s*=\s*(\d+)', source)
        self.assertIsNotNone(port)
        self.assertEqual(port.group(1), numbers["NM_QUANTUM_CERT_DEFAULT_PORT"])
        timeout = re.search(r'Key\s*=\s*"timeout".*?DefaultValue\s*=\s*"(\d+)"',
                            source, re.S)
        self.assertIsNotNone(timeout)
        self.assertEqual(timeout.group(1), numbers["NM_QUANTUM_CERT_DEFAULT_TIMEOUT_MS"])

    def test_command_operations_match_dotnet_and_require_signatures(self):
        reference = AGENT / "Services/RabbitListener.cs"
        if not reference.is_file():
            self.skipTest("Sibling NetworkMonitorProcessorAgent required for contract check")
        operations = {"processorCommand", "cancelCommand", "getCmdProcessorHelp",
                      "getCmdProcessorList"}
        registered = set(re.findall(r'FuncName\s*=\s*"([^"]+)"', reference.read_text()))
        self.assertTrue(operations.issubset(registered))
        security = (ROOT / "firmware/main/command_security.c").read_text()
        self.assertTrue(operations.issubset(set(re.findall(r'"([^"]+)"', security))))
        subscriptions = (ROOT / "firmware/main/processor_mqtt.c").read_text()
        self.assertTrue(operations.issubset(set(re.findall(r'"([^"]+)"', subscriptions))))

    def test_reply_routes_match_dotnet_topology(self):
        reference = LIB / "Objects/Repository/Helpers/ProcessorMqttTopology.cs"
        if not reference.is_file():
            self.skipTest("Sibling NetworkMonitorLib required for topology check")
        source = reference.read_text()
        runtime = (ROOT / "firmware/main/processor_cmd.c").read_text()
        for name in ("ScanRan", "ScanAck"):
            route = re.search(rf'{name}\s*=\s*"([^"]+)"', source)
            self.assertIsNotNone(route)
            self.assertIn('"' + route.group(1).replace('.', '/') + '"', runtime)


if __name__ == "__main__":
    unittest.main()
