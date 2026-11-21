# [Brian Dobrott] - Assignment 8 Unit Tests
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'code')))
from solution import aggregate_pcap_traffic

# Fixed test fixture
mock_records = [
    {"src": "192.168.1.15", "dst": "8.8.8.8", "proto": "udp", "syn_flag": False},
    {"src": "192.168.1.15", "dst": "142.250.190.46", "proto": "tcp", "syn_flag": True},
    {"src": "192.168.1.20", "dst": "8.8.8.8", "proto": "udp", "syn_flag": False},
]

result = aggregate_pcap_traffic(mock_records)

# Test 1: Verify protocol count dictionary
assert result["protocols"] == {"UDP": 2, "TCP": 1}, "Failed Test 1: Protocol counts mismatch"

# Test 2: Verify unique destinations is a sorted list
assert result["unique_sources"] == ["192.168.1.15", "192.168.1.20"], "Failed Test 2: Must be a sorted list"

# Test 3: Empty capture handling
empty_result = aggregate_pcap_traffic([])
assert empty_result["protocols"] == {}, "Failed Test 3: Check dictionary keys"

assert result["total_syn_packets"] == 1, "Failed test 4: SYN packet count mismatch"

print("ALL UNIT TESTS PASSED - ASSIGNMENT 8")