# [Brian Dobrott] - Assignment 8
import json

def aggregate_pcap_traffic(packet_list):

    report = {
        "protocols": {},
        "unique_sources": [],
        "total_syn_packets": 0
    }

    unique_srcs = set()

    for pkt in packet_list:

        # TODO: Safely extract proto and dst from packet dictionary
        proto = pkt.get("proto", "UNKNOWN").upper()
        report["protocols"][proto] = report["protocols"].get(proto, 0) + 1
        
        src = pkt.get("src")

        if src:
            unique_srcs.add(src)

        # New line for counting SYN packets
        if pkt.get("syn_flag") is True:
            report["total_syn_packets"] += 1

    # Error: Storing raw set instead of sorted list
    report["unique_sources"] = sorted(unique_srcs)
    return report

# Execution on your live Wireshark capture
if __name__ == "__main__":
    with open("capture.json", "r") as f:
        data = json.load(f)
    # Handles both raw packet lists and Wireshark's nested JSON layers
    summary = aggregate_pcap_traffic(data)
    print("LIVE CAPTURE SUMMARY:")
    print(summary)