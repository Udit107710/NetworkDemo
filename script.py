from pcapng import FileScanner
from scapy.all  import *
from collections import defaultdict
import networkx as nx

packets = rdpcap('data.pcap')
d = defaultdict(list)
graph = nx.Graph()

for packet in packets:
    if IP in packet:
#        print(packet[IP].src, packet[IP].dst)
        graph.add_node(packet[IP].src)
        graph.add_node(packet[IP].dst)
        graph.add_edge(packet[IP].src, packet[IP].dst)

nx.draw(graph, with_labels=True)
plt.savefig("sample.png")
