from pcapng import FileScanner
from scapy.all  import *
from collections import defaultdict
import networkx as nx

packets = rdpcap('data.pcap')
d = defaultdict(list)
graph = nx.Graph()

for packet in packets:
    graph.add_node(packet.src)
    graph.add_node(packet.dst)
    graph.add_edge(packet.src, packet.dst)
    #d[packet.src].append(packet.dst)
    #d[packet.dst].append(packet.src)

#for key, value in d.items():
#    print(key, ":", value)
nx.draw(graph, with_labels=True)
plt.savefig("sample.png")
plt.show()
