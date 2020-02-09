from pcapng import FileScanner
from scapy.all  import *
from collections import defaultdict
import networkx as nx
import json 

with open('data.json') as f:
    packets = json.load(f)
    graph = nx.Graph()
    color_map = []
    for packet in packets:
        if "tcp" in packet["_source"]["layers"].keys():
            if packet["_source"]["layers"]["tcp"]["tcp.seq"] == "1" and packet["_source"]["layers"]["tcp"]["tcp.ack"] == "1" and packet["_source"]["layers"]["tcp"]["tcp.len"] == "0":
                
                try:
                    graph.add_node(packet["_source"]["layers"]["ip"]["ip.src"])
                    graph.add_node(packet["_source"]["layers"]["ip"]["ip.dst"])
                    graph.add_edge(packet["_source"]["layers"]["ip"]["ip.dst"], packet["_source"]["layers"]["ip"]["ip.src"])
                except KeyError:
                    graph.add_node(packet["_source"]["layers"]["ipv6"]["ipv6.src"])
                    graph.add_node(packet["_source"]["layers"]["ipv6"]["ipv6.dst"])
                    graph.add_edge(packet["_source"]["layers"]["ipv6"]["ipv6.dst"], packet["_source"]["layers"]["ipv6"]["ipv6.src"])

nx.draw(graph, with_labels=True)
plt.savefig("sample.png")
