import argparse
import asyncio
from scapy.all import *
import socket
import networkx as nx
import matplotlib.pyplot as plt


parser = argparse.ArgumentParser()

parser.add_argument('-s', '--scan-type', nargs='+', choices=['S', 'N', 'X', 'A', 'U', 'T', 'TT'], default=['S'], help='scan type')
parser.add_argument('-t', '--target', required=True, help='target ip')
parser.add_argument('-p', '--port', required=True, help='port range')
parser.add_argument('--sleep', type=float, default=0.5, help='delay between port scans')
parser.add_argument('-v', '--verbose', action='store_true', help='display verbose output')

args = parser.parse_args()


async def work(host, port, scan_type, verbose):
    try:
        if 'T' in scan_type:
            response = sr1(IP(dst=host)/TCP(dport=int(port), flags="S"), timeout=0.5, verbose=verbose)
            if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                try:
                    service_name = socket.getservbyport(port)
                    return port, service_name, 'open'
                except:
                    return port, None, 'open'   
            else:
                return port, None, 'closed'
        elif 'S' in scan_type:
            response = sr1(IP(dst=host)/TCP(dport=int(port), flags="S"), timeout=0.5, verbose=verbose)
            if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                send(IP(dst=host)/TCP(dport=int(port), flags="R"), verbose=verbose)
                try:
                    service_name = socket.getservbyport(port)
                    return port, service_name, 'open'
                except:
                    return port, None, 'open'   
            else:
                return port, None, 'closed'
        elif 'U' in scan_type:
            response = sr1(IP(dst=host)/UDP(dport=int(port)), timeout=0.5, verbose=verbose)
            if response and response.haslayer(UDP):
                try:
                    service_name = socket.getservbyport(port)
                    return port, service_name, 'open'
                except:
                    return port, None, 'open'   
            else:
                return port, None, 'closed'
        elif 'N' in scan_type:
            response = sr1(IP(dst=host)/TCP(dport=int(port), flags=""), timeout=0.5, verbose=verbose)
            if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                try:
                    service_name = socket.getservbyport(port)
                    return port, service_name, 'open'
                except:
                    return port, None, 'open'   
            else:
                return port, None, 'closed'
        elif 'X' in scan_type:
            response = sr1(IP(dst=host)/TCP(dport=int(port), flags="FPU"), timeout=0.5, verbose=verbose)
            if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                try:
                    service_name = socket.getservbyport(port)
                    return port, service_name, 'open'
                except:
                    return port, None, 'open'   
            else:
                return port, None, 'closed'
        elif 'A' in scan_type:
            response = sr1(IP(dst=host)/TCP(dport=int(port), flags="A"), timeout=0.5, verbose=verbose)
            if response and response.haslayer(TCP):
                try:
                    service_name = socket.getservbyport(port)
                    return port, service_name, 'open'
                except:
                    return port, None, 'open'   
            else:
                return port, None, 'closed'
        elif 'TT' in scan_type:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((host, int(port)))
            if result == 0:
                try:
                    service_name = socket.getservbyport(port)
                    s.close()
                    return port, service_name, 'open'
                except:
                    s.close()
                    return port, None, 'open'   
            else:
                return port, None, 'closed'
    except Exception as e:
        return port, None, 'closed'

async def scan(host, port_range, sleep_time, scan_type, verbose):
    open_ports = []
    closed_ports = []
    network_graph = nx.Graph()
    if '-' in port_range:
        start, end = map(int, port_range.split('-'))
        port_range = range(start, end + 1)
    else:
        port_range = [int(port_range)]

    for port in port_range:
        result = await work(host, port, scan_type, verbose)
        if result[2] == 'open':
            network_graph.add_node(host) 
            network_graph.add_node(port)
            network_graph.add_edge(host, port)
            network_graph.add_edge(port, args.target) 
            open_ports.append(result)
        else:
            closed_ports.append(result)
        await asyncio.sleep(sleep_time)

    print("Scan report target", args.target)
    print("---------------------------------------------")
    print("PORT\tSTATE")
    print("---------------------------------------------")

    for port_info in sorted(open_ports + closed_ports):
        port, service_name, state = port_info
        if service_name:
            print(f"{port}/tcp\t{service_name}\t{state}")
        else:
            print(f"{port}/tcp\tunknown\t{state}")

    nx.draw(network_graph, with_labels=True, node_color='skyblue', node_size=800, font_weight='bold', font_size=12)
    plt.show()


async def main():
    await scan(args.target, args.port, args.sleep, args.scan_type, args.verbose)

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()
