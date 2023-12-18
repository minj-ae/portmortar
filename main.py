import socket
import argparse
import asyncio
from concurrent.futures import ThreadPoolExecutor

parser = argparse.ArgumentParser()

parser.add_argument('--target', required=True, help='target ip')
parser.add_argument('--port', required=True, help='port range')

args = parser.parse_args()

async def scan_port(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = await loop.run_in_executor(None, s.connect_ex, (host, port))
        if result == 0:
            print(f"Port {port} is open")
        s.close()
    except Exception as e:
        pass

async def scan(host, port_range):
    if '-' in port_range:
        start, end = map(int, port_range.split('-'))
        port_range = range(start, end + 1)
    else:
        port_range = [int(port_range)]

    tasks = [scan_port(host, port) for port in port_range]
    await asyncio.gather(*tasks)

async def main():
    await scan(args.target, args.port)

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()
