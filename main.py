import socket
import argparse
import asyncio

parser = argparse.ArgumentParser()

parser.add_argument('-S', '--scan-type', choices=['tcp', 'tcp-half'], default='tcp', help='scan type')
parser.add_argument('--target', required=True, help='target ip')
parser.add_argument('--port', required=True, help='port range')
parser.add_argument('--sleep', type=float, default=0.5, help='delay between port scans')

args = parser.parse_args()

async def scan_port(host, port, scan_type):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        if scan_type == 'tcp':
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            result = await loop.run_in_executor(None, s.connect_ex, (host, port))
            if result == 0:
                print(f"Port {port} is open")
                s.close()
        elif scan_type == 'tcp-half':
            s.connect((host, port))
            print(f"Port {port} is open")
            s.close()
    except Exception as e:
        pass

async def scan_with_delay(host, port_range, sleep_time, scan_type):
    if '-' in port_range:
        start, end = map(int, port_range.split('-'))
        port_range = range(start, end + 1)
    else:
        port_range = [int(port_range)]

    for port in port_range:
        await scan_port(host, port, scan_type)
        await asyncio.sleep(sleep_time)

async def main():
    await scan_with_delay(args.target, args.port, args.sleep, args.scan_type)

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()
