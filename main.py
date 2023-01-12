import CloudFlare
import logging
import urllib.request
import ipaddress
import sys
import subprocess
import re
import argparse
from datetime import datetime, timezone, timedelta
import pathlib

# 时区
tz = timezone(timedelta(hours=8), 'CST')

# 日志
log_file = pathlib.Path(__file__).resolve().with_name('log') / f'{datetime.now(tz):%Y-%m-%d %H-%M-%S %Z}.log'
if not log_file.parent.exists():
    log_file.parent.mkdir()
logging.basicConfig(filename=log_file, encoding='utf-8', level=logging.DEBUG,
                    format='[%(asctime)s][%(levelname)s]: %(message)s')

# 公网IP缓存
cache_file = pathlib.Path(__file__).resolve().with_name('cache.txt')


class IPAddress:
    @staticmethod
    def get_public_ip():
        with urllib.request.urlopen('https://4.ipw.cn/') as f:
            ipv4 = ipaddress.IPv4Address(f.read().decode('ascii'))
        with urllib.request.urlopen('https://6.ipw.cn/') as f:
            ipv6 = ipaddress.IPv6Address(f.read().decode('ascii'))
        return ipv4, ipv6

    @staticmethod
    def get_interface_ip():
        if sys.platform == 'win32':
            out = subprocess.run(['powershell.exe', 'Get-NetIPAddress'], check=True, text=True,
                                 stdout=subprocess.PIPE).stdout
            return [ipaddress.ip_address(ip) for ip in re.findall('^IPAddress +: (.*?)$', out, re.MULTILINE)]
        else:
            ips = subprocess.run(['hostname', '--all-ip-addresses'], check=True, text=True,
                                 stdout=subprocess.PIPE).stdout.strip().split(' ')
            return [ipaddress.ip_address(ip) for ip in ips]

    @classmethod
    def get_interface_public_ip(cls):
        public_ips = set(cls.get_public_ip())
        interface_ips = set(cls.get_interface_ip())
        interface_public_ips = public_ips & interface_ips
        return interface_public_ips


def ddns(cmd, cf, public_ips, zone_id, domain_name, dry_run=False, proxied=False):
    # 获取当前的解析记录
    logging.info(f'Reading current records list.')
    dns_records = cf.zones.dns_records.get(zone_id, params={"name": domain_name})

    # 更新所有解析记录
    if not dns_records:
        # 当前的解析记录为空
        logging.info(f'Records list is empty.')
        if cmd == 'update':
            # 创建解析记录
            for public_ip in public_ips:
                record_type = 'A' if isinstance(public_ip, ipaddress.IPv4Address) else 'AAAA'
                logging.info(f'Creating {record_type} record pointed to {public_ip}.')
                if not dry_run:
                    cf.zones.dns_records.post(zone_id, data={"name": domain_name, "type": record_type,
                                                             "content": str(public_ip),
                                                             "comment": 'This record is created by DDNS automatically.',
                                                             "proxied": proxied})

            # 更新公网IP地址缓存
            logging.info(f'Updating cache.')
            with cache_file.open('w') as f:
                f.writelines([str(ip) for ip in public_ips])
            logging.info(f'Update records success.')
        if cmd == 'delete':
            logging.info(f'Records list is empty, records do not need to be deleted.')
    else:
        # 当前解析记录不为空
        logging.info(f'Records list is not empty.')
        if cmd == 'update':
            # 删除不存在的记录类型
            non_existent_record_type = {'A', 'AAAA'} - {'A' if isinstance(ip, ipaddress.IPv4Address) else 'AAAA' for
                                                        ip in public_ips}
            for record in dns_records:
                if record['type'] in non_existent_record_type:
                    logging.info(f'Deleting unused record of type {record["type"]}.')
                    if not dry_run:
                        cf.zones.dns_records.delete(zone_id, record['id'])

            # 更新原有的解析记录或创建新的记录
            for public_ip in public_ips:
                record_type = 'A' if isinstance(public_ip, ipaddress.IPv4Address) else 'AAAA'
                for record in dns_records:
                    if record['type'] == record_type:
                        logging.info(f'{record_type} record is found, making the record point to {public_ip}.')
                        if not dry_run:
                            cf.zones.dns_records.put(zone_id, record['id'],
                                                     data={"name": domain_name, "type": record_type,
                                                           "content": str(public_ip),
                                                           "comment": 'This record is created by DDNS automatically.',
                                                           "proxied": proxied})
                        logging.info(f'{record_type} record is up to date.')
                        break
                else:
                    logging.info(
                        f'{record_type} record is not found, creating {record_type} record pointed to {public_ip}.')
                    if not dry_run:
                        cf.zones.dns_records.post(zone_id, data={"name": domain_name, "type": record_type,
                                                                 "content": str(public_ip),
                                                                 "comment": 'This record is created by DDNS automatically.',
                                                                 "proxied": proxied})

            # 更新公网IP地址缓存
            logging.info(f'Updating cache.')
            with cache_file.open('w') as f:
                f.writelines([str(ip) for ip in public_ips])
            logging.info(f'Update records success.')

        if cmd == 'delete':
            # 删除所有解析记录
            for record in dns_records:
                if record['type'] == 'AAAA' or record['type'] == 'A':
                    logging.info(f'Deleting record of type {record["type"]}.')
                    if not dry_run:
                        cf.zones.dns_records.delete(zone_id, record['id'])

            logging.info(f'Delete records success.')


def main(args):
    # 获取公网IP
    public_ips = IPAddress.get_interface_public_ip()
    if not public_ips:
        logging.error('This machine does not have any public ip address.')
        exit(-1)
    logging.info(f'Successfully obtained the public ip address: {public_ips}.')

    # 利用缓存判断是否需要更新
    if args.cmd == 'update':
        if cache_file.exists():
            logging.info(f'Reading cache.')
            with cache_file.open('r') as f:
                cache_ips_lines = f.readlines()
            try:
                cache_ips = {ipaddress.ip_address(ip.strip()) for ip in cache_ips_lines}
            except ValueError:
                cache_file.unlink()
            else:
                if not cache_ips ^ public_ips:
                    logging.info(f'Public ips are not changed, records do not need to be updated.')
                    exit(0)
    if args.cmd == 'delete' and cache_file.exists():
        logging.info(f'Cleaning cache.')
        cache_file.unlink()

    # 创建Cloudflare对象
    cf = CloudFlare.CloudFlare(token=args.token)

    # 得到待更新的域名
    zone_details = cf.zones.get(args.zone_id)
    domain_name = '.'.join([args.subdomain, zone_details["name"]])

    # 更新DNS记录
    ddns(args.cmd, cf, public_ips, args.zone_id, domain_name, args.dry_run, args.proxied)

    # 打印最终的DNS记录
    records = cf.zones.dns_records.get(args.zone_id, params={"name": domain_name})
    records_str = '\n'.join([f'{r["name"]} => {r["content"]}' for r in records])
    logging.info(f'The final dns records: \n{records_str}')


if __name__ == '__main__':
    # 命令行参数解析
    parser = argparse.ArgumentParser(
        prog='Cloudflare DDNS',
        description='Automatically update Cloudflare DNS records.'
    )
    parser.add_argument('cmd', choices=['update', 'delete'])
    parser.add_argument('--dry-run', action='store_true', default=False)
    parser.add_argument('--proxied', action='store_true', default=False)
    parser.add_argument('--token', required=True)
    parser.add_argument('--zone-id', required=True)
    parser.add_argument('--subdomain', required=True)
    main(parser.parse_args())
