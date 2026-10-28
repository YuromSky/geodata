#!/usr/bin/env python3
"""Чистит список IP для сплита и собирает облегчённые geoip.dat и geosite.dat для Happ/Xray.

Две версии:
  out/geoip.dat, out/geosite.dat — облегчённые, для телефонов: из файлов runetfreedom (18 и 73 МБ)
      оставлены только категории, которые используют правила сплита (Happ качает geo-файлы
      с ограничением в 3 минуты);
  out/full/geoip.dat — полный geoip.dat runetfreedom, для компьютеров (geosite для них берётся
      напрямую у runetfreedom).
В оба geoip.dat дописывается категория FRIEND (очищенный список друга).

Очистка:
  - убираются зарезервированные сети (CGNAT, документационные и т.п.);
  - записи, пересекающиеся с AWS, обрезаются до официальных подсетей AWS
    (так сохраняются игровые серверы на AWS, например Wardogs);
  - остальные записи шире /MIN_PREFIX выбрасываются;
  - из всего вычитаются российские подсети (geoip:ru) — российские сервисы
    не должны видеть IP VPS.

Запуск: python3 -I build_split.py <amnezia_sites.json | friend.txt> <out_dir>
"""
import bisect
import ipaddress
import json
import sys
import urllib.request
from pathlib import Path

GEOIP_URL = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat"
GEOSITE_URL = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat"
GEOIP_KEEP = {"PRIVATE", "RU", "RU-BLOCKED", "CLOUDFLARE", "TELEGRAM"}
GEOSITE_KEEP = {
    "PRIVATE", "RU-BLOCKED", "CATEGORY-RU", "RU-AVAILABLE-ONLY-INSIDE", "TELEGRAM",
    # сервисы, которые сами не пускают пользователей из РФ
    "CATEGORY-AI-!CN", "SPOTIFY", "NOTION", "CANVA", "INTEL", "NVIDIA", "JETBRAINS",
    "AUTODESK", "CURSOR", "WINDSURF",
}
AWS_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
MIN_PREFIX = 16
CATEGORY = "FRIEND"


def fetch(url, dest):
    with urllib.request.urlopen(url, timeout=120) as r:
        dest.write_bytes(r.read())
    return dest


def read_varint(b, i):
    result = shift = 0
    while True:
        x = b[i]
        i += 1
        result |= (x & 0x7F) << shift
        shift += 7
        if x < 0x80:
            return result, i


def pb_fields(b):
    i = 0
    while i < len(b):
        key, i = read_varint(b, i)
        field, wire = key >> 3, key & 7
        if wire == 0:
            value, i = read_varint(b, i)
        elif wire == 2:
            n, i = read_varint(b, i)
            value = b[i:i + n]
            i += n
        else:
            raise ValueError(f"unexpected protobuf wire type {wire}")
        yield field, value


def varint(n):
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def pb_bytes(field, payload):
    return varint(field << 3 | 2) + varint(len(payload)) + payload


def geoip_categories(dat, wanted):
    """Возвращает {категория: [сети IPv4]} для нужных категорий geoip.dat."""
    result = {}
    for _, entry in pb_fields(dat):
        code, cidrs = None, []
        for f, v in pb_fields(entry):
            if f == 1:
                code = v.decode()
            elif f == 2:
                cidrs.append(v)
        if code not in wanted:
            continue
        nets = []
        for c in cidrs:
            ip, prefix = b"", 0
            for f, v in pb_fields(c):
                if f == 1:
                    ip = v
                elif f == 2:
                    prefix = v
            if len(ip) == 4:
                nets.append(ipaddress.ip_network((ip, prefix)))
        result[code] = list(ipaddress.collapse_addresses(nets))
    return result


def keep_categories(dat, keep):
    """Копирует из .dat только записи нужных категорий (код категории — первое поле записи)."""
    out, found = bytearray(), set()
    for _, entry in pb_fields(dat):
        _, code = next(pb_fields(entry))
        if code.decode() in keep:
            out += pb_bytes(1, entry)
            found.add(code.decode())
    missing = keep - found
    if missing:
        sys.exit(f"в исходном файле нет категорий: {', '.join(sorted(missing))}")
    return bytes(out)


def encode_category(code, nets):
    body = pb_bytes(1, code.encode())
    for n in nets:
        cidr = pb_bytes(1, n.network_address.packed) + varint(2 << 3 | 0) + varint(n.prefixlen)
        body += pb_bytes(2, cidr)
    return pb_bytes(1, body)


class Index:
    """Отсортированный набор непересекающихся сетей для быстрого поиска пересечений."""

    def __init__(self, nets):
        self.nets = list(ipaddress.collapse_addresses(nets))
        self.starts = [int(n.network_address) for n in self.nets]

    def overlapping(self, net):
        i = bisect.bisect_right(self.starts, int(net.broadcast_address)) - 1
        out = []
        while i >= 0 and int(self.nets[i].broadcast_address) >= int(net.network_address):
            out.append(self.nets[i])
            i -= 1
        return out


def subtract(net, holes):
    parts = [net]
    for h in holes:
        nxt = []
        for p in parts:
            if p.subnet_of(h):
                continue
            nxt.extend(p.address_exclude(h) if h.subnet_of(p) else [p])
        parts = nxt
    return parts


def load_source(path):
    if path.suffix == ".json":
        entries = [e.get("hostname", "") for e in json.loads(path.read_text())]
    else:
        entries = [line.split("#")[0] for line in path.read_text().splitlines()]
    nets = []
    for e in (x.strip() for x in entries):
        if not e:
            continue
        try:
            n = ipaddress.ip_network(e, strict=False)
        except ValueError:
            print(f"пропущено (не IP/CIDR): {e}", file=sys.stderr)
            continue
        if n.version == 4:
            nets.append(n)
    return nets


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    src, out = Path(sys.argv[1]).expanduser(), Path(sys.argv[2]).expanduser()
    cache = out / "cache"
    cache.mkdir(parents=True, exist_ok=True)

    dat = fetch(GEOIP_URL, cache / "runetfreedom-geoip.dat").read_bytes()
    geosite = fetch(GEOSITE_URL, cache / "runetfreedom-geosite.dat").read_bytes()
    aws_json = json.loads(fetch(AWS_URL, cache / "aws-ip-ranges.json").read_text())

    cats = geoip_categories(dat, {"RU", "RU-BLOCKED", "CLOUDFLARE"})
    ru, blocked, cloudflare = Index(cats["RU"]), Index(cats["RU-BLOCKED"]), Index(cats["CLOUDFLARE"])
    aws = Index(ipaddress.ip_network(p["ip_prefix"]) for p in aws_json["prefixes"])

    source = load_source(src)
    kept, dropped, reserved, aws_clipped = [], [], [], 0
    for n in source:
        if not n.is_global:
            reserved.append(n)
            continue
        aws_hits = aws.overlapping(n)
        if aws_hits:
            if n.prefixlen < MIN_PREFIX:
                aws_clipped += 1
                kept.extend(a if a.subnet_of(n) else n for a in aws_hits)
            else:
                kept.append(n)
        elif n.prefixlen < MIN_PREFIX:
            dropped.append(n)
        else:
            kept.append(n)

    before_ru = list(ipaddress.collapse_addresses(kept))
    friend = []
    for n in before_ru:
        friend.extend(subtract(n, ru.overlapping(n)))
    friend = list(ipaddress.collapse_addresses(friend))

    def size(nets):
        return sum(n.num_addresses for n in nets)

    ru_removed = size(before_ru) - size(friend)
    in_blocked = sum(1 for n in friend if any(n.subnet_of(b) for b in blocked.overlapping(n)))
    in_cf = sum(1 for n in friend if cloudflare.overlapping(n))
    aws_left = sum(1 for n in friend if aws.overlapping(n))

    (out / "friend.txt").write_text("".join(f"{n}\n" for n in friend))
    (out / "dropped-wide.txt").write_text("".join(f"{n}\n" for n in sorted(dropped)))
    geoip_out = keep_categories(dat, GEOIP_KEEP) + encode_category(CATEGORY, friend)
    geosite_out = keep_categories(geosite, GEOSITE_KEEP)
    full_geoip_out = dat + encode_category(CATEGORY, friend)
    (out / "geoip.dat").write_bytes(geoip_out)
    (out / "geosite.dat").write_bytes(geosite_out)
    (out / "full").mkdir(exist_ok=True)
    (out / "full" / "geoip.dat").write_bytes(full_geoip_out)

    report = [
        f"Исходный список: {len(source)} записей, {size(ipaddress.collapse_addresses(source)):,} адресов "
        f"({size(ipaddress.collapse_addresses(source)) / 2**32:.2%} IPv4)",
        f"Зарезервированные сети убраны: {len(reserved)} ({', '.join(map(str, reserved))})",
        f"Широкие (< /{MIN_PREFIX}) не-AWS записи убраны: {len(dropped)} (см. dropped-wide.txt)",
        f"Широкие записи с AWS обрезаны до подсетей AWS: {aws_clipped}",
        f"Вычтено российских адресов (geoip:ru): {ru_removed:,}",
        f"Итог geoip:{CATEGORY.lower()}: {len(friend)} подсетей, {size(friend):,} адресов "
        f"({size(friend) / 2**32:.2%} IPv4)",
        f"  из них подсетей AWS: {aws_left}",
        f"  целиком уже есть в geoip:ru-blocked: {in_blocked}",
        f"  пересекаются с geoip:cloudflare: {in_cf}",
        f"geoip.dat: {len(geoip_out):,} байт ({', '.join(sorted(GEOIP_KEEP | {CATEGORY}))})",
        f"geosite.dat: {len(geosite_out):,} байт ({', '.join(sorted(GEOSITE_KEEP))})",
        f"full/geoip.dat: {len(full_geoip_out):,} байт (все категории runetfreedom + {CATEGORY})",
    ]
    (out / "report.txt").write_text("\n".join(report) + "\n")
    print("\n".join(report))


if __name__ == "__main__":
    main()
