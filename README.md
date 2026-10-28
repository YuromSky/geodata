# geodata

Slim `geoip.dat` / `geosite.dat` for Xray-based clients: only the categories used by the routing
rules, taken from [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat),
plus an extra `geoip:friend` category built from `friend-source.txt`.

Rebuilt daily by GitHub Actions and published to the `release` branch:

```
https://raw.githubusercontent.com/<owner>/<repo>/release/geoip.dat        # slim, for phones
https://raw.githubusercontent.com/<owner>/<repo>/release/geosite.dat      # slim, for phones
https://raw.githubusercontent.com/<owner>/<repo>/release/full/geoip.dat   # full + friend, for desktops
```

Desktops use the full `geosite.dat` straight from runetfreedom.

`build_split.py` cleans the source list before building: drops reserved networks and non-AWS
ranges wider than /16, clips wide ranges to official AWS prefixes, and subtracts `geoip:ru`.
