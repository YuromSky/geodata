# geodata

`geoip.dat` for Xray-based clients: [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat)
categories plus an extra `geoip:friend` category built from `friend-source.txt`.

Rebuilt daily by GitHub Actions and published to the `release` branch:

```
https://raw.githubusercontent.com/<owner>/<repo>/release/geoip.dat
```

`build_split.py` cleans the source list before building: drops reserved networks and non-AWS
ranges wider than /16, clips wide ranges to official AWS prefixes, and subtracts `geoip:ru`.
