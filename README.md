# ProtocolDetector

Protocol detector based on yara


Install:
```
sudo pip install git+git://github.com/jpalanco/ProtocolDetector.git
```



## Command Line


Analyze pcap:
```
ProtocolDetector -p example.pcap
```

Analyze iface (real-time):
```
ProtocolDetector -i eth0
```

Example output:

```
{'dport': 1604, 'src': '192.168.1.10', 'dst': '94.73.33.36', 'sport': 49181, 'protocols': [darkcomet]}
```


## API

```

from ProtocolDetector.Engine import get_rules, perform_check
import dpkt


pcap_path='dump.pcap'
pcap_file = open(pcap_path)
pcap=dpkt.pcap.Reader(pcap_file)

options = { 'mode': 'default',
            'socks_proxy': False,
            'remove_local' : False,
            'pcap_path': pcap_path,
            'iface': None,
            'rules' : get_rules() }



for ts, buf in pcap:
        results = perform_check(buf, options )
        print results
```



