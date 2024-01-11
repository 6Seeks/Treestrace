# Treestrace: An Efficient IPv6 scanner for Router Interface Address Discovery

This is a toy implentation of Treestrace, which is inspired by prior outstanding works, like [6Scan]{https://github.com/hbn1987/6Scan.git}, [Yarrp]{https://github.com/cmand/yarrp.git}, [Zmap]{https://github.com/zmap/zmap.git} and so on.

## Why do it?

Treestrace can help you fast collect IPv6 router interface address. It works like traceroute6 but in high parallelism. Its main novelity is that Treestrace can dynamically adjust its probing focuses during the process of high-speed asynchronous traceroute6.


## How to use?

I write it in a single golang file with relatively few lines of code. Users can customize the running script `run.sh` to set entire budget (how many packets do you want to use in this probing process, $10^9$ or $10^{10}$ or more?)

But not too large, because Treestrace also follows real-world operating rules. As a scanner, its capability is limited to sending 100,000 packets per second to the internet. Our endeavor is focused on enhancing the value and yield of these limited detection packets. So, it is important not to expect it to aggressively scan the entire IPv6 network's router interface addresses in a very short time.

Treestrace has tried his best!



## What is the underlying algorithm?

Its capabilities include randomly exploring multiple IPv6 prefixes with different weights, i.e., the IPv6 prefixes with high historical rewards will be probed more, like reinforment learning.

The weight random sampling is implented with follows:

1. According to weights (reward rates) of all IPv6 prefixes, Treestrace build Huffman coding tree.

2. Treestrace generate randomized bit streams and follow them to random walk on the tree from root to leaves.

3. Repeat it.


## Disclaimer

Treestrace is not very complete now, please don't use him directly for production scenes. We disclose it here only to facilitate research on IPv6 network measurements

