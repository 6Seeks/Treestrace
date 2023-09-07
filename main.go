package main

import (
	"container/heap"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"math"
	"math/rand"
	"net"
	_ "net/http"
	_ "net/http/pprof"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

var (
	eth       = layers.Ethernet{EthernetType: layers.EthernetTypeIPv6}
	ip6       = layers.IPv6{Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: 255}
	icmp6     = layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(128, 0)}
	icmp6echo = layers.ICMPv6Echo{}
	payload   = gopacket.Payload([]byte{0x00, 0x00, 0x00, 0x00})
	bpf       = []unix.SockFilter{
		{0x28, 0, 0, 0x0000000c},
		{0x15, 0, 6, 0x000086dd},
		{0x30, 0, 0, 0x00000014},
		{0x15, 3, 0, 0x0000003a},
		{0x15, 0, 3, 0x0000002c},
		{0x30, 0, 0, 0x00000036},
		{0x15, 0, 1, 0x0000003a},
		{0x06, 0, 0, 0x00040000},
		{0x06, 0, 0, 0x00000000},
	}
	bpf_prog = unix.SockFprog{Len: uint16(len(bpf)), Filter: &bpf[0]}
	fd       int      // for socket
	file     *os.File // for output
	PCStable          = []PCS{}
	BitSet            = make([]byte, 1<<30)
	hit      uint64   = 0
)

type PCS struct {
	stub   uint64
	mask   uint64
	reward uint64
	offset uint64
}

type node struct {
	index  int
	weight float64
	zero   *node
	one    *node
}
type nodeHeap []*node

func (h nodeHeap) Len() int            { return len(h) }
func (h nodeHeap) Less(i, j int) bool  { return h[i].weight < h[j].weight }
func (h nodeHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *nodeHeap) Push(x interface{}) { *h = append(*h, x.(*node)) }
func (h *nodeHeap) Pop() interface{} {
	defer func() { *h = (*h)[:len(*h)-1] }()
	return (*h)[len(*h)-1]
}

func destoryCodingTree(cur *node) {
	if cur == nil { // destroy the old tree if it exists
		return
	}
	destoryCodingTree(cur.zero)
	destoryCodingTree(cur.one)
	cur.zero, cur.one = nil, nil
}
func searchCodingTree(cur *node, bitstream uint64) *node {
	if cur.index != -1 {
		return cur
	}
	if bitstream&1 == 0 {
		return searchCodingTree(cur.zero, bitstream>>1)
	} else {
		return searchCodingTree(cur.one, bitstream>>1)
	}
}

func createCodingTree() *node {
	tHeap := nodeHeap{}
	for i := 0; i < len(PCStable); i++ {
		if (PCStable[i].offset >> 5) < PCStable[i].mask {
			tHeap = append(tHeap, &node{index: i, weight: (float64(20 + PCStable[i].reward)) / (math.Log2(float64(1000 + PCStable[i].offset)))})
		}
	}
	heap.Init(&tHeap)
	for tHeap.Len() > 1 {
		zero := heap.Pop(&tHeap).(*node)
		one := heap.Pop(&tHeap).(*node)
		heap.Push(&tHeap, &node{zero: zero, one: one, weight: zero.weight + one.weight, index: -1})
	}
	return heap.Pop(&tHeap).(*node)
}

func murmur3(data []byte, seed uint32) uint32 {
	hash := seed
	for i := 0; i < len(data); i = i + 4 {
		k := binary.BigEndian.Uint32(data[i : i+4])
		k = k * 0xcc9e2d51
		k = (k << 15) | (k >> 17)
		k = k * 0x1b873593
		hash = hash ^ k
		hash = (hash << 13) | (hash >> 19)
		hash = hash*5 + 0xe6546b64
	}
	hash = hash ^ (hash >> 16)
	hash = hash * 0x85ebca6b
	hash = hash ^ (hash >> 13)
	hash = hash * 0xc2b2ae35
	hash = hash ^ (hash >> 16)
	return hash
}

func fnv1(value uint64) uint64 {
	var hash uint64 = 14695981039346656037
	for i := 0; i < 8; i++ {
		hash ^= value & 0xff
		hash *= 1099511628211
		value >>= 8
	}
	return hash
}

func main() {
	var iface int
	var src string
	var smac string
	var dmac string
	var name string
	var err error
	var data []byte
	var budget uint64

	flag.IntVar(&iface, "i", 1, "")
	flag.Uint64Var(&budget, "b", 1000000000, "")
	flag.StringVar(&dmac, "g", "", "")
	flag.StringVar(&smac, "m", "", "")
	flag.StringVar(&src, "s", "", "")
	flag.StringVar(&name, "n", "", "")
	flag.Parse()
	if eth.SrcMAC, err = net.ParseMAC(smac); err != nil {
		panic(err)
	}
	if eth.DstMAC, err = net.ParseMAC(dmac); err != nil {
		panic(err)
	}
	ip6.SrcIP = net.ParseIP(src)
	if fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, ((unix.ETH_P_ALL<<8)&0xff00)|unix.ETH_P_ALL>>8); err != nil {
		panic(err)
	}
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: iface}); err != nil {
		panic(err)
	}
	if err = unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &bpf_prog); err != nil {
		panic(err)
	}
	if data, err = ioutil.ReadFile(name); err != nil {
		panic(err)
	}
	if file, err = os.Create("output/" + name + time.Now().Format("20060102-150405")); err != nil {
		panic(err)
	}
	rand.Seed(time.Now().UnixNano())
	for i, line := range strings.Fields(string(data)) {
		if ip6, ip6net, err := net.ParseCIDR(line); err != nil || i == (1<<24) {
			panic(err)
		} else {
			stub := binary.BigEndian.Uint64(ip6[:8])
			mask := ^binary.BigEndian.Uint64(ip6net.Mask[:8])
			PCStable = append(PCStable, PCS{stub: stub, mask: mask, offset: 0, reward: 0})
		}
	}

	go Recv()
	time.Sleep(3 * time.Second)
	// huffman coding tree
	var root *node
	step := uint64(100000)
	for sum := uint64(0); sum < budget; sum = sum + step {
		fmt.Println(sum, hit)
		destoryCodingTree(root)
		root = createCodingTree()
		// show(root, 0, "")
		Scan(root, step)
	}
}

func Scan(root *node, step uint64) {
	Dst := net.IPv6zero
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	for i := uint64(0); i < step; i++ {
		tnode := searchCodingTree(root, rand.Uint64())
		tPCS := &PCStable[tnode.index]
		tbits := fnv1(tPCS.offset)
		ip6.HopLimit = uint8(tbits&0x1f) + 3
		binary.BigEndian.PutUint64(Dst[0:], tPCS.stub+tPCS.mask&(tbits>>5))
		binary.BigEndian.PutUint32(Dst[8:12], uint32(time.Now().UnixNano()/1e3)) // timestamp / us
		binary.BigEndian.PutUint32(Dst[12:], murmur3(Dst[:12], 0x11112222))      // checksum
		ip6.DstIP = Dst
		// fmt.Printf("%0.16x, %0.16x, %s, %d\n", tPCS.stub, tPCS.mask, Dst, ip6.HopLimit)
		icmp6.SetNetworkLayerForChecksum(&ip6)
		icmp6echo.Identifier = uint16(tnode.index >> 8)
		icmp6echo.SeqNumber = uint16(tnode.index<<8) + uint16(ip6.HopLimit)
		gopacket.SerializeLayers(buffer, opts, &eth, &ip6, &icmp6, &icmp6echo, &payload)
		unix.Send(fd, buffer.Bytes(), unix.MSG_WAITALL)
		tPCS.offset++
	}
}

func Recv() {
	buf := make([]byte, 1000)
	var status32 uint32
	for {
		if n, _, err := unix.Recvfrom(fd, buf, 0); err != nil {
			fmt.Println(fd, err)
		} else {
			// responding addr, icmpv6 type, code, ttl, length, probing addr, prefix idx, probing ttl, send time, recv time, check
			switch buf[54] {
			case 129:
				status32 = binary.BigEndian.Uint32(buf[58:62])
				fmt.Fprintf(file, "%s,%d,%d,%d,%d,%s,%d,%d,%d,%d,%d\n", net.IP(buf[22:38]).To16(), buf[54], buf[55], buf[21], n, net.IP(buf[22:38]).To16(), status32>>24, status32&0xff, binary.BigEndian.Uint32(buf[30:34]), uint32(time.Now().UnixNano()/1e3), binary.BigEndian.Uint32(buf[34:38]) == murmur3(buf[22:34], 0x11112222))

			case 1, 3:
				status32 = binary.BigEndian.Uint32(buf[106:110])
				fmt.Fprintf(file, "%s,%d,%d,%d,%d,%s,%d,%d,%d,%d,%d\n", net.IP(buf[22:38]).To16(), buf[54], buf[55], buf[21], n, net.IP(buf[86:102]).To16(), status32>>24, status32&0xff, binary.BigEndian.Uint32(buf[94:98]), uint32(time.Now().UnixNano()/1e3), binary.BigEndian.Uint32(buf[98:102]) == murmur3(buf[86:98], 0x11112222))

				if int(status32>>8) >= len(PCStable) {
					continue
				}
				// Keys of Bloom filters
				i := murmur3(buf[22:38], 0x12345678)
				j := murmur3(buf[22:38], 0x87654321)
				// Check if the ip is in BitSet
				if BitSet[i/8]&(1<<(i%8)) != 0 && BitSet[j/8]&(1<<(j%8)) != 0 {
					continue
				}
				BitSet[i/8] |= (1 << (i % 8))
				BitSet[j/8] |= (1 << (j % 8))
				atomic.AddUint64(&PCStable[status32>>8].reward, 1)
				hit++
			}
		}
	}
}

func show(N *node, L int, code string) {
	if N == nil {
		return
	}
	if N.index != -1 {
		fmt.Printf("%d, %d\n", code, L)
	} else {
		show(N.zero, L+1, "0"+code)
		show(N.one, L+1, "1"+code)
	}
}
