package cidrman

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sort"
)

// https://github.com/EvilSuperstars/go-cidrman

// ipv4ToUInt32 converts an IPv4 address to an unsigned 32-bit integer.
func ipv4ToUInt32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip)
}

// uint32ToIPV4 converts an unsigned 32-bit integer to an IPv4 address.
func uint32ToIPV4(addr uint32) net.IP {
	ip := make([]byte, net.IPv4len)
	binary.BigEndian.PutUint32(ip, addr)
	return ip
}

// The following functions are inspired by http://www.cs.colostate.edu/~somlo/iprange.c.

// setBit sets the specified bit in an address to 0 or 1.
func setBit(addr uint32, bit uint, val uint) uint32 {

	if val == 0 {
		return addr & ^(1 << (32 - bit))
	} else if val == 1 {
		return addr | (1 << (32 - bit))
	} else {
		panic("set bit is not 0 or 1")
	}
}

// netmask returns the netmask for the specified prefix.
func netmask(prefix uint) uint32 {
	if prefix == 0 {
		return 0
	}
	return ^uint32((1 << (32 - prefix)) - 1)
}

// broadcast4 returns the broadcast address for the given address and prefix.
func broadcast4(addr uint32, prefix uint) uint32 {
	return addr | ^netmask(prefix)
}

// network4 returns the network address for the given address and prefix.
func network4(addr uint32, prefix uint) uint32 {
	return addr & netmask(prefix)
}

// splitRange4 recursively computes the CIDR blocks to cover the range lo to hi.
func splitRange4(addr uint32, prefix uint, lo, hi uint32, cidrs *[]*net.IPNet) error {
	if prefix > 32 {
		return fmt.Errorf("invalid mask size: %d", prefix)
	}

	bc := broadcast4(addr, prefix)
	if (lo < addr) || (hi > bc) {
		return fmt.Errorf("%d, %d out of range for network %d/%d, broadcast %d", lo, hi, addr, prefix, bc)
	}

	if (lo == addr) && (hi == bc) {
		cidr := net.IPNet{IP: uint32ToIPV4(addr), Mask: net.CIDRMask(int(prefix), 8*net.IPv4len)}
		*cidrs = append(*cidrs, &cidr)
		return nil
	}

	prefix++
	lowerHalf := addr
	upperHalf := setBit(addr, prefix, 1)
	if hi < upperHalf {
		return splitRange4(lowerHalf, prefix, lo, hi, cidrs)
	} else if lo >= upperHalf {
		return splitRange4(upperHalf, prefix, lo, hi, cidrs)
	} else {
		err := splitRange4(lowerHalf, prefix, lo, broadcast4(lowerHalf, prefix), cidrs)
		if err != nil {
			return err
		}
		return splitRange4(upperHalf, prefix, upperHalf, hi, cidrs)
	}
}

// IPv4 CIDR block.

type cidrBlock4 struct {
	first uint32
	last  uint32
}

type cidrBlock4s []*cidrBlock4

// newBlock4 returns a new IPv4 CIDR block.
func newBlock4(ip net.IP, mask net.IPMask) *cidrBlock4 {
	var block cidrBlock4

	block.first = ipv4ToUInt32(ip)
	prefix, _ := mask.Size()
	block.last = broadcast4(block.first, uint(prefix))

	return &block
}

// Sort interface.

func (c cidrBlock4s) Len() int {
	return len(c)
}

func (c cidrBlock4s) Less(i, j int) bool {
	lhs := c[i]
	rhs := c[j]

	// By last IP in the range.
	if lhs.last < rhs.last {
		return true
	} else if lhs.last > rhs.last {
		return false
	}

	// Then by first IP in the range.
	if lhs.first < rhs.first {
		return true
	} else if lhs.first > rhs.first {
		return false
	}

	return false
}

func (c cidrBlock4s) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

// merge4 accepts a list of IPv4 networks and merges them into the smallest possible list of IPNets.
// It merges adjacent subnets where possible, those contained within others and removes any duplicates.
func merge4(blocks cidrBlock4s) ([]*net.IPNet, error) {
	sort.Sort(blocks)

	// Coalesce overlapping blocks.
	for i := len(blocks) - 1; i > 0; i-- {
		if blocks[i].first <= blocks[i-1].last+1 {
			blocks[i-1].last = blocks[i].last
			if blocks[i].first < blocks[i-1].first {
				blocks[i-1].first = blocks[i].first
			}
			blocks[i] = nil
		}
	}

	var merged []*net.IPNet
	for _, block := range blocks {
		if block == nil {
			continue
		}

		if err := splitRange4(0, 0, block.first, block.last, &merged); err != nil {
			return nil, err
		}
	}

	return merged, nil
}

// ipv6ToUInt128 converts an IPv6 address to an unsigned 128-bit integer.
func ipv6ToUInt128(ip net.IP) *big.Int {
	return big.NewInt(0).SetBytes(ip)
}

// uint128ToIPV6 converts an unsigned 128-bit integer to an IPv6 address.
func uint128ToIPV6(addr *big.Int) net.IP {
	return net.IP(addr.Bytes()).To16()
}

// copyUInt128 copies an unsigned 128-bit integer.
func copyUInt128(x *big.Int) *big.Int {
	return big.NewInt(0).Set(x)
}

// broadcast6 returns the broadcast address for the given address and prefix.
func broadcast6(addr *big.Int, prefix uint) *big.Int {
	z := copyUInt128(addr)

	if prefix == 0 {
		z, _ = z.SetString("340282366920938463463374607431768211455", 10)
		return z
	}

	for i := int(prefix); i < 8*net.IPv6len; i++ {
		z = z.SetBit(z, i, 1)
	}
	return z
}

// network6 returns the network address for the given address and prefix.
func network6(addr *big.Int, prefix uint) *big.Int {
	z := copyUInt128(addr)

	if prefix == 0 {
		return z
	}

	for i := int(prefix); i < 8*net.IPv6len; i++ {
		z = z.SetBit(z, i, 0)
	}
	return z
}

// splitRange6 recursively computes the CIDR blocks to cover the range lo to hi.
func splitRange6(addr *big.Int, prefix uint, lo, hi *big.Int, cidrs *[]*net.IPNet) error {
	if prefix > 128 {
		return fmt.Errorf("invalid mask size: %d", prefix)
	}

	bc := broadcast6(addr, prefix)
	fmt.Printf("%v/%v/%v/%v/%v\n", addr, prefix, lo, hi, bc)
	if (lo.Cmp(addr) < 0) || (hi.Cmp(bc) > 0) {
		return fmt.Errorf("%v, %v out of range for network %v/%d, broadcast %v", lo, hi, addr, prefix, bc)
	}

	if (lo.Cmp(addr) == 0) && (hi.Cmp(bc) == 0) {
		cidr := net.IPNet{IP: uint128ToIPV6(addr), Mask: net.CIDRMask(int(prefix), 8*net.IPv6len)}
		*cidrs = append(*cidrs, &cidr)
		return nil
	}

	prefix++
	lowerHalf := copyUInt128(addr)
	upperHalf := copyUInt128(addr)
	upperHalf = upperHalf.SetBit(upperHalf, int(prefix), 1)
	if hi.Cmp(upperHalf) < 0 {
		return splitRange6(lowerHalf, prefix, lo, hi, cidrs)
	} else if lo.Cmp(upperHalf) >= 0 {
		return splitRange6(upperHalf, prefix, lo, hi, cidrs)
	} else {
		err := splitRange6(lowerHalf, prefix, lo, broadcast6(lowerHalf, prefix), cidrs)
		if err != nil {
			return err
		}
		return splitRange6(upperHalf, prefix, upperHalf, hi, cidrs)
	}
}

type ipNets []*net.IPNet

func (nets ipNets) toCIDRs() []string {
	var cidrs []string
	for _, net := range nets {
		cidrs = append(cidrs, net.String())
	}

	return cidrs
}

// MergeIPNets accepts a list of IP networks and merges them into the smallest possible list of IPNets.
// It merges adjacent subnets where possible, those contained within others and removes any duplicates.
func MergeIPNets(nets []*net.IPNet) ([]*net.IPNet, error) {
	if nets == nil {
		return nil, nil
	}
	if len(nets) == 0 {
		return make([]*net.IPNet, 0), nil
	}

	// Split into IPv4 and IPv6 lists.
	// Merge the list separately and then combine.
	var block4s cidrBlock4s
	for _, net := range nets {
		ip4 := net.IP.To4()
		if ip4 != nil {
			block4s = append(block4s, newBlock4(ip4, net.Mask))
		} else {
			return nil, errors.New("not implemented")
		}
	}

	merged, err := merge4(block4s)
	if err != nil {
		return nil, err
	}

	return merged, nil
}

// MergeCIDRs accepts a list of CIDR blocks and merges them into the smallest possible list of CIDRs.
func MergeCIDRs(cidrs []string) ([]string, error) {
	if cidrs == nil {
		return nil, nil
	}
	if len(cidrs) == 0 {
		return make([]string, 0), nil
	}

	var networks []*net.IPNet
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		networks = append(networks, network)
	}
	mergedNets, err := MergeIPNets(networks)
	if err != nil {
		return nil, err
	}

	return ipNets(mergedNets).toCIDRs(), nil
}

// IPRangeToIPNets accepts an arbitrary start and end IP address and returns a list of
// CIDR subnets that fit exactly between the boundaries of the two with no overlap.
func IPRangeToIPNets(start, end net.IP) ([]*net.IPNet, error) {
	start4 := start.To4()
	end4 := end.To4()

	if ((start4 == nil) && (end4 != nil)) || ((start4 != nil) && (end4 == nil)) {
		return nil, errors.New("mismatched IP address types")
	}

	var cidrs []*net.IPNet

	if start4 != nil {
		lo := ipv4ToUInt32(start4)
		hi := ipv4ToUInt32(end4)
		if hi < lo {
			return nil, errors.New("end < start")
		}

		if err := splitRange4(0, 0, lo, hi, &cidrs); err != nil {
			return nil, err
		}
	} else {
		start6 := start.To16()
		if start6 == nil {
			return nil, fmt.Errorf("invalid IP address: %v", start)
		}
		end6 := end.To16()
		if end6 == nil {
			return nil, fmt.Errorf("invalid IP address: %v", end)
		}

		lo := ipv6ToUInt128(start6)
		hi := ipv6ToUInt128(end6)
		if hi.Cmp(lo) < 0 {
			return nil, errors.New("end < start")
		}
		if err := splitRange6(big.NewInt(0), 0, lo, hi, &cidrs); err != nil {
			return nil, err
		}
	}

	return cidrs, nil
}

// IPRangeToCIDRs accepts an arbitrary start and end IP address and returns a list of
// CIDR subnets that fit exactly between the boundaries of the two with no overlap.
func IPRangeToCIDRs(start, end string) ([]string, error) {
	ipStart := net.ParseIP(start)
	if ipStart == nil {
		return nil, fmt.Errorf("invalid IP address: %s", start)
	}
	ipEnd := net.ParseIP(end)
	if ipEnd == nil {
		return nil, fmt.Errorf("invalid IP address: %s", end)
	}

	nets, err := IPRangeToIPNets(ipStart, ipEnd)
	if err != nil {
		return nil, err
	}

	return ipNets(nets).toCIDRs(), nil
}

func Subnets(cidr string, prefix int) ([]string, error) {

	return nil, nil
}

func NonContigousIPListToCIDR(ipList []string) ([]string, error) {
	if len(ipList) == 0 {
		return nil, nil
	}

	// Sort the IP list to ensure ranges are detected correctly
	sort.Slice(ipList, func(i, j int) bool {
		ip1 := net.ParseIP(ipList[i]).To4()
		ip2 := net.ParseIP(ipList[j]).To4()
		return ipv4ToUInt32(ip1) < ipv4ToUInt32(ip2)
	})

	var result []string
	var start, end string

	for i, ip := range ipList {
		if start == "" {
			// Initialize the start of the range
			start = ip
			end = ip
			continue
		}

		// Check if the current IP is contiguous with the previous one
		prevIP := net.ParseIP(ipList[i-1]).To4()
		currIP := net.ParseIP(ip).To4()
		if ipv4ToUInt32(currIP) == ipv4ToUInt32(prevIP)+1 {
			// Extend the range
			end = ip
		} else {
			// Process the current range
			cidrs, err := IPRangeToCIDRs(start, end)
			if err != nil {
				return nil, err
			}
			result = append(result, cidrs...)

			// Start a new range
			start = ip
			end = ip
		}
	}

	// Process the final range
	if start != "" {
		cidrs, err := IPRangeToCIDRs(start, end)
		if err != nil {
			return nil, err
		}
		result = append(result, cidrs...)
	}

	return result, nil
}
