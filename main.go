package main

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"

	"github.com/adammmmm/sverige/cidrman"
	"github.com/phuslu/iploc"
)

func intToIPv4(i int) string {
	buf := [15]byte{}
	pos := 0

	writeByte := func(b byte) {
		if b >= 100 {
			buf[pos] = '0' + b/100
			pos++
			b %= 100
		}
		if b >= 10 {
			buf[pos] = '0' + b/10
			pos++
			b %= 10
		}
		buf[pos] = '0' + b
		pos++
	}

	writeByte(byte(i >> 24))
	buf[pos] = '.'
	pos++
	writeByte(byte(i >> 16))
	buf[pos] = '.'
	pos++
	writeByte(byte(i >> 8))
	buf[pos] = '.'
	pos++
	writeByte(byte(i))

	return string(buf[:pos])
}

func isSE(ip string) bool {
	parsedIP, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}

	return iploc.Country(parsedIP.AsSlice()) == "SE"
}

func isRFC5735Address(i int) bool {
	return (i >= 167772160 && i <= 184549375) || // 10.0.0.0/8 (167772160-184549375)
		(i >= 2130706432 && i <= 2147483647) || // 127.0.0.0/8 (2130706432-2147483647)
		(i >= 2835218432 && i <= 2835283967) || // 169.254.0.0/16 (2835218432-2835283967)
		(i >= 2886729728 && i <= 2888957951) || // 172.16.0.0/12 (2886729728-2888957951)
		(i >= 3221356544 && i <= 3221356799) || // 192.0.2.0/24 (3221356544-3221356799)
		(i >= 3232235520 && i <= 3232301055) || // 192.168.0.0/16 (3232235520-3232301055)
		(i >= 3323068416 && i <= 3323199487) || // 198.18.0.0/15 (3323068416-3323199487)
		(i >= 3325231104 && i <= 3325231359) || // 198.51.0.0/24 (3325231104-3325231359)
		(i >= 3338790144 && i <= 3338790399) // 203.0.113.0/24 (3338790144-3338790399)
}

func processIPv4Addresses(writer *bufio.Writer) error {
	// Iterate through the IPv4 address space
	// Ignoring RFC5735 reserved ranges
	// https://tools.ietf.org/html/rfc5737
	var (
		curStart  = 0
		curEnd    = 0
		lastFound = 0
		first     = true
	)

	for i := 16777216; i <= 4294967295; i++ {
		if isRFC5735Address(i) {
			continue
		}

		ip := intToIPv4(i)
		if isSE(ip) && i == lastFound+1 || isSE(ip) && first {
			if curStart == 0 {
				curStart = i
			}
			curEnd = i
			lastFound = i
			first = false
			continue
		}

		if curStart != 0 && curEnd != 0 {
			cidrs, _ := cidrman.IPRangeToCIDRs(intToIPv4(curStart), intToIPv4(curEnd))
			for _, cidr := range cidrs {
				_, err := writer.WriteString(fmt.Sprintf("%s\n", cidr))
				if err != nil {
					return err
				}
				err = writer.Flush()
				if err != nil {
					return err
				}
			}
			curStart = 0
			curEnd = 0

			first = true
		}
	}

	return writer.Flush()
}

func main() {
	writeFile, err := os.Create("ipv4_addresses.txt")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer writeFile.Close()

	writer := bufio.NewWriter(writeFile)

	err = processIPv4Addresses(writer)
	if err != nil {
		fmt.Println("Error processing IPv4 addresses:", err)
	}
}
