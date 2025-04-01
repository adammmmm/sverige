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

func processIPv4Addresses(writer *bufio.Writer) error {
	// Iterate through the IPv4 address space
	// Ignoring RFC5735 reserved ranges
	// https://tools.ietf.org/html/rfc5735
	var (
		curStart  = 0
		curEnd    = 0
		lastFound = 0
		first     = true
	)
	// from 1.0.0.0 to 9.255.255.255, getting rid of 0.0.0.0/8 and 10.0.0.0/8
	for i := 16777216; i <= 167772159; i++ {
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

	// starting from 11.0.0.0 until 126.255.255.255, getting rid of 127.0.0.0/8
	for i := 184549376; i <= 2130706431; i++ {
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

	// starting from 128.0.0.0 until 169.253.255.255, getting rid of 169.254.0.0/16
	for i := 2147483648; i <= 2851995647; i++ {
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

	// starting from 169.255.0.0 until 172.15.255.255, getting rid of 172.16.0.0/12
	for i := 2852061184; i <= 2886729727; i++ {
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

	// starting from 172.32.0.0 until 192.0.1.255, getting rid of 192.0.2.0/24
	for i := 2887778304; i <= 3221225983; i++ {
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

	// starting from 192.0.3.0 until 192.167.255.255, getting rid of 192.168.0.0/16
	for i := 3221226240; i <= 3232235519; i++ {
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

	// starting from 192.169.0.0 until 198.17.255.255, getting rid of 198.18.0.0/15
	for i := 3232301056; i <= 3323068415; i++ {
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

	// starting from 198.20.0.0 until 198.50.255.255, getting rid of 198.51.0.0/24
	for i := 3323199488; i <= 3325231103; i++ {
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

	// starting from 198.51.1.0 until 203.0.112.255, getting rid of 203.0.113.0/24
	for i := 3325231360; i <= 3405803775; i++ {
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

	// starting from 203.0.114.0 until 255.255.255.255
	for i := 3405804032; i <= 4294967295; i++ {
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
