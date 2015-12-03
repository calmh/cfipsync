package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/calmh/cfdns"
)

var (
	verbose = false
)

func main() {
	flag.BoolVar(&verbose, "verbose", verbose, "Verbose output")
	authKey := flag.String("key", "", "Cloudflare API key")
	authEmail := flag.String("email", "", "Cloudflare API email")
	check := flag.Bool("check", false, "Verify reachability")
	flag.Parse()

	var r io.Reader
	if flag.NArg() > 0 {
		if verbose {
			log.Println("Reading", flag.Arg(0))
		}
		fd, err := os.Open(flag.Arg(0))
		if err != nil {
			log.Fatal(err)
		}
		r = fd
	} else {
		if verbose {
			log.Println("Reading stdin")
		}
		r = os.Stdin
	}

	wantRecords := recordMap(loadIPList(r))

	if *check {
		var wg sync.WaitGroup
		limit := make(chan struct{}, 4)
		for _, rec := range wantRecords {
			rec := rec
			if rec.Content != "" {
				wg.Add(1)
				go func() {
					limit <- struct{}{}
					checkRecord(rec)
					<-limit
					wg.Done()
				}()
			}
		}
		wg.Wait()
		return
	}

	client := cfdns.NewClient(*authEmail, *authKey)

	if verbose {
		log.Println("Listing zones")
	}
	zoneIDs := make(map[string]string)
	zones, err := client.ListZones()
	if err != nil {
		log.Println("Listing zones:", err)
	}
	for _, zone := range zones {
		if verbose {
			log.Println("Got zone", zone.Name, "with id", zone.ID)
		}
		zoneIDs[zone.Name] = zone.ID
	}

	haveRecords := make(map[string]cfdns.DNSRecord)
	for name, zoneID := range zoneIDs {
		if verbose {
			log.Println("Listing zone", name)
		}
		have, err := client.ListDNSRecords(zoneID)
		if err != nil {
			log.Fatal("Listing DNS records:", err)
		}
		if verbose {
			log.Println("Got", len(have), "records")
		}
		recordMapInto(have, haveRecords)
	}

	for key, rec := range wantRecords {
		if rec.Content == "" {
			// An ignore record
			continue
		}

		if curRec, ok := haveRecords[key]; !ok {
			log.Println("Create", rec)
			zoneID := zoneIDFor(zoneIDs, rec.Name)
			if err := client.CreateDNSRecord(zoneID, rec.Name, rec.Type, rec.Content); err != nil {
				log.Fatal(err)
			}
		} else if rec.Content != curRec.Content {
			log.Println("Update", rec)
			curRec.Content = rec.Content
			if err := client.UpdateDNSRecord(curRec); err != nil {
				log.Fatal(err)
			}
		} else if verbose {
			log.Println("Accept", rec)
		}
	}

	for key, rec := range haveRecords {
		switch rec.Type {
		case "A", "AAAA":
			if _, ok := wantRecords[key]; !ok {
				log.Println("Delete", rec)
				if err := client.DeleteDNSRecord(rec); err != nil {
					log.Fatal(err)
				}
			} else if verbose {
				log.Println("Retain", rec)
			}
		}
	}
}

func zoneIDFor(zoneIDs map[string]string, name string) string {
	for domain, zoneID := range zoneIDs {
		if strings.HasSuffix(name, domain) {
			return zoneID
		}
	}
	return ""
}

type domainRewrite struct {
	cidr   *net.IPNet
	domain string
}

func loadIPList(r io.Reader) []cfdns.DNSRecord {
	var domains []domainRewrite
	var records []cfdns.DNSRecord

	br := bufio.NewScanner(r)
	for br.Scan() {
		line := strings.TrimSpace(br.Text())
		if line == "" {
			continue
		}
		if line[0] == '#' {
			continue
		}

		fields := strings.Fields(line)
		switch fields[0] {
		case ".ignore":
			if len(fields) != 2 {
				fmt.Printf("Unknown format (ignore): %q\n", line)
				continue
			}
			name := fields[1]
			records = append(records, cfdns.DNSRecord{Name: name, Type: "A"})
			records = append(records, cfdns.DNSRecord{Name: name, Type: "AAAA"})

		case ".domain":
			if len(fields) != 3 {
				fmt.Printf("Unknown format (domain): %q\n", line)
				continue
			}
			_, cidr, err := net.ParseCIDR(fields[1])
			if err != nil {
				fmt.Println("In .domain:", err)
				continue
			}
			domain := fields[2]
			domains = append(domains, domainRewrite{cidr: cidr, domain: domain})

		default:
			if len(fields) != 2 {
				fmt.Printf("Unknown format (record): %q\n", line)
			}

			name := fields[0]
			ips := strings.Split(fields[1], ",")

			var err error
		nextIP:
			for _, ipStr := range ips {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					ip, _, err = net.ParseCIDR(ipStr)
					if err != nil {
						fmt.Println("In record:", err)
						continue nextIP
					}
				}

				rectype := "A"
				if strings.Contains(ip.String(), ":") {
					rectype = "AAAA"
				}

				for _, domain := range domains {
					if domain.cidr.Contains(ip) {
						parts := strings.SplitN(name, ".", 2)
						newName := parts[0] + "." + domain.domain
						records = append(records, cfdns.DNSRecord{
							Name:    newName,
							Type:    rectype,
							Content: ip.String(),
						})
						continue nextIP
					}
				}
				records = append(records, cfdns.DNSRecord{
					Name:    name,
					Type:    rectype,
					Content: ip.String(),
				})
			}
		}
	}

	return records
}

func recordMap(recs []cfdns.DNSRecord) map[string]cfdns.DNSRecord {
	m := make(map[string]cfdns.DNSRecord, len(recs))
	recordMapInto(recs, m)
	return m
}

func recordMapInto(recs []cfdns.DNSRecord, m map[string]cfdns.DNSRecord) {
	for _, rec := range recs {
		m[rec.Name+"/"+rec.Type] = rec
	}
}

func checkRecord(rec cfdns.DNSRecord) {
	ping := "ping"
	if rec.Type == "AAAA" {
		ping = "ping6"
	}

	if verbose {
		log.Println(ping, rec.Content)
	}
	cmd := exec.Command(ping, "-o", "-c5", rec.Content)
	err := cmd.Run()
	if err != nil {
		log.Println("Failed:", rec)
	}
}
