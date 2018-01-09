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
	dryRun := flag.Bool("dry-run", false, "Do not do")
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
		for _, recs := range wantRecords {
			for _, rec := range recs {
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

	haveRecords := make(map[string][]cfdns.DNSRecord)
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

	for key, recs := range wantRecords {
		if len(recs) == 1 && recs[0].Content == "" {
			// An ignore record
			continue
		}

		for _, rec := range recs {
			curRecs := haveRecords[key]
			if !contentInRecs(rec.Content, curRecs) {
				log.Println("Create", rec)
				zoneID := zoneIDFor(zoneIDs, rec.Name)
				if !*dryRun {
					if err := client.CreateDNSRecord(zoneID, rec.Name, rec.Type, rec.Content); err != nil {
						log.Fatal(err)
					}
				}
			} else if verbose {
				log.Println("Accept", rec)
			}
		}
	}

	for key, recs := range haveRecords {
		for _, rec := range recs {
			switch rec.Type {
			case "A", "AAAA":
				recs := wantRecords[key]
				if len(recs) == 1 && recs[0].Content == "" {
					// An ignore record
					continue
				}

				if !contentInRecs(rec.Content, recs) {
					log.Println("Delete", rec)
					if !*dryRun {
						if err := client.DeleteDNSRecord(rec); err != nil {
							log.Fatal(err)
						}
					}
				} else if verbose {
					log.Println("Retain", rec)
				}
			}
		}
	}
}

func contentInRecs(cont string, recs []cfdns.DNSRecord) bool {
	for _, rec := range recs {
		if rec.Content == cont {
			return true
		}
	}
	return false
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
	variables := make(map[string]string)

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

		case ".variable":
			if len(fields) != 3 {
				fmt.Printf("Unknown format (variable): %q\n", line)
				continue
			}
			variables[fields[1]] = fields[2]

		default:
			if len(fields) != 2 {
				fmt.Printf("Unknown format (record): %q\n", line)
			}

			name := fields[0]
			ips := strings.Split(fields[1], ",")

			for i, ip := range ips {
				if strings.HasPrefix(ip, "$") {
					val, ok := variables[ip[1:]]
					if !ok {
						fmt.Printf("Unknown variable: %q\n", ip)
						os.Exit(1)
					}
					ips[i] = val
				}
			}

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

				rec := cfdns.DNSRecord{
					Name:    name,
					Type:    rectype,
					Content: ip.String(),
				}
				records = append(records, rec)
			}
		}
	}

	return records
}

func recordMap(recs []cfdns.DNSRecord) map[string][]cfdns.DNSRecord {
	m := make(map[string][]cfdns.DNSRecord, len(recs))
	recordMapInto(recs, m)
	return m
}

func recordMapInto(recs []cfdns.DNSRecord, m map[string][]cfdns.DNSRecord) {
	for _, rec := range recs {
		key := rec.Name + "/" + rec.Type
		m[key] = append(m[key], rec)
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
