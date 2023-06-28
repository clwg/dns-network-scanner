package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	ipcipher "github.com/clwg/ip-cipher"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

type DnsQuery struct {
	Timestamp time.Time `db:"timestamp"`
	Ip        string    `db:"ip"`
	Domain    string    `db:"domain"`
	Query     string    `db:"query"`
	Answer    string    `db:"answer"`
}

const (
	schema = `
	CREATE TABLE IF NOT EXISTS dns_queries (
		timestamp TIMESTAMP,
		ip TEXT,
		domain TEXT,
		query TEXT,
		answer TEXT
	);
	`
)

func main() {
	domain := flag.String("domain", "", "Domain to query")
	network := flag.String("network", "", "Network range to query")
	timeout := flag.Int("timeout", 5, "Timeout for DNS queries in seconds")
	domains := flag.String("domains", "", "Comma-separated list of additional domains to query")
	dbfile := flag.String("db", "dns.db", "SQLite database file")
	numGoroutines := flag.Int("goroutines", 20, "Number of goroutines to run simultaneously")
	flag.Parse()

	dictionary, err := ipcipher.BuildDictionary("dictionary.txt")
	if err != nil {
		log.Fatalf("Error building dictionary: %v\n", err)
	}

	db, err := initializeDB(*dbfile)
	if err != nil {
		log.Fatalf("Error initializing database: %v\n", err)
	}
	defer db.Close()

	client := dns.Client{Timeout: time.Duration(*timeout) * time.Second}

	ip, ipnet, err := net.ParseCIDR(*network)
	if err != nil {
		log.Fatalf("Error parsing CIDR: %v\n", err)
	}

	semaphore := make(chan struct{}, *numGoroutines)

	var wg sync.WaitGroup

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		currentIP := make(net.IP, len(ip))
		copy(currentIP, ip)

		// Acquire a token from the semaphore
		semaphore <- struct{}{}

		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			if err := queryDNS(ip, domain, domains, dictionary, &client, db); err != nil {
				log.Printf("Error querying DNS: %v\n", err)
			}
			// Release the token back to the semaphore
			<-semaphore
		}(currentIP)
	}
	wg.Wait()
}

func initializeDB(dbFile string) (*sqlx.DB, error) {
	db, err := sqlx.Open("sqlite3", dbFile)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(schema)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func queryDNS(ip net.IP, domain, domains *string, dictionary []string, client *dns.Client, db *sqlx.DB) error {
	subdomain := ipcipher.EncodeIPAddress(ip, dictionary)
	fqdn := fmt.Sprintf("%s.%s", subdomain, *domain)

	query, answer, err := performDNSQuery(client, fqdn, ip)
	if err != nil {
		return fmt.Errorf("query request failed: %v", err)
	}

	if err := insertIntoDB(db, ip.String(), *domain, query, answer); err != nil {
		return err
	}

	if *domains != "" {
		for _, additionalDomain := range strings.Split(*domains, ",") {
			if err := queryAdditionalDNS(ip, additionalDomain, dictionary, client, db); err != nil {
				log.Printf("Error querying additional DNS: %v\n", err)
			}
		}
	}

	return nil
}

func performDNSQuery(client *dns.Client, fqdn string, ip net.IP) (string, string, error) {
	msg := dns.Msg{}
	msg.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)

	resp, _, err := client.Exchange(&msg, net.JoinHostPort(ip.String(), "53"))
	if err != nil {
		return "", "", err
	}

	query := dnsQuestionToString(msg.Question[0])
	answer := dnsRRToString(resp.Answer)

	return query, answer, nil
}

func insertIntoDB(db *sqlx.DB, ip, domain, query, answer string) error {
	stmt, err := db.Preparex("INSERT INTO dns_queries (timestamp, ip, domain, query, answer) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(time.Now(), ip, domain, query, answer)
	if err != nil {
		return err
	}

	return nil
}

func queryAdditionalDNS(ip net.IP, additionalDomain string, dictionary []string, client *dns.Client, db *sqlx.DB) error {
	query, answer, err := performDNSQuery(client, additionalDomain, ip)
	if err != nil {
		return err
	}

	return insertIntoDB(db, ip.String(), additionalDomain, query, answer)
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		if ip[j] < 255 {
			ip[j]++
			break
		} else {
			ip[j] = 0
		}
	}
}

func dnsQuestionToString(q dns.Question) string {
	return fmt.Sprintf("%s %s", q.Name, dns.TypeToString[q.Qtype])
}

func dnsRRToString(rr []dns.RR) string {
	var str strings.Builder
	for _, r := range rr {
		str.WriteString(r.String())
		str.WriteRune('\n')
	}
	return str.String()
}
