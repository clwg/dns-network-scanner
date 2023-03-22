package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/jmoiron/sqlx"
	"github.com/miekg/dns"
)

type DnsQuery struct {
	Timestamp time.Time `db:"timestamp"`
	Ip        string    `db:"ip"`
	Domain    string    `db:"domain"`
	Query     string    `db:"query"`
	Answer    string    `db:"answer"`
}

const schema = `
CREATE TABLE IF NOT EXISTS dns_queries (
    timestamp TIMESTAMP,
    ip TEXT,
    domain TEXT,
    query TEXT,
    answer TEXT
);
`

func main() {
	domain := flag.String("domain", "", "Domain to query")
	network := flag.String("network", "", "Network range to query")
	timeout := flag.Int("timeout", 5, "Timeout for DNS queries in seconds")
	domains := flag.String("domains", "", "Comma-separated list of additional domains to query")
	dbfile := flag.String("db", "dns.db", "SQLite database file")
	flag.Parse()

	db, err := sqlx.Open("sqlite3", *dbfile)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	if _, err := os.Stat(*dbfile); os.IsNotExist(err) {
		_, err = db.Exec(schema)
		if err != nil {
			panic(err)
		}
	}

	client := dns.Client{Timeout: time.Duration(*timeout) * time.Second}

	ip, ipnet, err := net.ParseCIDR(*network)
	if err != nil {
		panic(err)
	}

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		msg := dns.Msg{}
		msg.SetQuestion(dns.Fqdn(*domain), dns.TypeA)
		resp, _, err := client.Exchange(&msg, net.JoinHostPort(ip.String(), "53"))
		if err != nil {
			fmt.Printf("query request timeout: %s\n", err)
			continue
		}

		query := dnsQuestionToString(msg.Question[0])
		answer := dnsRRToString(resp.Answer)
		stmt, err := db.Preparex("INSERT INTO dns_queries (timestamp, ip, domain, query, answer) VALUES (?, ?, ?, ?, ?)")
		if err != nil {
			panic(err)
		}
		defer stmt.Close()
		_, err = stmt.Exec(time.Now(), ip.String(), *domain, query, answer)
		if err != nil {
			panic(err)
		}

		if resp.Rcode == dns.RcodeSuccess && *domains != "" {
			for _, additionalDomain := range strings.Split(*domains, ",") {
				additionalMsg := dns.Msg{}
				additionalMsg.SetQuestion(dns.Fqdn(additionalDomain), dns.TypeA)

				additionalResp, _, err := client.Exchange(&additionalMsg, net.JoinHostPort(ip.String(), "53"))
				if err != nil {
					fmt.Printf("DNS error: %s\n", err)
					continue
				}

				additionalQuery := dnsQuestionToString(additionalMsg.Question[0])
				additionalAnswer := dnsRRToString(additionalResp.Answer)
				additionalStmt, err := db.Preparex("INSERT INTO dns_queries (timestamp, ip, domain, query, answer) VALUES (?, ?, ?, ?, ?)")
				if err != nil {
					panic(err)
				}
				defer additionalStmt.Close()
				_, err = additionalStmt.Exec(time.Now(), ip.String(), additionalDomain, additionalQuery, additionalAnswer)
				if err != nil {
					panic(err)
				}
			}
		}
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func dnsQuestionToString(q dns.Question) string {
	return fmt.Sprintf("%s %s", q.Name, dns.TypeToString[q.Qtype])
}

func dnsRRToString(rr []dns.RR) string {
	var str string
	for _, r := range rr {
		str += r.String() + "\n"
	}
	return str
}
