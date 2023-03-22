# DNS Query Tool

The DNS Query Tool is a command-line tool that allows you to perform recursive DNS queries for a given domain name and network range, and stores the results in an SQLite database. It also supports querying multiple domains.

## Usage

To use the tool, run the following command:

```bash
go run main.go -domain <domain> -network <network> [-domains <domains>] [-timeout <timeout>] [-db <dbfile>]
```

### Flags

- domain: Initial domain to query
- network: The IPv4 network range to check (in CIDR format)
- domains: comma-separated list of additional domains to query
- timeout: Optional timeout for DNS queries in seconds (default is 5)
- db: Optional SQLite database file name (default is dns.db)
