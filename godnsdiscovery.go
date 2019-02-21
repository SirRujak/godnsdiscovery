package godnsdiscovery

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var reIPv4 regexp.Regexp = *regexp.MustCompile("(?i)^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.\\d{1,3}$")
var rePort regexp.Regexp = *regexp.MustCompile("(?i)^\\d{1,5}$")
var reAddr regexp.Regexp = *regexp.MustCompile("^([^:]+)(?::(\\d{1,5})(?:,(\\d{1,5}))?)?$")

const typeLookup = 1
const typeAnnounce = 2
const typeUnannounce = 3

//func DNSDiscovery(opts ???someKindOfDictionary)

type DNSDiscoveryOpts struct {
	Retries      int
	Timeout      int
	TimoutChecks int
	MaxQueries   int
	MaxRedirects int
	Multicast    bool
	Socket       *net.UDPConn
	Server       string
	Servers      []string
	TTL          *int
	Limit        *int
	Loopback     bool
}

type DNSDiscovery struct {
	Socket  *net.UDPConn
	Sockets [](*net.UDPConn)
	Servers []DNSAddr
}

func (dnsDiscovery *DNSDiscovery) Init(opts DNSDiscoveryOpts) error {
	dnsDiscovery.Socket = opts.Socket
	var tempAddr *DNSAddr
	var err error
	if len(opts.Servers) > 0 {
		for i := 0; i < len(opts.Servers); i++ {
			tempAddr, err = ParseAddr(opts.Servers[i])
			if err != nil {
				return err
			}
			dnsDiscovery.Servers = append(dnsDiscovery.Servers, *tempAddr)
		}
	} else if opts.Server != "" {
		tempAddr, err = ParseAddr(opts.Server)
		if err != nil {
			return err
		}
		dnsDiscovery.Servers = append(dnsDiscovery.Servers, *tempAddr)
	}

	return nil
}

func (dnsDiscovery *DNSDiscovery) OnSocket(socket *net.UDPConn) error {
	dnsDiscovery.Sockets = append(dnsDiscovery.Sockets, socket)
	// TODO: What in the world to do here?
	return nil
}

type DNSAddr struct {
	Port          int
	SecondaryPort int
	Host          string
}

func ParseAddr(addr string) (*DNSAddr, error) {
	var err error
	if strings.Contains(addr, ":") {
		addr = addr + ":5300,53"
	}
	var match [][]string
	match = reAddr.FindAllStringSubmatch(addr, -1)
	if len(match) == 0 {
		return nil, errors.New("could not parse address: " + string(addr))
	}
	var tempAddr DNSAddr
	var port, secondaryPort int

	if len(match[0]) == 4 {
		port, err = strconv.Atoi(match[0][2])
		if err != nil {
			return nil, err
		}
		secondaryPort, err = strconv.Atoi(match[0][3])
		if err != nil {
			return nil, err
		}
		tempAddr = DNSAddr{
			Port:          port,
			SecondaryPort: secondaryPort,
			Host:          match[0][1],
		}
	}
	return &tempAddr, nil
}
