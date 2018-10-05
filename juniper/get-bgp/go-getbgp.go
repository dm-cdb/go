// A small portable Juniper looking-glass
// Makes use of netconf to connect to router and execute a "show route X.X.X.X/N detail"
// Retrieve and display quick route infos
// Christian de Balorre 01/09/2018, unrestricted use

package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"github.com/Juniper/go-netconf/netconf"
	"golang.org/x/crypto/ssh"
	"log"
	"net"
	"os"
	"strings"
)
// netconf port ; default is 830 - RFC 4742
const port = "22"
// Username info to connect to router
var user string = "putyouruser"
var sym string = "putyourpass"

// Route struct models the xml representation of show route cde
type Route struct {
	XMLName xml.Name   `xml:"rpc-reply"`
	Table   string     `xml:"route-information>route-table>table-name"`
	Rt      RouteEntry `xml:"route-information>route-table>rt"`
}

type RouteEntry struct {
	Dest  string `xml:"rt-destination"`
	Entry [] struct {
		Proto  string `xml:"protocol-name"`
		Age    string `xml:"age"`
		AsPath string `xml:"as-path"`
		Communities [] string `xml:"communities>community"`
	} `xml:"rt-entry"`
}

func main() {
	host := flag.String("d", "", "hostname or ip address")
	route := flag.String("r", "", "route prefix")
	flag.Parse()

	if *host == "" {
		fmt.Printf("Usage : go-getbgp --d <hostname> --r <route>\n")
		log.Fatal("Provide device hostname or ip address")
	}
        if *route == "" {
                fmt.Printf("usage : go-getbgp --d <hostname> --r <route>\n")
                log.Fatal("Provide a valid ip route")
        }

	_, _, err := net.ParseCIDR(*route)
	if err != nil {
		log.Fatal("Provide a valid IP route (ie x.x.x.x/n)")
	}

	// netconf initialization & connection
	sshConfig := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(sym)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	var hostname string = *host + ":" + port
	s, err := netconf.DialSSH(hostname, sshConfig)

	if err != nil {
		log.Fatal(err)
	}

	defer s.Close()

	// Sends rpc cde in XML
	var rpc_cde string = "<get-route-information><destination>" + *route + "</destination><detail/></get-route-information>"
	reply, err := s.Exec(netconf.RawMethod(rpc_cde))
	if err != nil {
		panic(err)
	}
	// initialize a Route struct to be populated by xml response
	var q Route
	err = xml.Unmarshal([]byte(reply.RawReply), &q)
	if err != nil {
		log.Fatal(err)
	}
	if q.Table == "" {
		fmt.Printf("%s : No route found for prefix %s\n", *host, *route)
		s.Close()
		os.Exit(3)
	}
	// print route information
	fmt.Println()
	fmt.Printf("%s : %d routes in routing table %s for prefix %s\n", *host, len(q.Rt.Entry), q.Table, q.Rt.Dest)
	fmt.Println()
	for i := 0; i < len(q.Rt.Entry); i++ {
		var comm string
		if len(q.Rt.Entry[i].Communities) > 0 {
		        comm = strings.Join(q.Rt.Entry[i].Communities, " ")
		}
		fmt.Printf("  Protocol        : %s\n", q.Rt.Entry[i].Proto)
		fmt.Printf("    Age           : %s\n", q.Rt.Entry[i].Age)
		fmt.Printf("    As path       : %s", q.Rt.Entry[i].AsPath) // AsPath contains a line feed (0x0a)
		fmt.Printf("    Communities   : %s\n", comm)
		fmt.Println()
	} // end for
} // end main
