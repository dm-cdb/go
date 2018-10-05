// Query a Juniper device via snmp for chassis alarms
// Then retrieve critical alarm via netconf
// Christian de Balorre 01/09/2018, unrestricted use

package main

import (
	"fmt"
	"log"
	"strings"
	"flag"
        "encoding/xml"
	"github.com/Juniper/go-netconf/netconf"
	"golang.org/x/crypto/ssh"
	"github.com/alouca/gosnmp"
)
const port = "22"
const oid = "1.3.6.1.4.1.2636.3.4.2.3.1.0"
const cty = "putyoursnmpcommunity"
var user string = "putnetconf username"
var sym string = "putsecret"


type RpcCde struct {
	XMLName xml.Name `xml:"rpc-reply"`
	Alarm ChassisAlarm `xml:"alarm-information"`
}

type ChassisAlarm struct {
	AlarmSum string `xml:"alarm-summary>active-alarm-count"`
	AlarmEpoch struct {
		Epoch uint32 `xml:"seconds,attr"`
		Date string `xml:",chardata"`
	} `xml:"alarm-detail>alarm-time"`
	AlarmDesc string `xml:"alarm-detail>alarm-description"`
}

func main() {

	host := flag.String("ip", "", "hostname or ip address")
	flag.Parse()

	if *host == "" {
		fmt.Printf("usage : go-chassisalarm --ip <hostname>\n")
		log.Fatal("Please provide a hostname or ip address")
	}
	var hostname string = *host + ":" + port
        
	s, err := gosnmp.NewGoSNMP(*host, cty, gosnmp.Version2c, 3)
        resp, err := s.Get(oid)
	var isred int = 0
	var ok bool

	if err != nil {
                log.Fatal(err)
	        } else {
			if isred, ok = resp.Variables[0].Value.(int); !ok {
				log.Fatal("Error in return value ; should be an int")
			}
	        }

        if  isred == 3 {
	        sshConfig := &ssh.ClientConfig{
	        	User:            user,
		        Auth:            []ssh.AuthMethod{ssh.Password(sym)},
		        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	        }
	        s, err := netconf.DialSSH(hostname, sshConfig)
	        if err != nil {
	        	log.Fatal(err)
	        }
	        defer s.Close()

	     // fmt.Println(s.ServerCapabilities)
	     // fmt.Println(s.SessionID)
	        reply, err := s.Exec(netconf.RawMethod("<get-alarm-information/>"))
	        if err != nil {
	        	panic(err)
	        }
	        var q RpcCde
	        err = xml.Unmarshal([]byte(reply.RawReply), &q)
	        if err != nil {
                        log.Fatal(err)
                }

	        fmt.Printf("Alarm summary     : %s\n", q.Alarm.AlarmSum)
	        fmt.Printf("Alarm epoch       : %d\n", q.Alarm.AlarmEpoch.Epoch)
	        fmt.Printf("Alarm date        : %v\n", strings.Trim(q.Alarm.AlarmEpoch.Date, "\r\n"))
	        fmt.Printf("Alarm description : %s\n", q.Alarm.AlarmDesc)
	} // endif isred
} // endmain

