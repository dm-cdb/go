package main

import (
        //"fmt" //used in debug
        "strings"
        "strconv"
        "net"
        "os"
        "io/ioutil"
        "sync"
        "log"
        "log/syslog"
        "syscall"
        "encoding/binary"
        "encoding/json"
        "reflect"
        "math/rand"
        "time"
)

type IpHeader struct {
        Ipv uint16
        Ipl uint16
        Ipid uint16
        Ipfrag uint16
        Ipttlprot uint16
        Ipcsum uint16
        IpsrcHi uint16
        IpsrcLo uint16
        IpdstHi uint16
        IpdstLo uint16
}

type UdpHeader struct {
        Portsrc uint16
        Portdst uint16
        Udpl uint16
        Udpcsum uint16
}

type PseuHeader struct {
        SrcHi uint16
        SrcLo uint16
        DstHi uint16
        DstLo uint16
        Proto uint16
        Udpl uint16
}
// json config file struct
type Config struct {
        Listen struct {
                Address string `json:"Address"`
                Port    string `json:"Port"`
        } `json:"Listen"`

        Targets []ServerJson `json:"Targets"`
        mu sync.Mutex
}

type ServerJson struct {
        Server string `json:"Server"`
}

var (
    conf Config
    confPath string
    ch = make(chan int, 1)
    cherr = make(chan error, 100)
)

func watchFile(fpath string){
        throttle := time.Tick(time.Second * 10) 
        initStat, err := os.Stat(fpath)
        if err != nil {
                log.Fatal("stat conf file : ", err)
        }
        for {
                stat, err := os.Stat(fpath)
                if err != nil {
                       cherr <- err
                       <- throttle
                       continue
                }
                if stat.ModTime() != initStat.ModTime() {
                        ch <- 1
                        initStat, _ = os.Stat(fpath)
                }

        time.Sleep(2 * time.Second)
    }

}
      


func loadConfig(reload bool)(string) {
        if reload { log.Println("reloading config") }
        confFile, err := ioutil.ReadFile("udpreplic.json")
        if err == nil {
                confPath = "udpreplic.json"
        } else {
                confFile, err = ioutil.ReadFile("/etc/default/udpreplic.json")
                if err == nil {
                        confPath = "/etc/default/udpreplic.json"
                } else {
                        log.Println("open conf file : ", err)
                        if !reload {
                                os.Exit(1)
                        }
                }
        }
        conf.mu.Lock()
        defer conf.mu.Unlock()
        err = json.Unmarshal(confFile, &conf) 
        if (err != nil) {
                log.Println("config parsing error:", err)
                if !reload {
                        os.Exit(1)
                }
        }
        // check Targets ip:port syntax
        for _, e := range conf.Targets {
                _, err := net.ResolveUDPAddr("udp4", e.Server)
                if err != nil {
                       log.Println("conf file : ", err)
                       if !reload {
                                os.Exit(1)
                        }
                }
                log.Println("Targeting : ", e.Server)
        }
        return confPath
}

func main() {

        // Some init
        rand.Seed(time.Now().UTC().UnixNano()) //Seed the random identification ip header field
        sysLog, err := syslog.New(syslog.LOG_NOTICE, "")
        if err == nil {
                log.SetOutput(sysLog)
        }
        confPath := loadConfig(false)
        go watchFile(confPath)
        go func (){
                for {
                        select {
                        case err := <- cherr:
                                log.Println(err)
                        case <- ch:
                                _ = loadConfig(true)
                        }
                }
        }()

        // Open a regular udp socket for reading, rawsocket for writing
        if conf.Listen.Address == "*" {
                conf.Listen.Address = ""
        }
        service := conf.Listen.Address + ":" + conf.Listen.Port
        bind, _ :=  net.ResolveUDPAddr("udp4", service)
        conn, err := net.ListenUDP("udp4", bind)
        if err != nil {
                log.Fatal("udp socket binding error : ", err)
        }
        defer conn.Close()
        fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
        if err != nil {
                log.Fatal("syscall socket error : ", err)
        }
        defer syscall.Close(fd)

        //var count int // debug:packet counter
        buf := make([]byte, 65535)
        var iph IpHeader
        var psh PseuHeader
        var udpH UdpHeader
        var currTargets []ServerJson

        for {
                n, rAddr, _ := conn.ReadFromUDP(buf)
                // compute immediate ip &udp fields from udp socket info
                remote := strings.Split(rAddr.String(), ":")
                srcIP   := binary.BigEndian.Uint32(net.ParseIP(remote[0]).To4())
                srcIPHI := uint16(srcIP >> 16)
                srcIPLO := uint16(srcIP)
                ipID    := uint16(1 + rand.Intn(65534))
                ipL     := uint16(20 + 8 + n)
                srcport, _ := strconv.ParseUint(remote[1], 10, 16)

                // loops all ip targets and build custom datagram header
                conf.mu.Lock()
                currTargets = conf.Targets
                conf.mu.Unlock()
                for _, e := range currTargets {
                        //start := time.Now() //debug:packet chrono
                        headerbuf := make([]byte, 28)

                        // build common ip, pseudo, udp basic header 
                        iph = IpHeader{ 0x4500, 0x0, 0x0, 0x0, 0x4011, 0x0, 0x0, 0x0, 0x0, 0x0 }
                        iph.Ipl = ipL
                        iph.Ipid = ipID
                        iph.IpsrcHi = srcIPHI
                        iph.IpsrcLo = srcIPLO
                        psh = PseuHeader{ iph.IpsrcHi, iph.IpsrcLo, 0x0, 0x0, 17, uint16(8 + n)}
                        udpH = UdpHeader{ uint16(srcport), 0x0, uint16(8 + n), 0x0}

                        // compute variable ip, pseudo, udp basic header
                        if _, err := net.ResolveUDPAddr("udp4", e.Server); err != nil {
                                log.Fatal(err)
                        }
                        dst := strings.Split(e.Server, ":")
                        dstip := binary.BigEndian.Uint32(net.ParseIP(dst[0]).To4())//convert 4 IP byte slice to int32
                        dstport, _ := strconv.ParseUint(dst[1], 10, 16)

                        // build variable IP, pseudoIP, udp header fields
                        iph.IpdstHi = uint16(dstip >> 16)
                        iph.IpdstLo = uint16(dstip)
                        psh.DstHi = iph.IpdstHi
                        psh.DstLo = iph.IpdstLo
                        udpH.Portdst = uint16(dstport)

                        // build datagram header and checksum
                        buildIpH(&iph, headerbuf)
                        buildUdpH(buf[:n], headerbuf[20:], &udpH, &psh)
                        headerbuf = append(headerbuf, buf[:n]...)

                        // forward modified packet
                        var byteIP [4]byte
                        copy(byteIP[:], []byte(net.ParseIP(dst[0]).String()))
                        addr := syscall.SockaddrInet4{
                                Port: 0,
                                Addr: byteIP,
                        }
                        err = syscall.Sendto(fd, headerbuf, 0, &addr)
                        if err  != nil {
                                log.Println(err)
                       }
                       //debug:packet chrono
                       //end := time.Now()
                       //count++
                       //fmt.Printf("Processing %dth packet(s) in %v\n", count, end.Sub(start))
                }
        }
}

func buildUdpH(bytes []byte, hbuf []byte, udph *UdpHeader, pheader *PseuHeader) {
        // force clearing of checksum UDP fields bytea ; add byte in case payload is odd
        hbuf[6] = 0
        hbuf[7] = 0
        if udph.Udpl % 2 != 0 {
                bytes = append(bytes, 0)
        }
        var csum uint32

        // Compute udpsum 1) : sum of 16bits ip pseudo-header
        v1 := reflect.ValueOf(*pheader)
        for i := 0; i < v1.NumField(); i++ {
                csum += uint32(v1.Field(i).Interface().(uint16))
        }
        //  Compute udpsum 2) : sum of 16bits udp header & populate udp header
        v2 := reflect.ValueOf(*udph)
        for i := 0; i < v2.NumField(); i++ {
                value := v2.Field(i).Interface().(uint16)
                csum += uint32(value)
                binary.BigEndian.PutUint16(hbuf[i*2:], value)
        }
        // Compute udpsum 3) : sum of 16bits udp payload
        for i := 0; i < len(bytes); i += 2 {
                csum += (uint32(bytes[i]) << 8) + uint32(bytes[i+1])
        }
        // Compute udpsum 4) : csum 16 bits overflow computation
        for csum > 65535 {
                csum = (csum >> 16) + (csum &0xffff) //add 16bits upper part to 16bits lower
        }
        // Flip all the bits
        // udph.Udpcsum = uint16(^csum) debug:
        binary.BigEndian.PutUint16(hbuf[6:], uint16(^csum))
}


func buildIpH(header *IpHeader, hbuf []byte){
        var csum uint32
        // clear checksum IP fields byte
        hbuf[10] = 0
        hbuf[11] = 0
        v := reflect.ValueOf(*header)
        // Compute checksum 1) : sum of all 16bits ip header field
        for i := 0; i < v.NumField(); i++ {
                value := v.Field(i).Interface().(uint16)
                csum += uint32(value)
                binary.BigEndian.PutUint16(hbuf[i*2:], value)
        }
        // Compute checksum 2) : csum 16 bits overflow computation
        for {
                // Break when sum is less or equals to 0xFFFF
                if csum <= 65535 {
                        break
                }
                // Add carry to the sum
                csum = (csum >> 16) + uint32(uint16(csum))
        }
        // Compute checksum 3) : Flip all the bits - one complement - and modify struct field
        // header.Ipcsum = uint16(^csum) debug:
        binary.BigEndian.PutUint16(hbuf[10:], uint16(^csum))
}
