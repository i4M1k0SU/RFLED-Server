package main

import (
        "flag"
        "log"
        "net"
        "os/exec"
        "os/user"
        "os"
        "strconv"
        "strings"
        "sync"
        "github.com/tarm/serial"
        "reflect"
        "time"
        "math/rand"
        "encoding/binary"
        "encoding/hex"
)

// Logging function used by the application
// w: false = log, true = fatal
// x: debug flag
// y: false = not debug output, true = debug output
// z: message
func applog(w bool, x bool, y bool, z string) {
        if x && y {
                if !w {
                        log.Printf("DEBUG: %q \n", z)
                } else {
                        log.Fatal("DEBUG: ", z)
                }
        } else if !y {
                if !w {
                        log.Printf("%q \n", z)
                } else {
                        log.Fatal(z)
                }
        }
}

// Used to clean up all the error checks we do
func error_check(err error, log bool) {
        if err != nil {
                applog(true, log, false, err.Error())
        }
}

func createSessionId() []byte {
        rand.Seed(time.Now().Unix())
        bs := make([]byte, 2)
        binary.LittleEndian.PutUint16(bs, uint16(rand.Intn(65535)))
        return bs
}

// Function to check and work with LED control packets
func led_server(conn *net.UDPConn, log bool, s *serial.Port, macHex []byte) {
        var createSessionRequestValue = []byte {
                0x20, 0x00, 0x00, 0x00, 0x16, 0x02, 0x62, 0x3A,
                0xD5, 0xED, 0xA3, 0x01, 0xAE, 0x08, 0x2D, 0x46,
                0x61, 0x41, 0xA7, 0xF6, 0xDC, 0xAF, 0xD3, 0xE6,
                0x00, 0x00,
        }

        var createSessionResponseValue []byte
        var sessionId []byte
        var count uint8 = 5

        buf := make([]byte, 64)
        msg, remoteAddr, err := 0, new(net.UDPAddr), error(nil)
        for err == nil {
                msg, remoteAddr, err = conn.ReadFromUDP(buf)
                error_check(err,log)
                if buf != nil {
                      applog(false, log, true, "LED: message was " + string(buf[:msg]) + " from " + remoteAddr.String())
                      // session create
                      if reflect.DeepEqual(buf[:(msg - 1)], createSessionRequestValue) {
                              count = 5
                              sessionId = createSessionId()
                              createSessionResponseValue = []byte {0x28, 0x00, 0x00, 0x00, 0x11, 0x00, 0x02}
                              createSessionResponseValue = append(createSessionResponseValue, macHex...)
                              createSessionResponseValue = append(createSessionResponseValue, []byte {0x54, 0x07, 0x85, 0x00, 0x00}...)
                              createSessionResponseValue = append(createSessionResponseValue, sessionId...)
                              createSessionResponseValue = append(createSessionResponseValue, []byte {0x00, 0x00}...)
                              _, err = conn.WriteToUDP(createSessionResponseValue, remoteAddr)
                      } else {
                              // Write to serial
                              _, err = s.Write(buf[10:msg])
                              _, err = conn.WriteToUDP([]byte{ 0x88, 0x00, 0x00, 0x00, 0x03, 0x00, count, 0x00 },remoteAddr)
                              count++
                      }
                      error_check(err,log)
                }
        }
        error_check(err,log)
}

// Function to check and work with admin config packets
func adm_server(conn *net.UDPConn, log bool, ip string, mac string, hostname string) {
        buf := make([]byte, 64)
                msg, remoteAddr, err := 0, new(net.UDPAddr), error(nil)
        for err == nil {
                msg, remoteAddr, err = conn.ReadFromUDP(buf)
                error_check(err,log)
                if buf != nil {
                        applog(false, log, true, "ADM: message was " + string(buf[:msg]) + " from " + remoteAddr.String())

                        var value string
                        if strings.Contains(string(buf[:msg]),"HF-A11ASSISTHREAD") {
                                value = ip+","+mac+","+hostname
                        } else {
                                value = "+ok"
                        }
                        _,err = conn.WriteToUDP([]byte(value),remoteAddr)
                        error_check(err,log)
                        applog(false, log, true, "ADM: replied "+value)
                }
        }
        error_check(err,log)
}

func getHostName() string {
        hostname, err := os.Hostname()
        if err != nil {
                hostname = "HF-LPB100"
        }
        return hostname
}

func parseMacAddress(str string) (string, []byte) {
        macStr := strings.ToUpper(strings.Replace(str,":","",-1))
        macHex, err := hex.DecodeString(macStr)
        if err != nil {
                macHex = []byte{ 0xf0, 0xfe, 0x6b, 0x00, 0x00, 0x00 }
                macStr = "F0FE6B000000"
        }
        return macStr, macHex
}

func main() {
        var wg sync.WaitGroup

        // Set our UART vars
        comport := flag.String("serial", "/dev/ttyAMA0", "Serial device to use")
        comspeed := flag.Int("baud", 38400, "Serial baudrate")
        debug := flag.Bool("debug", false, "Enable verbose debugging")

        // Set our IP vars
        ip := flag.String("ip", "0.0.0.0", "IP address to listen on (LED Server)")
        interf := flag.String("int", "eth0", "Interface to listen on, used for mac address")
        adm_port := flag.Int("admport", 48899, "Port for the admin server")
        led_port := flag.Int("ledport", 5987, "Port for the led server")
        flag.Parse()

        // Check if we are root
        usr,err := user.Current()
        if err != nil {
                applog(false, *debug, true, "Error with user.Current(), failing back...")
                // If we are here, we are prob on arm which does NOT support user.Current()
                usr, err := exec.Command("whoami").Output()
                error_check(err,*debug)
                if string(usr) != "root\n" {
                        applog(false, *debug, true, "Current user us "+string(usr))
                        applog(true, *debug, false, "Not running as root, exiting!")
                }
        } else if usr.Uid != "0" {
                applog(true, *debug, false, "Not running as root, exiting!")
        }

        // Load our interface information based on user input, used for admin server
        var ethz *net.Interface
        if *ip == "0.0.0.0" {
                // lookup interface using interf
                ethz, err = net.InterfaceByName(*interf)
                if err != nil {
                        applog(true, *debug, false, "Error, unable to lookup interface "+*interf+"!")
                }
                applog(false, *debug, true, "IntLookup vars: eth="+string(ethz.Name)+" ip="+*ip)
        } else {
                // lookup interface using IP
                applog(false, *debug, true,"Looking up all interfaces")
                list, err := net.Interfaces()
                found := false
                error_check(err,*debug)
                for _, iface := range list {
                        applog(false, *debug, true, "Int="+iface.Name)
                        addrs, err := iface.Addrs()
                        error_check(err,*debug)
                        for _, addr := range addrs {
                                applog(false, *debug, true, "  IP="+addr.String())
                                if strings.Contains(addr.String(),*ip) {
                                        applog(false, *debug, true, "Found our interface!")
                                        ethz = &iface
                                        found = true
                                        break
                                }
                        }
                }
                if !found {
                        applog(true, *debug, false, "Error, unable to find an interface with the IP of "+*ip)
                }
        }

        // Once we found our Interface we can then get the IP/Mac (unless we have one manually set)
        mymac, mymacHex := parseMacAddress(ethz.HardwareAddr.String())
        hostname := getHostName()
        if *ip == "0.0.0.0" {
                addrs, err := ethz.Addrs()
                error_check(err,*debug)
                for _, addr := range addrs {
                        // Find and remove the SubNet from the IP and set to var
                        *ip = addr.String()[:strings.Index(addr.String(),"/")]
                        break
                }
        }
        // Make sure we got our mac! (sometimes lo will not return one)
        if len(mymac) < 12 {
                applog(true, *debug, false, "Error, unable to lookup mac address for interface!")
        }
        applog(false, *debug, true,"Our Info: mac="+mymac+" ip="+*ip+" hostname="+hostname)

        // load serial connection
        c := &serial.Config{Name: *comport, Baud: *comspeed}
        s, err := serial.OpenPort(c)
        error_check(err,*debug)

        // Start Admin server
        adm_addr, err := net.ResolveUDPAddr("udp", ":"+strconv.Itoa(*adm_port))
        error_check(err,*debug)
        adm_listen, err := net.ListenUDP("udp", adm_addr)
        error_check(err,*debug)
        defer adm_listen.Close()

        // Start LED server
        led_addr, err := net.ResolveUDPAddr("udp", *ip+":"+strconv.Itoa(*led_port))
        error_check(err,*debug)
        led_listen, err := net.ListenUDP("udp", led_addr)
        error_check(err,*debug)
        defer led_listen.Close()

        // Start main app loop!
        applog(false, *debug, false, "rfled-server started!")

        // Function for Admin Server
        wg.Add(1)
        go adm_server(adm_listen, *debug, *ip, mymac, hostname)

        // Function for LED Server
        wg.Add(1)
        go led_server(led_listen, *debug, s, mymacHex)

        wg.Wait()
}
