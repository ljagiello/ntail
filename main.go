package main

import (
    "fmt"
    "time"
    "github.com/jeromer/syslogparser/rfc3164"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
)

var (
    device      string = "eth3"
    snapshotLen int32  = 1600
    promiscuous bool   = false
    err         error
    timeout     time.Duration = 0 * time.Second
    handle      *pcap.Handle
)

func main() {
    handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
    if err != nil { panic(err) }
    err = handle.SetBPFFilter("udp and port 500")
    if err != nil { panic(err) }
    defer handle.Close()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        printPacketInfo(packet)
    }
}

func printPacketInfo(packet gopacket.Packet) {
    applicationLayer := packet.ApplicationLayer()
    if applicationLayer != nil {
        buff := []byte(applicationLayer.Payload())
        p := rfc3164.NewParser(buff)
        err := p.Parse()
        if err != nil {
            fmt.Println("Error decoding Payload:", err)
        }
        fmt.Printf("%s", p.Dump()["content"])
    }

    if err := packet.ErrorLayer(); err != nil {
        fmt.Println("Error decoding some part of the packet:", err)
    }
}
