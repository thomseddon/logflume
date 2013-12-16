/**
 * LogFlume
 *
 * Copyright (c) 2013-present Thom Seddon
 */

package main

import (
  "flag"
  "fmt"
  "net"
  "time"
  "github.com/jeromer/syslogparser/rfc5424"
  elasticSearchServer "github.com/mattbaird/elastigo/api"
  elasticSearch "github.com/mattbaird/elastigo/core"
)

var FACILITY_LABELS = [...]string{
  "kernel",
  "user-level",
  "mail",
  "daemon",
  "security/authorization",
  "syslogd",
  "line printer",
  "network news",
  "uucp",
  "clock",
  "security/authorization",
  "ftp",
  "ntp",
  "log audit",
  "log alert",
  "clock",
  "local0",
  "local1",
  "local2",
  "local3",
  "local4",
  "local5",
  "local6",
  "local7",
}

var SEVERITY_LABELS = [...]string{
  "emergency",
  "alert",
  "critical",
  "error",
  "warning",
  "notice",
  "informational",
  "debug",
}

func handlePacket (buffer []byte, addr net.Addr) {
  parser := rfc5424.NewParser(buffer)
  err := parser.Parse()

  if err != nil {
    fmt.Printf("Error reading syslog message %s", err)
    return
  }

  log := parser.Dump()
  log["@timestamp"] = log["timestamp"]
  log["facility_label"] = FACILITY_LABELS[(log["facility"]).(int)]
  log["severity_label"] = SEVERITY_LABELS[(log["severity"]).(int)]
  log["type"] = "syslog"

  now := time.Now()
  index := "logstash-" + now.Format("2006.01.02")

  _, err = elasticSearch.Index(true, index, "logs", "", log)
  if err != nil {
    fmt.Printf("Error indexing message %s", err)
    return
  }
  fmt.Println("Logged")
}

func udpserver (laddr string) {
  // Create udp socket
  conn, err := net.ListenPacket("udp4", laddr)
  if err != nil {
    panic("Could not ListenUDP")
  }

  for {
    buffer := make([]byte, 1024)
    rlen, addr, err := conn.ReadFrom(buffer)

    if err != nil {
      fmt.Printf("Error reading from udp connection")
      continue
    }

    go handlePacket(buffer[:rlen - 1], addr)
  }
}

func main () {

  domain := flag.String("domain", "localhost", "Domain to listen on")
  port := flag.String("port", "5544", "Port to listen on")
  esDomain := flag.String("elasticSearch", "localhost", "elastic search domain")
  flag.Parse()

  // Setup elastic search
  elasticSearchServer.Domain = *esDomain

  udpserver(*domain + ":" + *port)
}
