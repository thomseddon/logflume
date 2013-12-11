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

func handlePacket(buffer []byte, addr net.Addr) {
  parser := rfc5424.NewParser(buffer)
  err := parser.Parse()

  if err != nil {
    fmt.Printf("Error reading syslog message %s", err)
    return
  }

  log := parser.Dump()
  log["@timestamp"] = log["timestamp"]
  log["facility_label"] = "user-level"  // TODO
  log["severity_label"] = "Error"       // TODO
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

func main() {

  port := flag.String("port", "5544", "Port to listen on")
  esDomain := flag.String("elasticSearch", "localhost", "elastic search domain")
  flag.Parse()

  // Create udp socket
  conn, err := net.ListenPacket("udp4", ":" + *port)
  if err != nil {
    panic("Could not ListenUDP")
  }

  // Setup elastic search
  elasticSearchServer.Domain = *esDomain

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
