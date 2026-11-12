package main

import (
	"log"
	"net"
	"os"

	agentpb "github.com/zandieh/paradise-panel/agent/proto"
	"github.com/zandieh/paradise-panel/agent/internal/server"
	"github.com/zandieh/paradise-panel/agent/internal/tlsutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	tlsCfg, err := tlsutil.ServerConfig(
		env("AGENT_CERT", "/etc/paradise/agent.crt"),
		env("AGENT_KEY", "/etc/paradise/agent.key"),
		env("CA_CERT", "/etc/paradise/ca.crt"),
	)
	if err != nil {
		log.Fatal(err)
	}

	lis, err := net.Listen("tcp", env("LISTEN", ":9443"))
	if err != nil {
		log.Fatal(err)
	}

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	agentpb.RegisterAgentServiceServer(srv, server.New(
		env("XRAY_API", "127.0.0.1:10085"),
		env("XRAY_CONFIG", "/etc/xray/config.json"),
	))

	log.Printf("عامل پارادایس نت روی %s (mTLS) گوش می‌دهد", lis.Addr())
	log.Fatal(srv.Serve(lis))
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
