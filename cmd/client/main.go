package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/casbin/casbin-go-client/client"
	"google.golang.org/grpc"
)

func main() {
	var port int
	flag.IntVar(&port, "port", 50051, "listening port")
	flag.Parse()

	if port < 1 || port > 65535 {
		panic(fmt.Sprintf("invalid port number: %d", port))
	}

	log.Println("Sending to", port)

	ctx := context.Background()
	c, err := client.NewClient(ctx, fmt.Sprintf(":%d", port), grpc.WithInsecure())
	if err != nil {
		panic(err)
	}

	// Load the existing
	cfg := client.Config{DriverName: "redis", ConnectString: ":6379", ModelText: "", DbSpecified: true}
	enforcer, err := c.NewEnforcer(ctx, cfg)
	if err != nil {
		panic(err)
	}

	// Test adding some stuff
	enforcer.AddRoleForUser(ctx, "user1", "role1")
	enforcer.AddRoleForUser(ctx, "user1", "role2")
	enforcer.AddRoleForUser(ctx, "user2", "role3")
}
