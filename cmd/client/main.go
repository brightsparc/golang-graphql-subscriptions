package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/casbin/casbin-go-client/client"
	"google.golang.org/grpc"
)

func getModelText() string {
	return `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[role_definition]
g = _, _
g2 = _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = g(r.sub, p.sub) && g2(r.obj, p.obj) && r.act == p.act`
}

func testRequests() [][]interface{} {
	return [][]interface{}{
		{"john", "m1", "predict", true},  // Public allowed predict
		{"john", "m1", "read", false},    // Not allowed by default
		{"john", "m2", "read", true},     // Override to allow m2 read
		{"adam", "m1", "predict", true},  // inherit from engine
		{"adam", "e1", "read", true},     // allowed by engine
		{"adam", "e1", "write", true},    // allow by engine
		{"adam", "e2", "read", false},    // engine e2 doesn't exist
		{"matt", "m1", "write", true},    // allow by group 2
		{"matt", "m2", "write", true},    // allowed by group 1
		{"matt", "m3", "write", false},   // override deny
		{"bolek", "m1", "predict", true}, // inherits public
		{"bolek", "m1", "write", true},   // inherits model
		{"bolek", "e1", "write", false},  // override deny
		{"bolek", "m1", "delete", true},  // admin only permission
		{"bolek", "s1", "write", true},   // inherits source with admin
	}
}

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
	cfg := client.Config{DriverName: "redis", ConnectString: ":6379", ModelText: getModelText(), DbSpecified: true}
	e, err := c.NewEnforcer(ctx, cfg)
	if err != nil {
		panic(err)
	}

	// Add role permissions (role, object, action) effect allow is default
	e.AddPolicy(ctx, "role:DATA", "s1", "read", "allow")
	e.AddPolicy(ctx, "role:DATA", "s1", "write", "allow")
	e.AddPolicy(ctx, "role:ENGINES", "e1", "read", "allow")
	e.AddPolicy(ctx, "role:ENGINES", "e1", "write", "allow")
	e.AddPolicy(ctx, "role:PUBLIC", "m1", "predict", "allow")
	e.AddPolicy(ctx, "role:ADMIN", "m1", "delete", "allow")

	// Add role permissions for groups of models
	e.AddPolicy(ctx, "role:MODELS", "group:g1", "read", "allow")
	e.AddPolicy(ctx, "role:MODELS", "group:g1", "write", "allow")
	e.AddNamedGroupingPolicy(ctx, "g2", "m1", "group:g1")
	e.AddNamedGroupingPolicy(ctx, "g2", "m2", "group:g1")
	e.AddNamedGroupingPolicy(ctx, "g2", "m3", "group:g1")

	// Define role-to-role mapping (public->engines,modesl,data->admin)
	e.AddGroupingPolicy(ctx, "role:DATA", "role:PUBLIC")
	e.AddGroupingPolicy(ctx, "role:ENGINES", "role:PUBLIC")
	e.AddGroupingPolicy(ctx, "role:MODELS", "role:PUBLIC")
	e.AddGroupingPolicy(ctx, "role:ADMIN", "role:DATA")
	e.AddGroupingPolicy(ctx, "role:ADMIN", "role:ENGINES")
	e.AddGroupingPolicy(ctx, "role:ADMIN", "role:MODELS")
	// Specify user membership
	e.AddGroupingPolicy(ctx, "john", "role:PUBLIC")
	e.AddGroupingPolicy(ctx, "adam", "role:ENGINES")
	e.AddGroupingPolicy(ctx, "matt", "role:MODELS")
	e.AddGroupingPolicy(ctx, "bolek", "role:ADMIN")

	// Add overrides for specific users
	e.AddPolicy(ctx, "john", "m2", "read", "allow")
	e.AddPolicy(ctx, "matt", "m3", "write", "deny")
	e.AddPolicy(ctx, "bolek", "e1", "write", "deny")

	// Log the policy statements, and grouing policies
	fmt.Println("\nPolicy p")
	fmt.Println(e.GetPolicy(ctx))
	fmt.Println("\nGrouping Policy g")
	fmt.Println(e.GetGroupingPolicy(ctx))
	fmt.Println("\nGrouping Policy g2")
	fmt.Println(e.GetNamedGroupingPolicy(ctx, "g2"))

	for _, r := range testRequests() {
		if ok, _ := e.Enforce(ctx, r[0], r[1], r[2]); ok != r[3] {
			log.Fatalf("Unexpected request %v", r)
		}
	}

	fmt.Println("\nAll tests passed")
}
