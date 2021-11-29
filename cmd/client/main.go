package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/casbin/casbin-go-client/client"
	"github.com/schollz/progressbar/v3"
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

func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("%s took %s", name, elapsed)
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

const letterBytes = "abcdefghijklmnopqrstuvwxyz"

func randString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func main() {
	var port, userCount, objectCount int
	var overrideProb float64
	flag.IntVar(&port, "port", 50051, "listening port")
	flag.IntVar(&userCount, "userCount", 0, "number of users to generate")
	flag.IntVar(&objectCount, "objectCount", 0, "number of objects to generate per user")
	flag.Float64Var(&overrideProb, "overrideProb", 0.1, "percent that user has override")
	flag.Parse()

	if port < 1 || port > 65535 {
		panic(fmt.Sprintf("invalid port number: %d", port))
	}

	log.Println("Connecting to client on port: ", port)
	ctx := context.Background()
	c, err := client.NewClient(ctx, fmt.Sprintf(":%d", port), grpc.WithInsecure())
	if err != nil {
		panic(err)
	}

	log.Println("Loading enforcer...")
	cfg := client.Config{DriverName: "redis", ConnectString: ":6379", ModelText: getModelText(), DbSpecified: true}
	e, err := c.NewEnforcer(ctx, cfg)
	if err != nil {
		panic(err)
	}

	// Add policy files over GRPC
	log.Println("Adding default rules...")

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

	roleIds := []string{"role:ENGINES", "role:MODELS", "role:DATA", "role:ADMIN", "role:PUBLIC"}
	objTypes := []string{"e", "m", "s"}
	actTypes := []string{"read", "write", "predict", "delete"}
	eftTypes := []string{"allow", "deny"}

	if userCount > 0 {
		log.Printf("Generating %d objects...", objectCount)
		// For each object type, create a series of policies for action and effect
		bar := progressbar.Default(int64(objectCount))
		for i := 0; i < objectCount; i++ {
			j := rand.Intn(len(objTypes))
			objType := objTypes[j]
			typeId := fmt.Sprintf("%s%d", objType, i)
			// Get a random selection of actions
			for _, k := range rand.Perm(rand.Intn(len(actTypes))) {
				roleId := roleIds[j]
				eft := eftTypes[rand.Intn(len(eftTypes))]
				act := actTypes[k]
				e.AddPolicy(ctx, roleId, typeId, act, eft)
			}
			bar.Add(1)
		}
		log.Printf("Generating %d users...", userCount)
		bar = progressbar.Default(int64(userCount))
		for i := 0; i < userCount; i++ {
			userId := randString(32)
			roleId := roleIds[rand.Intn(len(roleIds))]
			// Add user to random role
			e.AddGroupingPolicy(ctx, userId, roleId)
			// Add override if less than prob
			if rand.Float64() < overrideProb {
				typeId := fmt.Sprintf("%s%d", objTypes[rand.Intn(len(objTypes))], rand.Intn(objectCount)+1)
				act := actTypes[rand.Intn(len(actTypes))]
				eft := eftTypes[rand.Intn(len(eftTypes))]
				e.AddPolicy(ctx, userId, typeId, act, eft)
			}
			bar.Add(1)
		}
	}

	// Test policy files over GRPC
	defer timeTrack(time.Now(), "Tests completed in")
	for _, r := range testRequests() {
		if ok, _ := e.Enforce(ctx, r[0], r[1], r[2]); ok != r[3] {
			log.Printf("Unexpected request %v", r)
		}
	}

	log.Println("\nAll tests passed")
}
