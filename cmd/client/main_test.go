package main

import (
	"testing"

	"github.com/casbin/casbin/v2"
)

func testEnforce(t *testing.T, e *casbin.Enforcer, r []interface{}) {
	t.Helper()
	if myRes, _ := e.Enforce(r[0], r[1], r[2], r[3]); myRes != r[4] {
		t.Errorf("%s, %v, %v, %s: %t, supposed to be %t", r[0], r[1], r[2], r[3], myRes, r[4])
	}
}

func TestModel(t *testing.T) {
	e, _ := casbin.NewEnforcer("rbac_policy.conf", "rbac_policy.csv")

	t.Log("Policy", e.GetPolicy())
	t.Log("Grouping Policy", e.GetGroupingPolicy())
	t.Log("Named Grouping Policy g2", e.GetNamedGroupingPolicy("g2"))

	for _, request := range testRequests("d1") {
		testEnforce(t, e, request)
	}
}
