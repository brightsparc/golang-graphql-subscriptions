package main

import (
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
)

func testEnforce(t *testing.T, e *casbin.Enforcer, request []interface{}) {
	t.Helper()
	if myRes, _ := e.Enforce(request[0], request[1], request[2]); myRes != request[3] {
		t.Errorf("%s, %v, %s: %t, supposed to be %t", request[0], request[1], request[2], myRes, request[3])
	}
}

func TestModel(t *testing.T) {
	m, _ := model.NewModelFromString(getModelText())
	a := fileadapter.NewAdapter("rbac_policy.csv")
	e, _ := casbin.NewEnforcer(m, a)
	for _, request := range testRequests() {
		testEnforce(t, e, request)
	}
}
