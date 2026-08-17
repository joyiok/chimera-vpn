package main

import "testing"

func TestUpsertServer(t *testing.T) {
	var list []savedServer
	list = upsertServer(list, "home", "10.0.0.1:4789")
	list = upsertServer(list, "vps", "1.2.3.4:4789")
	list = upsertServer(list, "home-lan", "10.0.0.1:4789")
	if len(list) != 2 {
		t.Fatalf("len=%d", len(list))
	}
	if list[0].Name != "home-lan" || list[0].Addr != "10.0.0.1:4789" {
		t.Fatalf("%+v", list[0])
	}
	list = upsertServer(list, "", "   ")
	if len(list) != 2 {
		t.Fatal("blank addr should be ignored")
	}
}
