package aws

import (
	"reflect"
	"testing"
	"time"
)

func TestBuildInventorySnapshot(t *testing.T) {
	snapshot := BuildInventorySnapshot(time.Date(2026, 3, 11, 12, 0, 0, 0, time.UTC), []Asset{
		{AccountID: "123456789012", Region: "us-west-2", Service: "ec2", AssetType: "instance", ResourceID: "i-1", Name: "api", Target: "api.example.net", Public: true, Source: "aws"},
		{AccountID: "123456789012", Region: "us-east-1", Service: "cloudfront", AssetType: "distribution", ResourceID: "dist-1", Target: "d123.cloudfront.net", Public: true, Source: "aws"},
	}, DiscoverOptions{
		Regions: []string{"us-west-2", "us-east-1"},
		Include: []string{"*.example.net"},
		Exclude: []string{"internal.example.net"},
	})

	if snapshot.Source != "aws" {
		t.Fatalf("unexpected source: %s", snapshot.Source)
	}
	if snapshot.AssetCount != 2 {
		t.Fatalf("unexpected asset count: %d", snapshot.AssetCount)
	}
	if !reflect.DeepEqual(snapshot.Accounts, []string{"123456789012"}) {
		t.Fatalf("unexpected accounts: %v", snapshot.Accounts)
	}
}
