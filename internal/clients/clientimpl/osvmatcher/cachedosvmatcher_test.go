package osvmatcher

import (
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"sync"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"osv.dev/bindings/go/api"
	"osv.dev/bindings/go/osvdev"
)

func TestCachedOSVMatcher_buildQueryPlanDeduplicatesRepeatedPackages(t *testing.T) {
	t.Parallel()

	matcher := &CachedOSVMatcher{}
	matcher.vulnCache.Store(
		packageCacheKey{Name: "cached-go-package", Ecosystem: "Go"},
		[]*osvschema.Vulnerability{},
	)

	plan := matcher.buildQueryPlan([]*extractor.Package{
		{Name: "abc", Version: "1.2.1", PURLType: purl.TypeGolang},
		{Name: "abc", Version: "1.3.0", PURLType: purl.TypeGolang},
		{Name: "xyz", Version: "2.19.0", PURLType: purl.TypeGolang},
		{Name: "xyz", Version: "2.20.0", PURLType: purl.TypeGolang},
		{Name: "cached-go-package", Version: "1.0.0", PURLType: purl.TypeGolang},
		{Name: "cached-go-package", Version: "1.1.0", PURLType: purl.TypeGolang},
	})

	if got, want := plan.cacheHits, 2; got != want {
		t.Fatalf("cacheHits = %d, want %d", got, want)
	}

	if got, want := plan.duplicateSuppressed, 2; got != want {
		t.Fatalf("duplicateSuppressed = %d, want %d", got, want)
	}

	gotNames := make(map[string]int)
	for _, query := range plan.queries {
		gotNames[query.GetPackage().GetName()]++
	}
	wantNames := map[string]int{
		"abc": 1,
		"xyz": 1,
	}

	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("query package names = %#v, want %#v", gotNames, wantNames)
	}

	if got, want := len(plan.repeatedPackageLines), 2; got != want {
		t.Fatalf("len(repeatedPackageLines) = %d, want %d", got, want)
	}
}

func TestCachedOSVMatcher_MatchVulnerabilitiesPassesThroughCommitQueries(t *testing.T) {
	t.Parallel()

	var (
		mu              sync.Mutex
		recordedBatches [][]*api.Query
		recordedGets    []string
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == osvdev.QueryBatchEndpoint:
			var batch api.BatchQuery
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read batched query: %v", err)
			}
			_ = r.Body.Close()
			if err := protojson.Unmarshal(body, &batch); err != nil {
				t.Fatalf("decode batched query: %v", err)
			}

			mu.Lock()
			copied := make([]*api.Query, len(batch.GetQueries()))
			for i, query := range batch.GetQueries() {
				copied[i] = proto.Clone(query).(*api.Query)
			}
			recordedBatches = append(recordedBatches, copied)
			mu.Unlock()

			resp := &api.BatchVulnerabilityList{
				Results: make([]*api.VulnerabilityList, len(batch.GetQueries())),
			}
			for i, query := range batch.GetQueries() {
				resp.Results[i] = &api.VulnerabilityList{}
				switch {
				case query.GetCommit() != "":
					resp.Results[i].Vulns = []*osvschema.Vulnerability{{Id: "COMMIT-1"}}
				case query.GetPackage().GetName() == "abc":
					resp.Results[i].Vulns = []*osvschema.Vulnerability{{Id: "PKG-1"}}
				case query.GetPackage().GetName() == "hpack":
					resp.Results[i].Vulns = []*osvschema.Vulnerability{{Id: "HACKAGE-1"}}
				}
			}

			writeProtoJSON(t, w, resp)
		case r.Method == http.MethodGet && r.URL.Path == osvdev.GetEndpoint+"/PKG-1":
			mu.Lock()
			recordedGets = append(recordedGets, "PKG-1")
			mu.Unlock()

			writeProtoJSON(t, w, &osvschema.Vulnerability{
				Id: "PKG-1",
				Affected: []*osvschema.Affected{{
					Package: &osvschema.Package{
						Name:      "abc",
						Ecosystem: "Go",
					},
					Versions: []string{"1.2.1", "1.3.0"},
				}},
			})
		case r.Method == http.MethodGet && r.URL.Path == osvdev.GetEndpoint+"/COMMIT-1":
			mu.Lock()
			recordedGets = append(recordedGets, "COMMIT-1")
			mu.Unlock()

			writeProtoJSON(t, w, &osvschema.Vulnerability{Id: "COMMIT-1"})
		case r.Method == http.MethodGet && r.URL.Path == osvdev.GetEndpoint+"/HACKAGE-1":
			mu.Lock()
			recordedGets = append(recordedGets, "HACKAGE-1")
			mu.Unlock()

			writeProtoJSON(t, w, &osvschema.Vulnerability{Id: "HACKAGE-1"})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	matcher := &CachedOSVMatcher{
		Client: osvdev.OSVClient{
			HTTPClient:  server.Client(),
			Config:      osvdev.DefaultConfig(),
			BaseHostURL: server.URL,
		},
	}

	got, err := matcher.MatchVulnerabilities(t.Context(), []*extractor.Package{
		{Name: "abc", Version: "1.2.1", PURLType: purl.TypeGolang},
		{Name: "abc", Version: "1.3.0", PURLType: purl.TypeGolang},
		{SourceCode: &extractor.SourceCodeIdentifier{Commit: "33dffa3909a67e1b5d22647128ab7eb6e53fd0c7"}},
		{Name: "hpack", Version: "0.38.0", PURLType: purl.TypeHaskell},
	})
	if err != nil {
		t.Fatalf("MatchVulnerabilities() error = %v", err)
	}

	if got, want := len(got), 4; got != want {
		t.Fatalf("len(results) = %d, want %d", got, want)
	}

	gotIDs := []string{
		got[0][0].GetId(),
		got[1][0].GetId(),
		got[2][0].GetId(),
		got[3][0].GetId(),
	}
	wantIDs := []string{"PKG-1", "PKG-1", "COMMIT-1", "HACKAGE-1"}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("vulnerability IDs = %#v, want %#v", gotIDs, wantIDs)
	}

	mu.Lock()
	defer mu.Unlock()

	if got, want := len(recordedBatches), 2; got != want {
		t.Fatalf("query batch request count = %d, want %d", got, want)
	}

	if got, want := len(recordedBatches[0]), 1; got != want {
		t.Fatalf("package query batch size = %d, want %d", got, want)
	}
	if recordedBatches[0][0].GetPackage().GetName() != "abc" || recordedBatches[0][0].GetCommit() != "" {
		t.Fatalf("package query = %#v, want package abc query", recordedBatches[0][0])
	}
	if got := recordedBatches[0][0].GetVersion(); got != "" {
		t.Fatalf("cached package query version = %q, want empty package-level query", got)
	}

	if got, want := len(recordedBatches[1]), 2; got != want {
		t.Fatalf("passthrough query batch size = %d, want %d", got, want)
	}
	if recordedBatches[1][0].GetCommit() != "33dffa3909a67e1b5d22647128ab7eb6e53fd0c7" {
		t.Fatalf("passthrough commit query = %#v, want commit query", recordedBatches[1][0])
	}
	if recordedBatches[1][1].GetPackage().GetName() != "hpack" || recordedBatches[1][1].GetVersion() != "0.38.0" {
		t.Fatalf("passthrough package query = %#v, want versioned hackage query", recordedBatches[1][1])
	}

	slices.Sort(recordedGets)
	if want := []string{"COMMIT-1", "HACKAGE-1", "PKG-1"}; !reflect.DeepEqual(recordedGets, want) {
		t.Fatalf("hydrated vulnerability IDs = %#v, want %#v", recordedGets, want)
	}
}

func TestShouldUseCachedPackageQuery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		pkg  *extractor.Package
		want bool
	}{
		{
			name: "supported ecosystem uses cached package query",
			pkg:  &extractor.Package{Name: "abc", Version: "1.2.1", PURLType: purl.TypeGolang},
			want: true,
		},
		{
			name: "non-go ecosystem falls back to direct query",
			pkg:  &extractor.Package{Name: "protobuf", Version: "4.25.5", PURLType: purl.TypePyPi},
			want: false,
		},
		{
			name: "unsupported ecosystem falls back to direct query",
			pkg:  &extractor.Package{Name: "hpack", Version: "0.38.0", PURLType: purl.TypeHaskell},
			want: false,
		},
		{
			name: "missing version falls back to direct query",
			pkg:  &extractor.Package{Name: "abc", PURLType: purl.TypeGolang},
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := shouldUseCachedPackageQuery(tt.pkg); got != tt.want {
				t.Fatalf("shouldUseCachedPackageQuery() = %v, want %v", got, tt.want)
			}
		})
	}
}

func writeProtoJSON(t *testing.T, w http.ResponseWriter, msg proto.Message) {
	t.Helper()

	body, err := protojson.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatalf("write response: %v", err)
	}
}
