// Package osvmatcher implements two vulnerability matcher using osv.dev's API.
package osvmatcher

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/semantic"
	"github.com/google/osv-scanner/v2/internal/clients/clientimpl/localmatcher"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"osv.dev/bindings/go/api"
	"osv.dev/bindings/go/osvdev"
	"osv.dev/bindings/go/osvdevexperimental"
)

type packageCacheKey struct {
	Name      string
	Ecosystem string
}

// CachedOSVMatcher implements the VulnerabilityMatcher interface with a osv.dev client.
// It sends out requests for every vulnerability of each package, which get cached.
// Checking if a specific version matches an OSV record is done locally.
// This should be used when we know the same packages are going to be repeatedly
// queried multiple times, as in guided remediation. Commit-based queries are
// passed through directly without caching.
type CachedOSVMatcher struct {
	Client osvdev.OSVClient
	// InitialQueryTimeout allows you to set a timeout specifically for the initial paging query
	// If timeout runs out, whatever pages that has been successfully queried within the timeout will
	// still return fully hydrated.
	InitialQueryTimeout time.Duration

	vulnCache sync.Map // map[packageCacheKey][]*osvschema.Vulnerability
}

type cachedQueryPlan struct {
	queries              []*api.Query
	queryKeys            []packageCacheKey
	cacheHits            int
	duplicateSuppressed  int
	repeatedPackageLines []string
}

type batchQueryMetrics struct {
	queryBatchRequests int
	vulnDetailRequests int
}

type directQueryResult struct {
	vulnerabilities []*osvschema.Vulnerability
}

func NewCached(initialQueryTimeout time.Duration, userAgent string, httpClient *http.Client) *CachedOSVMatcher {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	config := osvdev.DefaultConfig()
	config.UserAgent = userAgent

	return &CachedOSVMatcher{
		Client: osvdev.OSVClient{
			HTTPClient:  httpClient,
			Config:      config,
			BaseHostURL: osvdev.DefaultBaseURL,
		},
		InitialQueryTimeout: initialQueryTimeout,
	}
}

func batchQueryPagingWithMetrics(ctx context.Context, c *osvdev.OSVClient, queries []*api.Query, metrics *batchQueryMetrics) (*api.BatchVulnerabilityList, error) {
	metrics.queryBatchRequests++
	batchResp, err := c.QueryBatch(ctx, queries)
	if err != nil {
		return nil, err
	}

	var errToReturn error
	var nextPageQueries []*api.Query
	var nextPageIndexMap []int
	for i, res := range batchResp.GetResults() {
		if res.GetNextPageToken() == "" {
			continue
		}

		clonedQuery := proto.Clone(queries[i]).(*api.Query)
		clonedQuery.PageToken = res.GetNextPageToken()
		nextPageQueries = append(nextPageQueries, clonedQuery)
		nextPageIndexMap = append(nextPageIndexMap, i)
	}

	if len(nextPageQueries) > 0 {
		if ctx.Err() != nil {
			return batchResp, &osvdevexperimental.DuringPagingError{
				PageDepth: 1,
				Inner:     ctx.Err(),
			}
		}

		nextPageResp, err := batchQueryPagingWithMetrics(ctx, c, nextPageQueries, metrics)
		if err != nil {
			var dpe *osvdevexperimental.DuringPagingError
			if ok := errors.As(err, &dpe); ok {
				dpe.PageDepth += 1
				errToReturn = dpe
			} else {
				errToReturn = &osvdevexperimental.DuringPagingError{
					PageDepth: 1,
					Inner:     err,
				}
			}
		}

		if nextPageResp != nil {
			for i, res := range nextPageResp.GetResults() {
				batchResp.GetResults()[nextPageIndexMap[i]].Vulns = append(batchResp.GetResults()[nextPageIndexMap[i]].GetVulns(), res.GetVulns()...)
				batchResp.GetResults()[nextPageIndexMap[i]].NextPageToken = res.GetNextPageToken()
			}
		}
	}

	return batchResp, errToReturn
}

func (matcher *CachedOSVMatcher) MatchVulnerabilities(ctx context.Context, pkgs []*extractor.Package) ([][]*osvschema.Vulnerability, error) {
	results := make([][]*osvschema.Vulnerability, len(pkgs))

	packagePkgs := make([]*extractor.Package, 0, len(pkgs))
	packageIndexes := make([]int, 0, len(pkgs))
	passthroughPkgs := make([]*extractor.Package, 0)
	passthroughIndexes := make([]int, 0)

	for i, pkg := range pkgs {
		switch {
		case shouldUseCachedPackageQuery(pkg):
			packagePkgs = append(packagePkgs, pkg)
			packageIndexes = append(packageIndexes, i)
		case imodels.Commit(pkg) != "" || (imodels.Name(pkg) != "" && !imodels.Ecosystem(pkg).IsEmpty()):
			passthroughPkgs = append(passthroughPkgs, pkg)
			passthroughIndexes = append(passthroughIndexes, i)
		}
	}

	plan, queryMetrics, err := matcher.doQueries(ctx, packagePkgs)
	if err != nil {
		return nil, err
	}

	for i, pkg := range packagePkgs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		key, ok := cacheKeyForPackage(pkg)
		if !ok {
			continue
		}

		cachedVulns, ok := matcher.vulnCache.Load(key)
		if !ok {
			continue
		}

		results[packageIndexes[i]] = localmatcher.VulnerabilitiesAffectingPackage(cachedVulns.([]*osvschema.Vulnerability), pkg)
	}

	passthroughResults, passthroughMetrics, err := matcher.matchDirectQueries(ctx, passthroughPkgs)
	if err != nil {
		return nil, err
	}
	queryMetrics.queryBatchRequests += passthroughMetrics.queryBatchRequests
	queryMetrics.vulnDetailRequests += passthroughMetrics.vulnDetailRequests
	for i, res := range passthroughResults {
		results[passthroughIndexes[i]] = res.vulnerabilities
	}

	matcher.logSummary(len(pkgs), plan, queryMetrics)

	return results, nil
}

func (matcher *CachedOSVMatcher) buildQueryPlan(pkgs []*extractor.Package) cachedQueryPlan {
	plan := cachedQueryPlan{}
	seen := make(map[packageCacheKey]struct{})
	occurrenceCounts := make(map[packageCacheKey]int)

	for _, pkg := range pkgs {
		query, key, ok := cachedPackageQuery(pkg)
		if !ok {
			continue
		}

		if _, ok := matcher.vulnCache.Load(key); ok {
			plan.cacheHits++
			continue
		}

		occurrenceCounts[key]++
		if _, ok := seen[key]; ok {
			plan.duplicateSuppressed++
			continue
		}

		seen[key] = struct{}{}
		plan.queries = append(plan.queries, query)
		plan.queryKeys = append(plan.queryKeys, key)
	}

	for key, count := range occurrenceCounts {
		if count <= 1 {
			continue
		}
		plan.repeatedPackageLines = append(
			plan.repeatedPackageLines,
			fmt.Sprintf(
				"ecosystem=%s package=%s occurrences=%d suppressed_duplicate_entries=%d deduped_query_entry=true",
				key.Ecosystem,
				key.Name,
				count,
				count-1,
			),
		)
	}
	slices.Sort(plan.repeatedPackageLines)

	return plan
}

func (matcher *CachedOSVMatcher) doQueries(ctx context.Context, pkgs []*extractor.Package) (cachedQueryPlan, batchQueryMetrics, error) {
	var batchResp *api.BatchVulnerabilityList
	deadlineExceeded := false

	plan := matcher.buildQueryPlan(pkgs)
	queryMetrics := batchQueryMetrics{}

	if len(plan.queries) == 0 {
		return plan, queryMetrics, nil
	}

	var err error
	if matcher.InitialQueryTimeout > 0 {
		batchQueryCtx, cancelFunc := context.WithDeadline(ctx, time.Now().Add(matcher.InitialQueryTimeout))
		batchResp, err = batchQueryPagingWithMetrics(batchQueryCtx, &matcher.Client, plan.queries, &queryMetrics)
		cancelFunc()
	} else {
		batchResp, err = batchQueryPagingWithMetrics(ctx, &matcher.Client, plan.queries, &queryMetrics)
	}

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			deadlineExceeded = true
		} else {
			return plan, queryMetrics, err
		}
	}

	if batchResp == nil {
		return plan, queryMetrics, err
	}

	vulnerabilities := make([][]*osvschema.Vulnerability, len(batchResp.GetResults()))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentRequests)

	for batchIdx, resp := range batchResp.GetResults() {
		queryMetrics.vulnDetailRequests += len(resp.GetVulns())
		vulnerabilities[batchIdx] = make([]*osvschema.Vulnerability, len(resp.GetVulns()))
		for resultIdx, vuln := range resp.GetVulns() {
			batchIdx := batchIdx
			resultIdx := resultIdx
			vuln := vuln

			g.Go(func() error {
				if ctx.Err() != nil {
					return nil //nolint:nilerr // this value doesn't matter to errgroup.Wait()
				}

				hydrated, err := matcher.Client.GetVulnByID(ctx, vuln.GetId())
				if err != nil {
					return err
				}
				vulnerabilities[batchIdx][resultIdx] = hydrated

				return nil
			})
		}
	}

	if err := g.Wait(); err != nil {
		return plan, queryMetrics, err
	}

	if deadlineExceeded {
		return plan, queryMetrics, context.DeadlineExceeded
	}

	for i, vulns := range vulnerabilities {
		matcher.vulnCache.Store(plan.queryKeys[i], vulns)
	}

	return plan, queryMetrics, nil
}

func (matcher *CachedOSVMatcher) matchDirectQueries(ctx context.Context, pkgs []*extractor.Package) ([]directQueryResult, batchQueryMetrics, error) {
	if len(pkgs) == 0 {
		return nil, batchQueryMetrics{}, nil
	}

	var batchResp *api.BatchVulnerabilityList
	deadlineExceeded := false
	queryMetrics := batchQueryMetrics{}
	queries := pkgsToQueries(pkgs)

	var err error
	if matcher.InitialQueryTimeout > 0 {
		batchQueryCtx, cancelFunc := context.WithDeadline(ctx, time.Now().Add(matcher.InitialQueryTimeout))
		batchResp, err = batchQueryPagingWithMetrics(batchQueryCtx, &matcher.Client, queries, &queryMetrics)
		cancelFunc()
	} else {
		batchResp, err = batchQueryPagingWithMetrics(ctx, &matcher.Client, queries, &queryMetrics)
	}

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			deadlineExceeded = true
		} else {
			return nil, queryMetrics, err
		}
	}

	if batchResp == nil {
		return nil, queryMetrics, err
	}

	results := make([]directQueryResult, len(batchResp.GetResults()))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentRequests)

	for batchIdx, resp := range batchResp.GetResults() {
		results[batchIdx] = directQueryResult{
			vulnerabilities: make([]*osvschema.Vulnerability, len(resp.GetVulns())),
		}
		queryMetrics.vulnDetailRequests += len(resp.GetVulns())

		for resultIdx, vuln := range resp.GetVulns() {
			batchIdx := batchIdx
			resultIdx := resultIdx
			vuln := vuln

			g.Go(func() error {
				if ctx.Err() != nil {
					return nil //nolint:nilerr // this value doesn't matter to errgroup.Wait()
				}

				hydrated, err := matcher.Client.GetVulnByID(ctx, vuln.GetId())
				if err != nil {
					return err
				}
				results[batchIdx].vulnerabilities[resultIdx] = hydrated

				return nil
			})
		}
	}

	if err := g.Wait(); err != nil {
		return nil, queryMetrics, err
	}

	if deadlineExceeded {
		return results, queryMetrics, context.DeadlineExceeded
	}

	return results, queryMetrics, nil
}

func (matcher *CachedOSVMatcher) logSummary(inventoryCount int, plan cachedQueryPlan, metrics batchQueryMetrics) {
	if len(plan.queries) == 0 && plan.cacheHits == 0 && plan.duplicateSuppressed == 0 {
		return
	}

	cmdlogger.Infof("osv matcher=cached")
	cmdlogger.Infof("  summary:")
	cmdlogger.Infof("  - inventories=%d", inventoryCount)
	cmdlogger.Infof("  - deduped_batched_package_query_entries=%d", len(plan.queries))
	cmdlogger.Infof("  - duplicate_package_entries_suppressed=%d", plan.duplicateSuppressed)
	cmdlogger.Infof("  - package_cache_hits=%d", plan.cacheHits)
	cmdlogger.Infof("  - query_batch_requests=%d", metrics.queryBatchRequests)
	if len(plan.repeatedPackageLines) > 0 {
		cmdlogger.Infof("  repeated_packages:")
		for _, repeatedPkg := range plan.repeatedPackageLines {
			cmdlogger.Infof("  - %s", repeatedPkg)
		}
	}
	cmdlogger.Infof("  - vulnerability_detail_requests=%d", metrics.vulnDetailRequests)
}

func shouldUseCachedPackageQuery(pkg *extractor.Package) bool {
	_, _, ok := cachedPackageQuery(pkg)

	return ok
}

func cachedPackageQuery(pkg *extractor.Package) (*api.Query, packageCacheKey, bool) {
	if imodels.Name(pkg) == "" || imodels.Ecosystem(pkg).IsEmpty() || imodels.Version(pkg) == "" {
		return nil, packageCacheKey{}, false
	}
	if imodels.Ecosystem(pkg).String() != "Go" {
		return nil, packageCacheKey{}, false
	}

	query := pkgToQuery(pkg)
	if query == nil || query.GetPackage() == nil || query.GetVersion() == "" {
		return nil, packageCacheKey{}, false
	}
	if query.GetPackage().GetName() == "" || query.GetPackage().GetEcosystem() == "" {
		return nil, packageCacheKey{}, false
	}
	if _, err := semantic.Parse(query.GetVersion(), query.GetPackage().GetEcosystem()); err != nil {
		return nil, packageCacheKey{}, false
	}

	cacheKey := packageCacheKey{
		Name:      query.GetPackage().GetName(),
		Ecosystem: query.GetPackage().GetEcosystem(),
	}

	return &api.Query{
		Package: &osvschema.Package{
			Name:      cacheKey.Name,
			Ecosystem: cacheKey.Ecosystem,
		},
	}, cacheKey, true
}

func cacheKeyForPackage(pkg *extractor.Package) (packageCacheKey, bool) {
	_, key, ok := cachedPackageQuery(pkg)

	return key, ok
}
