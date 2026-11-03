// load is an open-loop, bounded-worker HTTP workload generator. Latency starts
// at scheduled arrival, not dispatch; overload is reported as dropped work.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

func main() {
	target := flag.String("url", "http://127.0.0.1:8088/json", "target URL")
	rate := flag.Int("rate", 1000, "scheduled requests/second")
	duration := flag.Duration("duration", 10*time.Second, "arrival duration")
	workers := flag.Int("workers", 64, "maximum concurrent requests")
	method := flag.String("method", "GET", "HTTP method")
	body := flag.String("body", "", "request body")
	paths := flag.String("paths", "", "optional comma-separated paths for round-robin mixed traffic; url is the base")
	expect := flag.Int("expect", 200, "expected response status")
	timeout := flag.Duration("timeout", 5*time.Second, "per-request timeout")
	flag.Parse()
	if *rate < 1 || *rate > 1000000 || *workers < 1 || *duration <= 0 || *duration > time.Hour {
		fmt.Fprintln(os.Stderr, "invalid rate, workers or duration")
		os.Exit(2)
	}
	type job struct {
		scheduled time.Time
		index     int
	}
	type result struct {
		latency time.Duration
		success bool
		bytes   int64
	}
	// A bounded arrival queue absorbs worker scheduling jitter. Queueing time
	// remains part of latency, and a full queue produces an explicit drop.
	jobs := make(chan job, *workers)
	results := make(chan result, *workers)
	client := &http.Client{Timeout: *timeout, Transport: &http.Transport{MaxIdleConns: *workers, MaxIdleConnsPerHost: *workers, MaxConnsPerHost: *workers}}
	var wg sync.WaitGroup
	for range *workers {
		wg.Go(func() {
			for j := range jobs {
				url := *target
				if *paths != "" {
					choices := strings.Split(*paths, ",")
					url = strings.TrimRight(url, "/") + choices[j.index%len(choices)]
				}
				r, err := http.NewRequest(*method, url, bytes.NewBufferString(*body))
				if err != nil {
					results <- result{latency: time.Since(j.scheduled)}
					continue
				}
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Authorization", "Bearer benchmark")
				resp, err := client.Do(r)
				ok := false
				var n int64
				if err == nil {
					n, err = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
					ok = err == nil && resp.StatusCode == *expect
				}
				results <- result{time.Since(j.scheduled), ok, n}
			}
		})
	}
	total := int(float64(*rate) * duration.Seconds())
	start := time.Now()
	dropped := make(chan int, 1)
	go func() {
		drops := 0
		for i := range total {
			at := start.Add(time.Duration(float64(i) / float64(*rate) * float64(time.Second)))
			if delay := time.Until(at); delay > 0 {
				time.Sleep(delay)
			}
			select {
			case jobs <- job{at, i}:
			default:
				drops++
			}
		}
		close(jobs)
		dropped <- drops
		wg.Wait()
		close(results)
	}()
	var latencies []float64
	successful, failed := 0, 0
	var received int64
	for r := range results {
		latencies = append(latencies, float64(r.latency)/float64(time.Millisecond))
		received += r.bytes
		if r.success {
			successful++
		} else {
			failed++
		}
	}
	sort.Float64s(latencies)
	percentile := func(p float64) float64 {
		if len(latencies) == 0 {
			return 0
		}
		return latencies[int(float64(len(latencies)-1)*p)]
	}
	elapsed := time.Since(start).Seconds()
	report := map[string]any{"url": *target, "method": *method, "paths": *paths, "body": *body, "expected_status": *expect, "offered_rps": *rate, "duration_seconds": duration.Seconds(), "workers": *workers, "timeout_seconds": timeout.Seconds(), "scheduled": total, "successful": successful, "failed": failed, "dropped": <-dropped, "elapsed_seconds": elapsed, "successful_rps_including_drain": float64(successful) / elapsed, "response_bytes": received, "latency_ms_all_completed": map[string]float64{"p50": percentile(.50), "p95": percentile(.95), "p99": percentile(.99)}}
	report["queue_capacity"] = *workers
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		panic(err)
	}
}
