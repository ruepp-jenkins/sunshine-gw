// Command junitreport converts the JSON stream of `go test -json` into a JUnit XML
// report, which is what Jenkins' junit step reads.
//
// Written here rather than pulled in as a tool (gotestsum, go-junit-report) on purpose:
// the module has no dependencies, and the image build stays offline apart from the base
// images. A package that fails to build produces no test events at all, so that case is
// turned into a failing test case of its own - an empty report would otherwise look like
// "nothing to see here" in the build.
package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// event is one line of `go test -json`.
type event struct {
	Time    time.Time `json:"Time"`
	Action  string    `json:"Action"`
	Package string    `json:"Package"`
	Test    string    `json:"Test"`
	Elapsed float64   `json:"Elapsed"`
	Output  string    `json:"Output"`
}

type testCase struct {
	XMLName   xml.Name `xml:"testcase"`
	Name      string   `xml:"name,attr"`
	ClassName string   `xml:"classname,attr"`
	Time      string   `xml:"time,attr"`
	Failure   *failure `xml:"failure,omitempty"`
	Skipped   *skipped `xml:"skipped,omitempty"`
}

type failure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Output  string `xml:",cdata"`
}

type skipped struct {
	Message string `xml:"message,attr"`
}

type testSuite struct {
	XMLName   xml.Name   `xml:"testsuite"`
	Name      string     `xml:"name,attr"`
	Tests     int        `xml:"tests,attr"`
	Failures  int        `xml:"failures,attr"`
	Skipped   int        `xml:"skipped,attr"`
	Time      string     `xml:"time,attr"`
	Timestamp string     `xml:"timestamp,attr,omitempty"`
	Cases     []testCase `xml:"testcase"`
}

type testSuites struct {
	XMLName  xml.Name    `xml:"testsuites"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Time     string      `xml:"time,attr"`
	Suites   []testSuite `xml:"testsuite"`
}

func main() {
	suites, failed, err := convert(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "junitreport:", err)
		os.Exit(2)
	}
	out, err := xml.MarshalIndent(suites, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "junitreport:", err)
		os.Exit(2)
	}
	fmt.Println(xml.Header + string(out))

	// A short summary on stderr, because the JSON stream itself is unreadable in a build
	// log and the report is only looked at afterwards.
	fmt.Fprintf(os.Stderr, "junitreport: %d Tests, %d Fehler, %d uebersprungen\n",
		suites.Tests, suites.Failures, suites.Skipped)
	for _, name := range failed {
		fmt.Fprintln(os.Stderr, "  FAIL", name)
	}
}

// packageState collects the events of one package until it reports its result.
type packageState struct {
	name    string
	cases   []testCase
	byName  map[string]int
	output  []string
	elapsed float64
}

func convert(r io.Reader) (testSuites, []string, error) {
	packages := map[string]*packageState{}
	var order []string
	// Output accumulates per test until the test reports pass/fail/skip.
	output := map[string][]string{}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var ev event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			// Not every line of the stream is an event (a panic can interleave raw
			// text); skipping is better than losing the whole report over it.
			continue
		}
		if ev.Package == "" {
			continue
		}
		pkg, ok := packages[ev.Package]
		if !ok {
			pkg = &packageState{name: ev.Package, byName: map[string]int{}}
			packages[ev.Package] = pkg
			order = append(order, ev.Package)
		}

		key := ev.Package + "\x00" + ev.Test
		switch ev.Action {
		case "output":
			if ev.Test == "" {
				pkg.output = append(pkg.output, ev.Output)
			} else {
				output[key] = append(output[key], ev.Output)
			}
		case "pass", "fail", "skip":
			if ev.Test == "" {
				pkg.elapsed = ev.Elapsed
				if ev.Action == "fail" && len(pkg.cases) == 0 {
					// No test ran, yet the package failed: a build error, a panic
					// during init, or a vet failure. Without this the suite would be
					// empty and the build would look green-ish.
					pkg.cases = append(pkg.cases, testCase{
						Name:      "package",
						ClassName: ev.Package,
						Time:      formatSeconds(ev.Elapsed),
						Failure: &failure{
							Message: "Paket konnte nicht getestet werden",
							Type:    "build-error",
							Output:  strings.Join(pkg.output, ""),
						},
					})
				}
				continue
			}
			tc := testCase{
				Name:      ev.Test,
				ClassName: ev.Package,
				Time:      formatSeconds(ev.Elapsed),
			}
			switch ev.Action {
			case "fail":
				tc.Failure = &failure{
					Message: "Test fehlgeschlagen",
					Type:    "go-test",
					Output:  strings.Join(output[key], ""),
				}
			case "skip":
				tc.Skipped = &skipped{Message: strings.TrimSpace(strings.Join(output[key], ""))}
			}
			// A retried or re-reported test replaces its earlier result rather than
			// showing up twice.
			if idx, seen := pkg.byName[ev.Test]; seen {
				pkg.cases[idx] = tc
			} else {
				pkg.byName[ev.Test] = len(pkg.cases)
				pkg.cases = append(pkg.cases, tc)
			}
			delete(output, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return testSuites{}, nil, err
	}

	sort.Strings(order)
	var out testSuites
	var failed []string
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05")
	for _, name := range order {
		pkg := packages[name]
		if len(pkg.cases) == 0 {
			// Packages without test files produce no cases; leaving out the empty
			// suite keeps the report readable.
			continue
		}
		suite := testSuite{
			Name:      name,
			Tests:     len(pkg.cases),
			Time:      formatSeconds(pkg.elapsed),
			Timestamp: timestamp,
			Cases:     pkg.cases,
		}
		for _, tc := range pkg.cases {
			switch {
			case tc.Failure != nil:
				suite.Failures++
				failed = append(failed, name+"."+tc.Name)
			case tc.Skipped != nil:
				suite.Skipped++
			}
		}
		out.Tests += suite.Tests
		out.Failures += suite.Failures
		out.Skipped += suite.Skipped
		out.Suites = append(out.Suites, suite)
	}
	out.Time = formatSeconds(totalTime(out.Suites))
	return out, failed, nil
}

func totalTime(suites []testSuite) float64 {
	var total float64
	for _, s := range suites {
		var seconds float64
		fmt.Sscanf(s.Time, "%f", &seconds)
		total += seconds
	}
	return total
}

func formatSeconds(v float64) string {
	return fmt.Sprintf("%.3f", v)
}
