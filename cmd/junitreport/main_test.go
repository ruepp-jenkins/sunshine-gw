package main

import (
	"encoding/xml"
	"strings"
	"testing"
)

const sample = `
{"Time":"2026-09-27T14:00:00Z","Action":"run","Package":"example/pkg","Test":"TestOne"}
{"Time":"2026-09-27T14:00:00Z","Action":"output","Package":"example/pkg","Test":"TestOne","Output":"=== RUN   TestOne\n"}
{"Time":"2026-09-27T14:00:01Z","Action":"pass","Package":"example/pkg","Test":"TestOne","Elapsed":0.01}
{"Time":"2026-09-27T14:00:01Z","Action":"run","Package":"example/pkg","Test":"TestTwo"}
{"Time":"2026-09-27T14:00:01Z","Action":"output","Package":"example/pkg","Test":"TestTwo","Output":"    main_test.go:9: kaputt <&>\n"}
{"Time":"2026-09-27T14:00:02Z","Action":"fail","Package":"example/pkg","Test":"TestTwo","Elapsed":0.02}
{"Time":"2026-09-27T14:00:02Z","Action":"run","Package":"example/pkg","Test":"TestThree"}
{"Time":"2026-09-27T14:00:02Z","Action":"output","Package":"example/pkg","Test":"TestThree","Output":"    main_test.go:20: nur unter Linux\n"}
{"Time":"2026-09-27T14:00:02Z","Action":"skip","Package":"example/pkg","Test":"TestThree","Elapsed":0}
{"Time":"2026-09-27T14:00:02Z","Action":"fail","Package":"example/pkg","Elapsed":0.03}
{"Time":"2026-09-27T14:00:02Z","Action":"output","Package":"example/empty","Output":"?   \texample/empty\t[no test files]\n"}
{"Time":"2026-09-27T14:00:02Z","Action":"skip","Package":"example/empty","Elapsed":0}
`

func TestConvert(t *testing.T) {
	suites, failed, err := convert(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if suites.Tests != 3 || suites.Failures != 1 || suites.Skipped != 1 {
		t.Errorf("Summen = %d Tests, %d Fehler, %d uebersprungen", suites.Tests, suites.Failures, suites.Skipped)
	}
	if len(suites.Suites) != 1 {
		t.Fatalf("%d Suites, erwartet 1 (Pakete ohne Tests gehoeren nicht in den Report)", len(suites.Suites))
	}
	suite := suites.Suites[0]
	if suite.Name != "example/pkg" {
		t.Errorf("Suite-Name = %q", suite.Name)
	}
	if len(failed) != 1 || failed[0] != "example/pkg.TestTwo" {
		t.Errorf("fehlgeschlagene Tests = %v", failed)
	}
	byName := map[string]testCase{}
	for _, tc := range suite.Cases {
		byName[tc.Name] = tc
	}
	if tc := byName["TestOne"]; tc.Failure != nil || tc.Skipped != nil || tc.Time != "0.010" {
		t.Errorf("TestOne = %+v", tc)
	}
	if tc := byName["TestTwo"]; tc.Failure == nil {
		t.Error("TestTwo muss als Fehler im Report stehen")
	} else if !strings.Contains(tc.Failure.Output, "kaputt") {
		t.Errorf("Ausgabe des fehlgeschlagenen Tests fehlt: %q", tc.Failure.Output)
	}
	if tc := byName["TestThree"]; tc.Skipped == nil {
		t.Error("TestThree muss als uebersprungen im Report stehen")
	}
}

// XML that Jenkins cannot parse is worse than no report, so the output is parsed back
// and the characters that break naive string building are checked explicitly.
func TestOutputIsWellFormedXML(t *testing.T) {
	suites, _, err := convert(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	blob, err := xml.MarshalIndent(suites, "", "  ")
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back testSuites
	if err := xml.Unmarshal(blob, &back); err != nil {
		t.Fatalf("eigene Ausgabe ist kein gueltiges XML: %v\n%s", err, blob)
	}
	if back.Tests != suites.Tests || len(back.Suites) != len(suites.Suites) {
		t.Errorf("Round-Trip verloren: %+v", back)
	}
	if !strings.Contains(string(blob), "<![CDATA[") {
		t.Error("Testausgabe wird nicht in CDATA verpackt")
	}
	if strings.Contains(string(blob), "kaputt <&>") == false {
		t.Error("Sonderzeichen der Testausgabe gingen verloren")
	}
}

// A package that does not compile emits no test events. Without a synthetic case the
// suite would be empty and the build would look like it simply had nothing to run.
func TestBuildErrorBecomesFailingCase(t *testing.T) {
	const broken = `
{"Action":"output","Package":"example/broken","Output":"# example/broken\n"}
{"Action":"output","Package":"example/broken","Output":"./main.go:7:2: undefined: nope\n"}
{"Action":"fail","Package":"example/broken","Elapsed":0}
`
	suites, failed, err := convert(strings.NewReader(broken))
	if err != nil {
		t.Fatal(err)
	}
	if suites.Tests != 1 || suites.Failures != 1 {
		t.Fatalf("Summen = %d Tests, %d Fehler", suites.Tests, suites.Failures)
	}
	tc := suites.Suites[0].Cases[0]
	if tc.Name != "package" || tc.Failure == nil {
		t.Fatalf("Fall = %+v", tc)
	}
	if !strings.Contains(tc.Failure.Output, "undefined: nope") {
		t.Errorf("Compiler-Fehler fehlt im Report: %q", tc.Failure.Output)
	}
	if len(failed) != 1 {
		t.Errorf("fehlgeschlagene Tests = %v", failed)
	}
}

func TestGarbageLinesAreIgnored(t *testing.T) {
	const noisy = `
panic: irgendwas ganz kaputtes
{"Action":"pass","Package":"example/pkg","Test":"TestOne","Elapsed":0.5}
nicht mal JSON
{"Action":"pass","Package":"example/pkg","Elapsed":0.5}
`
	suites, _, err := convert(strings.NewReader(noisy))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if suites.Tests != 1 {
		t.Errorf("%d Tests, erwartet 1", suites.Tests)
	}
}
