// Command pgprobe checks that a PostgreSQL server is reachable and speaking
// the Postgres protocol, without credentials or a driver.
//
//	pgprobe "$DATABASE_URL"
//	pgprobe db:5432
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/PrinceAdvant/pgprobe"
)

func main() {
	timeout := flag.Duration("timeout", 5*time.Second, "overall timeout")
	asJSON := flag.Bool("json", false, "print JSON")
	flag.Parse()
	target := flag.Arg(0)
	if target == "" {
		target = os.Getenv("DATABASE_URL")
	}
	r := pgprobe.Probe(context.Background(), target, *timeout)
	if *asJSON {
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		_ = e.Encode(r)
	} else {
		fmt.Printf("%s:%s stage=%s tls=%v time=%s\n", r.Host, r.Port, r.Stage, r.TLS, r.Elapsed.Round(time.Millisecond))
		if r.Err != "" {
			fmt.Println("error:", r.Err)
		}
		if r.Hint != "" {
			fmt.Println("hint:", r.Hint)
		}
	}
	if r.Stage != pgprobe.StageOK {
		os.Exit(1)
	}
}
