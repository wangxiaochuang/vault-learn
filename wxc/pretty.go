package wxc

import (
	"fmt"
	"time"

	"github.com/kr/pretty"
)

func P(objs ...interface{}) {
	if len(objs) == 1 {
		fmt.Printf("%# v\n", pretty.Formatter(objs[0]))
	} else {
		fmt.Printf("%# v\n", pretty.Formatter(objs))
	}
	time.Sleep(time.Hour)
}

func Print(objs ...interface{}) {
	if len(objs) == 1 {
		fmt.Printf("wxc.Print => %# v\n", pretty.Formatter(objs[0]))
	} else {
		fmt.Printf("wxc.Print => %# v\n", pretty.Formatter(objs))
	}
}
