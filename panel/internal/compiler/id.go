package compiler

import "strconv"

func recordID(i int) string { return "record-" + strconv.Itoa(i+1) }
