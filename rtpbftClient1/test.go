package main

import "fmt"
import "runtime"
func dec() {
	num := runtime.NumCPU()
	fmt.Print("hello world! num = ",num)
}
