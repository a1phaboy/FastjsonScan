package main

import (
	"FastjsonScan/Utils"
	"FastjsonScan/console"
	"flag"
)


// ./FastjsonScan -u http://test.a1phaboy.tech/api/post -o result.txt
// ./FastjsonScan -f targets.txt
func main() {
	Console.Banner()
	var options Utils.Option
	flag.StringVar(&options.Url,"u","","url")
	flag.StringVar(&options.Targets,"f","","targets file . for example: -f targets.txt")
	flag.StringVar(&options.Result,"o","result.txt","results output file. for example: -o result.txt")
	flag.Parse()
	if options.Url == "" && options.Targets == ""{
		Console.Opts()
		return
	}
	Console.Start(options)
}
