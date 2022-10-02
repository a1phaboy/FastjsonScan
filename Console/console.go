package Console

import (
	"FastjsonScan/Detect"
	"FastjsonScan/Utils"
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

func Opts(){
fmt.Println(`Usage of ./FastjsonScan:
  -u url e.g: https://a1phaboy.tech/fastjson/post
        
  -f targets file . for example: -f targets.txt
        
  -o results output file. for example: -o result.txt
`)
}
func Banner(){
fmt.Println(`
  _____         _    _                 ____                  
 |  ___|_ _ ___| |_ (_)___  ___  _ __ / ___|  ___ __ _ _ __  
 | |_ / _' / __| __|| / __|/ _ \| '_ \\___ \ / __/ _' | '_ \
 |  _| (_| \__ \ |_ | \__ \ (_) | | | |___) | (_| (_| | | | |
 |_|  \__,_|___/\__|/ |___/\___/|_| |_|____/ \___\__,_|_| |_|
	          |__/
					 v1.2 by a1phaboy
`)
}

func Start(options Utils.Option){
	var ch chan string
	var targets []string
	initTargetList(options,&targets)
	//fmt.Println(targets)
	var results = make([]Utils.Result,len(targets))
	var wg sync.WaitGroup
	wg.Add(len(targets))
	for k,v := range targets{
		go func(k int,v string,ch chan string) {
			results[k] = Detect.DetectVersion(v)
			wg.Done()
		}(k,v,ch)
	}
	wg.Wait()

	writeResults(options.Result,results)
	fmt.Println("[*] 结果已保存至 " + options.Result)

	//fmt.Println(results)
}

func initTargetList(options Utils.Option,targets *[]string) {

	if options.Url != ""{
		*targets = append(*targets,options.Url)
	}
	if options.Targets != ""{
		file,err := os.Open(options.Targets)
		if err != nil{
			fmt.Println("文件不存在")
			return
		}
		buffer := bufio.NewReader(file)

		for{
			line,err := buffer.ReadString('\n')
			line = strings.TrimSpace(line)
			if err != nil {
				if err == io.EOF{
					return
				}
				fmt.Println("未知错误")
				return
			}
			*targets = append(*targets,line)
		}
	}
}

func writeResults(file string, results []Utils.Result ){
	var f *os.File
	var err error
	f,err = os.Create(file)
	if err != nil{
		fmt.Println(err.Error())
		return
	}
	for _,v := range results{
		if v.Type == "Fastjson" {
			info := Utils.SCAN_RESULTS_OUTPUT_FACTORY(v)
			_, err = io.WriteString(f, info)
		}
	}
}
