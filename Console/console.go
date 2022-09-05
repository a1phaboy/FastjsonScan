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
  -f string
        targets file . for example: -f targets.txt
  -o string
        results output file. for example: -o result.txt
  -u string
        url`)
}
func Banner(){

}

func Start(options Utils.Option){
	var ch chan string
	var targets []string
	initTargetList(options,&targets)
	fmt.Println(targets)
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
