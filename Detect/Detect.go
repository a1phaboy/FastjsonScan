package Detect

import (
	"FastjsonScan/Utils"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptrace"
	"regexp"
	"strings"
	"time"
)

/**
***	识别fastjson(主要通过报错回显的方式)
**/

func DetectFastjson(url string) (bool,string){
	fmt.Println("[+] 正在进行报错识别")
	jsonType, _ := ErrDetectVersion(url)
	if jsonType == "jackson" {
		return false,Utils.NOT_FS
	}
	if jsonType != ""{
		return true,jsonType
	}
	return false,jsonType
}

/**
***	探测fastjson版本，目前包括:报错探测，DNS探测和延迟探测
**/

func DetectVersion(url string ) Utils.Result {
	var result Utils.Result
	fmt.Println("开始检测 "+url)
	result.Url = url
	//是否出网
	var payloads Utils.DNSPayloads
	isFastjson,jsonType := DetectFastjson(url)
	if jsonType == "jackson" {
		result.Type = jsonType
		return result
	}
	//出网探测
	fmt.Println("[+] 正在进行出网探测")
	payload, session := Utils.NET_DETECT_FACTORY()
	if DnslogDetect(url, payload, session) != "[]" {
		//出网
		fmt.Println("[*] 目标可出网")
		result.Netout = true
		result.Type = "Fastjson"
		fmt.Println("[+] 正在进行 AutoType状态 探测")
		result.AutoType = DetectAutoType(url)
		result.Dependency = DetectDependency(url)
		if isFastjson && jsonType != Utils.NOT_FS && jsonType != ""{
			fmt.Println("[+] Fastjson版本为 "+jsonType)
			result.Version = jsonType
			return result
		}
		fmt.Println("[+] 正在进行版本探测")
		payloads, session = Utils.DNS_DETECT_FACTORY()
		if DnslogDetect(url, payloads.Dns_48, session) == "48" {
			result.Version = Utils.FJ_UNDER_48
			return result
		}
		if DnslogDetect(url, payloads.Dns_68, session) == "68" {
			if result.AutoType{
				result.Version = Utils.FJ_BEYOND_48
				return result
			}
			result.Version = Utils.FJ_BETWEEN_48_68
			return result
		}
		if DnslogDetect(url, payloads.Dns_80, session) == "80" {
			result.Version = Utils.FJ_BETWEEN_69_80
			return result
		}
		if DnslogDetect(url, payloads.Dns_80, session) == "83" {
			result.Version = Utils.FS_BEYOND_80
			return result
		}
	} else {
		//不出网
		fmt.Println("[-] 目标不出网")
		fmt.Println("[+] 正在进行延迟探测")
		if TimeDelayCheck(url) {
			result.Netout = false
			result.Type = "Fastjson"
			result.Version = Utils.FS_BETWEEN_36_62
			return result
			//fastjson > 1.2.61 且 不出网

		}
	}

	result.Type = ""
	return result
}


/**
*** 探测java环境依赖库
**/

func DetectDependency(target string)[]string{
	fmt.Println("[+] 正在进行依赖库探测")
	fmt.Println("[+] 正在进行报错探测")
	var result []string
	findDependency := ErrDetectDependency(target,Utils.DEPENDENCY_ERR_DETECT_FACTORY())
	//fmt.Println(findDependency)
	if findDependency[0] == "" {
		fmt.Println("[-] 报错探测未发现任何依赖库")
		result[0] = ""
	}else{
		fmt.Println("[*] 发现依赖库如下")
		for dependency := range findDependency{
			if findDependency[dependency] != "" {
				fmt.Println(findDependency[dependency])
				result = append(result,findDependency[dependency])
			}

		}
	}
	return result
}


/**
*** Autotype 开启检测，需出网
*** return  True 为 开启 ; False 为 关闭
**/

func DetectAutoType(url string) bool{
	dnsurl,session := Utils.GetDnslogUrl()
	var result bool
	payload := Utils.AUTOTYPE_DETECT_FACTORY(dnsurl)
	if DnslogDetect(url,payload,session) == "[]" {
		fmt.Println("[-] 目标没有开启 AutoType")
		result = false
	}else{
		fmt.Println("[*] 目标开启了 AutoType ")
		result = true
	}
	return result
}

func DnslogDetect(target string,payload string,session string) string{
	reqBody := strings.NewReader(payload)
	httpReq, err := http.NewRequest("POST", target, reqBody)
	if err != nil {
		err.Error()
	}
	httpReq.Header.Add("Content-Type", "application/json")
	httpRsp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		err.Error()
	}
	defer httpRsp.Body.Close()
	//fmt.Println(session)
	time.Sleep(3*time.Second) // 等3秒钟，防止由于网络原因误报
	//fmt.Println(payload+":"+ Utils.GetDnslogRecord(session))
	return Utils.GetDnslogRecord(session)
}

/**
*** 报错探测
**/

func ErrDetectVersion(target string) (string,bool){
	var version string
	reqBody := strings.NewReader(Utils.FS_ERR_DETECT)
	httpReq, err := http.NewRequest("POST", target, reqBody)
	if err != nil {
		err.Error()
	}
	httpReq.Header.Add("Content-Type", "application/json")
	httpRsp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		err.Error()
	}
	defer httpRsp.Body.Close()
	body, err := ioutil.ReadAll(httpRsp.Body)
	if err != nil{
		err.Error()
	}
	reg := regexp.MustCompile(`fastjson-version\s\d.\d.[0-9]+`)

	version = reg.FindString(string(body))
	if version == ""{
		reg = regexp.MustCompile(`jackson`)
		version = reg.FindString(string(body))
		return version,false
	}else{
		return version[17:],true
	}
}

func ErrDetectDependency(target string, payloadsMap map[string]string) []string{
	var result = make([]string, len(payloadsMap))
	var cursor = 0
	for dependencyName , payload := range payloadsMap {
		reqBody := strings.NewReader(payload)
		httpReq, err := http.NewRequest("POST", target, reqBody)
		if err != nil{
			err.Error()
		}
		httpReq.Header.Add("Content-Type", "application/json")
		httpRsp, err := http.DefaultClient.Do(httpReq)
		if err != nil {
			err.Error()
		}
		defer httpRsp.Body.Close()
		body, err := ioutil.ReadAll(httpRsp.Body)
		//fmt.Println(string(body))
		if err != nil{
			err.Error()
		}
		reg := regexp.MustCompile(dependencyName)

		find := reg.FindString(string(body))
		if find != ""{
			result[cursor] = dependencyName
			cursor++
		}
	}
	return result
}

/**
*** 延迟探测
**/

func TimeDelayCheck(url string) bool{
	var count int
	var start int64
	var pos int64 = 0
	for i := 0; i < 5; i++ {
		start = pos
		payloads := Utils.TIME_DETECT_FACTORY(5)
		pos = TimeGet(url,payloads[i])
		if pos - start > 0{
			count ++
		}
	}
	if count > 3 {
		return true
	}
	return false
}

/**
*** 获取请求的时间
**/

func TimeGet(url string,payload string) int64{
	reqBody := strings.NewReader(payload)
	req, _ := http.NewRequest("POST", url, reqBody)
	var start time.Time

	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			//fmt.Printf("Time from start to first byte: %v\n", time.Since(start))
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	start = time.Now()
	if _, err := http.DefaultTransport.RoundTrip(req); err != nil {
		log.Fatal(err)
	}
	//fmt.Printf("Total time: %v\n", time.Since(start))
	return int64(time.Since(start))
}