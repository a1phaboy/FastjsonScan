package Utils

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"regexp"
	"time"
)

/**
***	dnslog API
**/

func GetDnslogUrl()	(string,string){
	session := randCreator()
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://www.dnslog.cn/getdomain.php",nil)
	if err != nil{
		err.Error()
	}
	req.Header.Add("Cookie","PHPSESSID="+session)
	resp, err := client.Do(req)
	if err != nil{
		resp = NetWorkErrHandle(client,req,err)
		if resp == nil{
			fmt.Println("与dns平台网络不可达,请检查网络")
			return NETWORK_NOT_ACCESS,""
		}
	}
	domain, _ := ioutil.ReadAll(resp.Body)

	return string(domain),session
}

func GetDnslogRecord(PHPSESSID string) string{
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://www.dnslog.cn/getrecords.php",nil)
	if err != nil{
		err.Error()
	}
	req.Header.Add("Cookie","PHPSESSID=" + PHPSESSID)
	resp, err := client.Do(req)
	if err != nil{
		resp = NetWorkErrHandle(client,req,err)
		if resp == nil{
			fmt.Println("与dns平台网络不可达,请检查网络")
			return NETWORK_NOT_ACCESS
		}
	}
	body, _ := ioutil.ReadAll(resp.Body)
	dns_48 := regexp.MustCompile(`48_.`)
	dns_68 := regexp.MustCompile(`68_.`)
	dns_80 := regexp.MustCompile(`80_.`)
	dns_83 := regexp.MustCompile(`83_.`)
	//fmt.Println(string(body))
	if string(body) == "[]"{
		return ""
	}else{
		if dns_48.FindString(string(body)) != "" {
			return "48"
		}
		if dns_68.FindString(string(body)) != ""{
			return "68"
		}
		if dns_83.FindString(string(body)) != ""{
			return "83"
		}
		if dns_80.FindString(string(body)) != ""{
			return "80"
		}
		return "Recorded"
	}
}

func randCreator() string{
	str:="0123456789abcdefghigklmnopqrstuvwxyz"
	strList:=[]byte(str)
	result:=[]byte{}
	i:=0
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i< 26{
		new:=strList[r.Intn(len(strList))]
		result=append(result,new)
		i=i+1
	}
	return string(result)
}
