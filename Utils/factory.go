package Utils

import (
	"bytes"
	"log"
	"text/template"
)


/**
*** 工厂文件，用于处理payload模版，生成实际payload
**/



/**
*** 出网探测
**/

func NET_DETECT_FACTORY() (string,string){
	var buffer bytes.Buffer
	payloadTemplate := TAR_NET_DETECT
	var session string
	Payload := &Payload{}
	Payload.Variables = make(map[string]string)
	Payload.Variables["DNS"],session = GetDnslogUrl()
	buffer.Reset()
	PayloadTemplate, err := template.New("Payload").Parse(payloadTemplate)
	if err != nil {
		log.Fatal(err)
	}
	buffer.Reset()
	if err = PayloadTemplate.Execute(&buffer, Payload); err != nil {
		log.Fatal(err)
	}
	return buffer.String(),session
}

/**
***  DNS探测
***  output  payloads(dns_48_payload,dns_68_payload,dns_80_payload),session
**/

func DNS_DETECT_FACTORY() (DNSPayloads,string){
	var payloads DNSPayloads
	var buffer bytes.Buffer
	var session string
	Dns := &Payload{}
	Dns.Variables = make(map[string]string)
	Dns.Variables["DNS"],session = GetDnslogUrl()
	buffer.Reset()
	dns_48_payload, err := template.New("Dns").Parse(DNS_DETECT_48)
	dns_68_payload, err := template.New("Dns").Parse(DNS_DETECT_68)
	dns_80_payload, err := template.New("Dns").Parse(DNS_DETECT_80)
	if err != nil {
		log.Fatal(err)
	}
	buffer.Reset()
	if err = dns_48_payload.Execute(&buffer, Dns); err != nil {
		log.Fatal(err)
	}
	payloads.Dns_48 = buffer.String()
	buffer.Reset()
	if err = dns_68_payload.Execute(&buffer, Dns); err != nil {
		log.Fatal(err)
	}
	payloads.Dns_68 = buffer.String()
	buffer.Reset()
	if err = dns_80_payload.Execute(&buffer, Dns); err != nil {
		log.Fatal(err)
	}
	payloads.Dns_80 = buffer.String()
	return payloads,session
}




/**
*** 生成count条payload 默认为count=5
**/

func TIME_DETECT_FACTORY(count int) []string{
	var buffer bytes.Buffer
	var payloadTemplate = TIME_DETECT
	payloads := make([]string,count)
	Payload := &Payload{}
	Payload.Variables = make(map[string]string)
	for i := 0; i < count; i++ {
		Payload.Variables["Value"] += "a"
		buffer.Reset()
		PayloadTemplate, err := template.New("Payload").Parse(payloadTemplate)
		if err != nil {
			log.Fatal(err)
		}
		buffer.Reset()
		if err = PayloadTemplate.Execute(&buffer, Payload); err != nil {
			log.Fatal(err)
		}
		payloads[i] = buffer.String()
	}
	return payloads
}

/**
*** 检测是否开启了AutoType的payload
*** input  dnsurl
*** output payload
**/

func AUTOTYPE_DETECT_FACTORY(dnsurl string) string{
	var buffer bytes.Buffer
	var payloadTemplate = AUTOTYPE_CHECK
	Payload :=&Payload{}
	Payload.Variables = make(map[string]string)
	Payload.Variables["DNS"] = dnsurl
	buffer.Reset()
	PayloadTemplate, err := template.New("Payload").Parse(payloadTemplate)
	if err != nil {
		log.Fatal(err)
	}
	buffer.Reset()
	if err = PayloadTemplate.Execute(&buffer, Payload); err != nil {
		log.Fatal(err)
	}
	return buffer.String()
}


/**
*** 探测是否含有依赖库
***
*** output payloads
**/

func DEPENDENCY_ERR_DETECT_FACTORY() map[string]string{
	var payloads = make(map[string]string)
	var buffer bytes.Buffer
	var payloadTemplate = DEPENDENCY_DETECT_BY_ERR
	gadgetName :=&Payload{}
	gadgetName.Variables = make(map[string]string)
	for i := 0; i < len(DependencyList); i++ {
		gadgetName.Variables["Dependency"] = DependencyList[i]
		buffer.Reset()
		PayloadTemplate, _ := template.New("gadgetName").Parse(payloadTemplate)
		_ = PayloadTemplate.Execute(&buffer, gadgetName)
		payloads[DependencyList[i]] = buffer.String()
	}
	return payloads

}

func SCAN_RESULTS_OUTPUT_FACTORY(result Result) string{
	var outputString string
	var buffer bytes.Buffer
	var outputStringTemplate = RESULT_OUTPUT
	var net string
	var autotype string
	if result.Netout{
		net = "可出网"
	}else{
		net = "不出网"
	}
	if result.AutoType {
		autotype = "开启"
	}else{
		autotype = "未开启"
	}
	field := &ResultFomat{}
	field.Variables = make(map[string]string)
	field.Dependency = make([]string,len(result.Dependency))
	field.Variables["Url"] = result.Url
	field.Variables["Version"] = result.Version
	field.Variables["Netout"] = net
	field.Variables["Autotype"] = autotype
	field.Dependency = result.Dependency
	buffer.Reset()
	resultTemplate ,_ := template.New("field").Parse(outputStringTemplate)
	_ = resultTemplate.Execute(&buffer,field)
	outputString  = buffer.String()
	return outputString
}

