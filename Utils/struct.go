package Utils

type FS_VERSION string   //fastjson版本号
const FJ_UNDER_48 string = "Fastjson < 1.2.48"
const FJ_BEYOND_48 string = "Fastjson ≥ 1.2.48"
const FJ_NOT_DETECT string = "Fastjson isn't detected or network isn't achieve"
const FJ_BETWEEN_48_68 string = "1.2.48 ≤ Fastjson ≤ 1.2.68"
const FJ_BETWEEN_69_80 string = "1.2.69 ≤ Fastjson ≤ 1.2.80"
const FS_BETWEEN_36_62 = "1.2.37 ≤ Fastjson ≤ 1.2.61 (来自延迟探测，受网络因素影响，有一定误报率)"
const FS_BEYOND_80 = "fastjson = 1.2.83"
const NOT_FS = "target isn't fastjson"
const NETWORK_NOT_ACCESS = "Network is Unreachable"

/* class */

var DependencyList =[]string{
	"org.springframework.web.bind.annotation.RequestMapping",
	"org.apache.shiro.jndi.JndiObjectFactory",
	"org.apache.catalina.startuo.Tomcat",
	"groovy.lang.GroovyShell",
	"com.mysql.jdbc.Driver",
	"java.net.http.HttpClient",

}

/**
***  定义的一些结构体
**/

type DNSPayloads struct {
	Dns_48 string
	Dns_68 string
	Dns_80 string
}


type ResultFomat struct {
	Variables map[string]string
	Dependency []string
}


type Payload struct {
	Variables map[string]string
}


type Option struct {
	Url string
	Targets string
	Result string
}

type Result struct {
	Url string
	Type string
	Version string
	AutoType bool
	Netout bool
	Dependency []string
}

func InitResult(result Result)  {
	result.Url = ""
	result.Type = ""
	result.Version = ""
	result.AutoType = false
	result.Netout = false
}







