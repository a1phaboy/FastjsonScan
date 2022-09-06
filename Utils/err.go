package Utils

import (
	"net/http"
	"strings"
	"time"
)

/**
***	异常处理函数封装
**/

func NetWorkErrHandle(client *http.Client,req *http.Request,err error) *http.Response{
	if strings.Contains(err.Error(), "Timeout") {
		i := 0
		for {
			time.Sleep(2 * time.Second)
			resp, err := client.Do(req)
			i++
			if err == nil {
				return resp
			}
			if i > 3 {
				defer client.CloseIdleConnections()
				return nil
			}
		}
	} else {
		defer client.CloseIdleConnections()
		return nil
	}
}









