package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"strings"
)

// SampleDSL
type SampleDSL struct {
	DSLs map[string]interface{}
}

func main() {
	files, err := ioutil.ReadDir("./angora_log")
	if err != nil {
		log.Fatal(err)
		return
	}
	sample := SampleDSL{
		DSLs: make(map[string]interface{}),
	}
	for i, file := range files {
		if file.IsDir() {
			continue
		}
		//log.Println("file name : %s\n", file.Name())
		ReadAngoraLog(&sample, "./angora_log/"+file.Name())
		log.Printf("[ %d ] DSLS Len[ %d ]\n", i, len(sample.DSLs))
	}
	// for debug
	//for i, v := range sample.DSLs {
	//    log.Printf("Dec : %s\n", i)
	//    enc := v.([]string)
	//    log.Println("Enc : ", enc)
	//}
	WriteDSLs(&sample)
}

// ReadAngoraLog angora 로그에서 DSL을 추출한다.
func ReadAngoraLog(dsls *SampleDSL, path string) error {
	readFile, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	defer readFile.Close()

	reader := bufio.NewReader(readFile)

	for {
		line, isPrefix, err := reader.ReadLine()
		if isPrefix || err != nil {
			break
		}
		strLine := string(line)

		if strings.Index(strLine, `angora.interface.restful.handlers.queryverify - INFO - encrypted_query:`) > 0 {
			// DSL 시작 전 필요없는 로그를 제거
			dslLog := strings.Split(strLine, "[")
			if len(dslLog) == 2 {
				// 제일 끝의 ']' 문자 제거
				dslLog[1] = strings.TrimRight(dslLog[1], "]")
				// ',' 구분되어 표현된 문자를 배열 형태로 자름.
				sliceText := strings.Split(dslLog[1], ",")

				isError := false
				var descryptText string
				// 각 배열을 Base64 Decode, RSA Decrypt 수행
				for i, v := range sliceText {
					sliceText[i] = strings.Trim(strings.TrimSpace(v), "'")
					baseDecode, _ := base64.StdEncoding.DecodeString(sliceText[i])
					plainText, err := Decrypt(baseDecode, "")
					if err != nil {
						log.Println(err)
						isError = true
						break
					}
					descryptText = descryptText + string(plainText)
				}
				if isError {
					continue
				}
				dec, err := url.QueryUnescape(descryptText)
				if err != nil {
					log.Println(err)
					continue
				}
				dsls.DSLs[dec] = sliceText
				//log.Println("dec: " + dsl.DecryptText)
				//log.Println(dsl.EncryptText)
				//DSLs = append(DSLs, dsl)
			}
			continue
		}
	}

	//var insertData map[string]interface{}
	//insertData = make(map[string]interface{})
	//for _, dsl := range DSLs {
	//    dec, err := url.QueryUnescape(dsl.DecryptText)
	//    if err != nil {
	//        log.Println("fail uri decode")
	//        continue
	//    }
	//    insertData[dec] = dsl.EncryptText
	//}
	//for k, _ := range insertData {
	//    log.Println(k)
	//}
	//log.Printf("encrypt[ %d ] decrypt[ %d ]\n", encrypt, decrypt)
	return nil
}

// WriteDSLs write dsl to file
func WriteDSLs(dsl *SampleDSL) error {
	fd, err := os.OpenFile("./sample_dsl.json",
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		os.FileMode(0644))
	if err != nil {
		return err
	}
	writer := bufio.NewWriter(fd)
	// json struct to json string
	jsonString, err := json.Marshal(dsl)
	if err != nil {
		return err
	}
	// string write to file
	len, err := writer.WriteString(string(jsonString))
	log.Printf("Wrote %d bytes\n", len)
	writer.Flush()
	fd.Close()
	return nil
}
