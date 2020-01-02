package main

import (

	"errors"
	"fmt"
	"github.com/go-vgo/robotgo"
	"io/ioutil"
	"log"

	"strings"
	"time"

	"os"
	"os/exec"
)

type anti360 struct {
	binpath1 string
	binpath2 string
}


type ResultInfo struct {
	status string
	info string
}

var pngroot string = ""
var torrent float64 = 0.1



func loginit() *os.File{
	f,err := os.OpenFile("scan.log",os.O_RDWR|os.O_CREATE|os.O_APPEND,0666)
	if err != nil{
		log.Fatal("open log failed!")
	}

	log.SetOutput(f)
	log.Println("test")
	return f
}

func findProcess(name string) (int32, error) {
	processes, err := robotgo.Process()
	if err != nil {
		return 0, err
	}
	for _, process := range processes {
		if process.Name == name {
			return process.Pid, nil
		}
	}
	return 0, errors.New("process not found")
}

func Exists(path string) bool{
	_ , err := os.Stat(path)
	if err != nil{
		if os.IsExist(err){
			return true
		}
		return false
	}
	return true
}

func get_bin_path(anti3602 *anti360) string{

	if Exists(anti3602.binpath1){
		return anti3602.binpath1
	}
	if Exists(anti3602.binpath2){
		return anti3602.binpath2
	}
	return ""
}

func open_bin(filepath string) {
	cmd := exec.Command(filepath)
	err := cmd.Start()

	if err != nil{

		log.Println("Error %v executing command!", err)
		os.Exit(1)
	}
}
func scan(engine string,filename string){

	cmd := exec.Command(engine,filename)

	err := cmd.Start()
	if err != nil{

		log.Println("Error %v executing command!", err)
		os.Exit(1)
	}

}


func getstat() string{
	status := "unknown"

	// 主界面
	main := robotgo.OpenBitmap(pngroot + "pic\\main.png")
	fx,fy := robotgo.FindBitmap(main,nil,torrent)

	if fx != -1 && fy != -1{
		status = "main"
		return status
	}

	// 扫描状态
	scanning := robotgo.OpenBitmap(pngroot + "pic\\scanning.png")
	defer robotgo.FreeBitmap(scanning)
	fx,fy = robotgo.FindBitmap(scanning,nil,torrent)

	if fx != -1 && fy != -1{
		status = "scanning"
		return status
	}

	// 恶意文件
	mal := robotgo.OpenBitmap(pngroot + "pic\\mal.png")
	defer robotgo.FreeBitmap(mal)
	fx,fy = robotgo.FindBitmap(mal,nil,torrent)

	if fx != -1 && fy != -1{
		status = "malware"
		return status
	}

	// 正常文件
	benign := robotgo.OpenBitmap(pngroot + "pic\\benign.png")
	defer robotgo.FreeBitmap(benign)
	fx,fy = robotgo.FindBitmap(benign,nil,torrent)

	if fx != -1 && fy != -1{
		status = "benign"
		return status
	}

	benign1 := robotgo.OpenBitmap(pngroot + "pic\\benign1.png")
	defer robotgo.FreeBitmap(benign1)
	fx,fy = robotgo.FindBitmap(benign,nil,torrent)
	if fx != -1 && fy != -1{
		status = "benign"
		return status
	}
	return status
}

func getmaldetail() string{
	info := ""
	// 恶意文件
	mal := robotgo.OpenBitmap(pngroot + "pic\\mal.png")
	fx,fy := robotgo.FindBitmap(mal,nil,torrent)
	if fx == -1 || fy == -1{

		log.Println("get location error")
		return info
	}

	robotgo.MoveMouse(fx+5,fy+2)
	nowtime := time.Now().Format("20060102150405")
	robotgo.MouseClick("left",true)

	log.Println(nowtime)
	logfile := `C:\Program Files(x86)\360sd\Log\VirusScanLog\`+ nowtime + `.log`
	infodata,err :=ioutil.ReadFile(logfile)

	if err != nil{
		log.Println(err)
		return info
	}
	data := strings.TrimSpace(string(infodata))
	lines := strings.Split(data,"\n")

	lastline := lines[len(lines)-1]
	log.Println(lastline)

	info = strings.Split(lastline,"	")[1]

	return info
}


func result() *ResultInfo{

	log.Println("start scan ...")
	ret := &ResultInfo{
		status: "unkonwn",
		info:   "",
	}
	// 等待两分钟
	Loop:
	for i:=0;i<=20;i++{

		status := getstat()

		log.Println("current status "+ status)
		switch status {

		case "scanning":
			time.Sleep(5*time.Second)
		case "malware":
			ret.status = "malware"

			// 等待日志文件生成
			time.Sleep(1*time.Second)
			ret.info = getmaldetail()
			break Loop
		case "benign":
			ret.status = "benign"
			break Loop
		case "unknown":
			time.Sleep(5*time.Second)
		}
	}
	return ret
}




func is_running(){
	for{
		r,err:=findProcess("360sd.exe")
		if err != nil{
			return
		}
		if r == 0{
			return
		}
		log.Println("another task running")
		time.Sleep(1*time.Second)
	}
}
func detect(filename string){

	_ ,err := os.Stat(filename)
	if err != nil {
		log.Println("file not found")
		fmt.Println("error,")
		return
	}

	filename = strings.ReplaceAll(filename,"/","\\")
	if err != nil {
		log.Println("get abs file error")
		fmt.Println("error,")
		return
	}

	var a360 anti360
	a360.binpath1 = `C:\Program Files(x86)\360sd\360sd.exe`
	a360.binpath2 = `C:\Program Files\360\360sd\360sd.exe`
	// 获取引擎执行路径
	binpath := get_bin_path(&a360)
	// 单线程运行，判断不存在扫描任务
	is_running()
	// 开启检测引擎
	open_bin(binpath)

	// 确保引擎已打开
	for i:=0;i<=5;i++{
		if getstat() =="main"{
			break
		}
		log.Println(getstat())
		time.Sleep(time.Second * 1)
	}

	scan(binpath,filename)

	time.Sleep(1000)
	// 等待结果
	ret :=result()

	// 结果输出
	fmt.Println(filename+","+ret.status+","+ ret.info)

}






func main() {

	logfile :=loginit()
	defer logfile.Close()
	detect(os.Args[1])

}
