# go-SigLoader
go version for SigLoader    
仅作为学习研究使用  
原项目地址 https://github.com/med0x2e/SigFlip  
参考了原作者和[TimWhite](https://github.com/med0x2e/SigFlip/pull/5)师傅的代码。  
Loader用的：https://github.com/Ne0nd0g/go-shellcode  
## 用法
build  
```bash
go build Loader.go
```
运行  
```bash
Loader.exe -f pefile.exe -e Testkey -pid 8888
```
