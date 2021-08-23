# go-SigLoader
**仅作为学习研究使用，请勿用于非法用途**  
go version for SigLoader    
自己学习golang，顺手仿写的Loader，参考了原作者和[TimWhite](https://github.com/med0x2e/SigFlip/pull/5)师傅的代码。  
原项目地址 https://github.com/med0x2e/SigFlip    
Loader地址：https://github.com/Ne0nd0g/go-shellcode  
## 用法
参考原项目，生成一个pefile，之后loader去加载，实测bin文件可以成功上线。  
build  
```bash
go build Loader.go
```
运行  
```bash
Loader.exe -f pefile.exe -e Testkey -pid 8888
```
