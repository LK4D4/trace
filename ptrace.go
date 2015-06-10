package trace

import (
	"bytes"
	"fmt"
	"syscall"

	"github.com/LK4D4/syscallpp"
	"github.com/Sirupsen/logrus"
)

func printSyscall(regs *syscall.PtraceRegs) {
	logrus.Infof("Syscall: %d(%d, %d, %d)", regs.Orig_rax, regs.Rdi, regs.Rsi, regs.Rdx)
}

type Syscall struct {
	Name   string
	Number int
	Args   []string
}

func getArg(regs *syscall.PtraceRegs, i int) uint64 {
	switch i {
	case 0:
		return regs.Rdi
	case 1:
		return regs.Rsi
	case 2:
		return regs.Rdx
	case 3:
		return regs.R10
	case 4:
		return regs.R8
	case 5:
		return regs.R9
	}
	return 0
}

func readString(pid int, addr uint64) (string, error) {
	out := make([]byte, 4096)
	_, err := syscall.PtracePeekText(pid, uintptr(addr), out)
	if err != nil {
		return "", err
	}
	idx := bytes.IndexRune(out, '\x00')
	out = out[:idx]
	return string(out), nil
}

func getArgs(pid int, argsTypes []syscallpp.ArgType, regs *syscall.PtraceRegs) ([]string, error) {
	var res []string
	for i, t := range argsTypes {
		arg := getArg(regs, i)
		switch t {
		case syscallpp.ARG_INT:
			res = append(res, fmt.Sprintf("%d", arg))
		case syscallpp.ARG_STR:
			out, err := readString(pid, arg)
			if err != nil {
				return nil, err
			}
			res = append(res, fmt.Sprintf("%q", out))
		case syscallpp.ARG_PTR:
			res = append(res, fmt.Sprintf("%#x", arg))
		}
	}
	return res, nil
}

func New(pid int) (<-chan *Syscall, error) {
	syscall.Wait4(pid, nil, 0, nil)
	if err := syscall.PtraceSetOptions(pid, syscall.PTRACE_O_TRACESYSGOOD); err != nil {
		return nil, err
	}
	ch := make(chan *Syscall, 4096)
	go func() {
		for {
			if err := syscall.PtraceSyscall(pid, 0); err != nil {
				close(ch)
				break
			}
			status := new(syscall.WaitStatus)
			if _, err := syscall.Wait4(pid, status, 0, nil); err != nil {
				close(ch)
				break
			}
			if !status.Stopped() {
				close(ch)
				break
			}
			regs := &syscall.PtraceRegs{}
			if err := syscall.PtraceGetRegs(pid, regs); err != nil {
				close(ch)
				break
			}
			name := syscallpp.GetName(int(regs.Orig_rax))
			args, err := getArgs(pid, syscallpp.GetArgsTypes(name), regs)
			if err != nil {
				close(ch)
				break
			}
			ch <- &Syscall{Name: name, Number: int(regs.Orig_rax), Args: args}
		}
	}()
	return ch, nil
}
