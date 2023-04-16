// adapted from https://golangbot.com/webassembly-using-go/
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"syscall/js"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"kraken/util"
)

func main() {
	js.Global().Set("getFile", getFileWrapper())
	<-make(chan struct{})
}

func getFile(filename string, hostname string) ([]byte, error) {
	// Generate ephemeral keypair and format server's public key.
	privKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return []byte{}, err
	}
	privKeyBytes, err := base64.StdEncoding.DecodeString(privKey.String())
	if err != nil {
		return []byte{}, err
	}
	serverPubKeyBytes, err := base64.StdEncoding.DecodeString(util.ServerPubKey)
	if err != nil {
		return []byte{}, err
	}

	// Make ephemeral ipv6 address.
	ephemAddr, err := generateAddr()

	// Make virtual device.
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{ephemAddr},
		[]netip.Addr{},
		util.MTU)
	if err != nil {
		return []byte{}, err
	}
	// DEBUG: dev := device.NewDevice(tun, NewWSBind(privKey.PublicKey().String(), ephemAddr, hostname), device.NewLogger(device.LogLevelVerbose, ""))
	dev := device.NewDevice(tun, NewWSBind(privKey.PublicKey().String(), ephemAddr, hostname), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()

	dev.IpcSet(fmt.Sprintf(`private_key=%s
public_key=%s
endpoint=[::]:%d
allowed_ip=::/0
`,
		hex.EncodeToString(privKeyBytes),
		hex.EncodeToString(serverPubKeyBytes),
		util.ServerPhysicalPort,
	))

	err = dev.Up()
	if err != nil {
		return []byte{}, err
	}

	client := http.Client{
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
		},
		Timeout: 5 * time.Second,
	}
	url := fmt.Sprintf("http://%s/%s", net.JoinHostPort(util.ServerVirtualAddress, fmt.Sprint(fmt.Sprint(util.ServerVirtualPort))), filename)
	resp, err := client.Get(url)
	if err != nil {
		return []byte{}, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, err
	}

	dev.Close()

	if resp.StatusCode != 200 {
		return []byte{}, errors.New(string(body))
	}
	return body, nil
}

func generateAddr() (netip.Addr, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return netip.Addr{}, err
	}

	return netip.AddrFrom16(*(*[16]byte)(b)), nil
}

func getFileWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		filename := args[0].String()
		hostname := args[1].String()

		handler := js.FuncOf(func(this js.Value, args []js.Value) any {
			resolve, reject := args[0], args[1]

			go func() {
				contents, err := getFile(filename, hostname)
				if err != nil {
					errorConstructor := js.Global().Get("Error")
					errorObject := errorConstructor.New(err.Error())
					reject.Invoke(errorObject)
					return
				}

				base := filepath.Base(filename)
				base = base[:len(base)-len(filepath.Ext(base))]

				switch filepath.Ext(filename) {
				case ".png", ".jpg":
					resolve.Invoke(fmt.Sprintf("<figure>\n<img alt=%s src=\"data:image/png;base64,%s\">\n<figcaption><i>%s</i></figcaption>\n</figure>", base, base64.StdEncoding.EncodeToString(contents), base))
				default:
					resolve.Invoke(string(contents))
				}
			}()

			return nil
		})

		promiseConstructor := js.Global().Get("Promise")
		return promiseConstructor.New(handler)
	})
}
