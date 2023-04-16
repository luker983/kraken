package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"text/template"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"nhooyr.io/websocket"

	"kraken/util"
)

const (
	privateKey = "2J6VczjFmT2RMsqS1ltsHwOHtGrwqept5BewhZ91blw="

	assetsDir     = "../../assets/"
	compressedDir = "../../compressed_assets/"

	pubDir            = assetsDir + "gallery/pub/"
	privDir           = assetsDir + "gallery/priv/"
	compressedPubDir  = compressedDir + "gallery/pub/"
	compressedPrivDir = compressedDir + "gallery/priv/"
	staticDir         = compressedDir + "static/"
	indexTemplate     = assetsDir + "index.html"

	mtu     = util.MTU
	timeout = 10
)

type Image struct {
	Name string
	Path string
}

type Collection struct {
	Name   string
	Images []Image
}

type Gallery struct {
	Public  []Collection
	Private []Collection
}

type CompressedDir struct {
	d http.Dir
}

func main() {
	// Make virtual device.
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(util.ServerVirtualAddress)},
		[]netip.Addr{},
		mtu,
	)
	if err != nil {
		log.Panic(err)
	}

	// Setup websocket bind for device.
	wsChan := make(chan WSMessage)
	bind := NewWSBind(wsChan)
	// DEBUG: dev := device.NewDevice(tun, bind, device.NewLogger(device.LogLevelVerbose, ""))
	dev := device.NewDevice(tun, bind, device.NewLogger(device.LogLevelSilent, ""))
	err = dev.IpcSet(fmt.Sprintf("private_key=%s", util.Base64KeyToHex(privateKey)))
	if err != nil {
		log.Panic(err)
	}

	err = dev.Up()
	if err != nil {
		log.Panic(err)
	}

	// Virtual file server.
	go serveFiles(tnet)

	// "Real" server.
	mux := http.NewServeMux()
	server := http.Server{
		Addr:    fmt.Sprintf(":%v", util.ServerPhysicalPort),
		Handler: mux,
	}

	mux.Handle("/", serveTemplate())
	mux.Handle("/ws", http.HandlerFunc(wsHandlerWrapper(dev, wsChan)))
	mux.Handle("/static/", compressedWrapper(http.StripPrefix("/static/", http.FileServer(CompressedDir{http.Dir(staticDir)}))))
	err = server.ListenAndServe()
	if err != nil {
		fmt.Println("Failed to start server", err)
		return
	}
}

func (d CompressedDir) Open(name string) (http.File, error) {
	return d.d.Open(name + ".gz")
}

// Serve files using virtual server.
func serveFiles(tnet *netstack.Net) {
	l, err := tnet.ListenTCP(&net.TCPAddr{Port: util.ServerVirtualPort})
	if err != nil {
		log.Panicln(err)
	}

	http.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir(pubDir))))
	http.Handle("/private/", localOnlyWrapper(http.StripPrefix("/private/", http.FileServer(http.Dir(privDir)))))

	err = http.Serve(l, nil)
	if err != nil {
		log.Panicln(err)
	}
}

// Format image directories for template use.
func collectionsFromDirectory(dir string) ([]Collection, error) {
	dirFile, err := os.Open(dir)
	if err != nil {
		return []Collection{}, err
	}
	collectionNames, err := dirFile.Readdirnames(0)
	if err != nil {
		return []Collection{}, err
	}
	collections := []Collection{}
	for _, dirName := range collectionNames {
		images := []Image{}
		dirFile, err = os.Open(filepath.Join(dir, dirName))
		if err != nil {
			return []Collection{}, err
		}
		imageNames, err := dirFile.Readdirnames(0)
		if err != nil {
			return []Collection{}, err
		}
		for _, fname := range imageNames {
			images = append(images, Image{
				Name: fname[:len(fname)-len(filepath.Ext(fname))],
				Path: fname,
			})
		}
		collections = append(collections, Collection{
			Name:   dirName,
			Images: images,
		})
	}

	return collections, nil
}

// Read filenames from gallery and serve template.
func serveTemplate() http.Handler {
	tmpl := template.Must(template.ParseFiles(indexTemplate))

	publicImages, err := collectionsFromDirectory(pubDir)
	if err != nil {
		log.Panic(err)
	}
	privateImages, err := collectionsFromDirectory(privDir)
	if err != nil {
		log.Panic(err)
	}

	gallery := Gallery{
		Public:  publicImages,
		Private: privateImages,
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tmpl.Execute(w, gallery)
	})
}

// Only localhost can access these files.
func localOnlyWrapper(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteAddr := netip.MustParseAddrPort(r.RemoteAddr).Addr()
		if remoteAddr != netip.MustParseAddr("127.0.0.1") && remoteAddr != netip.MustParseAddr("::1") {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, "Remote access to this file is disabled")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Add content-encoding header for compressed files.
func compressedWrapper(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", mime.TypeByExtension(filepath.Ext(r.URL.Path)))
		h.ServeHTTP(w, r)
	})
}

// WireGuard websocket handler.
func wsHandlerWrapper(dev *device.Device, wsChan chan WSMessage) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get public key and virtual address from client and temporarily add to peer list.
		pubKey := r.URL.Query().Get("pub")
		pubKeyHex := util.UrlKeyToHex(pubKey)
		if len(pubKeyHex) == 0 {
			log.Printf("ws error: couldn't parse pub key")
			return
		}
		remoteAddr, err := netip.ParseAddr(r.URL.Query().Get("addr"))
		if err != nil {
			log.Printf("ws error: %v", err)
			return
		}
		remotePrefix := netip.PrefixFrom(remoteAddr, remoteAddr.BitLen())

		npk := device.NoisePublicKey{}
		err = npk.FromHex(pubKeyHex)
		if err != nil {
			log.Printf("ws error: %v", err)
			return
		}
		err = dev.IpcSet(fmt.Sprintf("public_key=%s\nallowed_ip=%v", pubKeyHex, remotePrefix))
		if err != nil {
			log.Printf("ws error: %v", err)
			return
		}
		defer dev.RemovePeer(npk)

		// Upgrade request conn to websocket with timeout.
		// Loop over read/write and forward packets to virtual interface.
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			log.Printf("ws error: %v", err)
			return
		}
		defer c.Close(websocket.StatusNormalClosure, "")

		ctx, cancel := context.WithTimeout(r.Context(), time.Second*timeout)
		defer cancel()

		netConn := websocket.NetConn(ctx, c, websocket.MessageBinary)

		recvChan := make(chan []byte)
		defer close(recvChan)

		wg := new(sync.WaitGroup)
		wg.Add(2)

		// Read loop.
		go func() {
			defer wg.Done()
			readBuf := make([]byte, 1500)
			for {
				n, err := netConn.Read(readBuf)
				if err != nil {
					cancel()
					// DEBUG: log.Print(err)
					return
				}

				select {
				case wsChan <- WSMessage{
					buff:     readBuf[:n],
					endpoint: WSEndpoint(netip.MustParseAddrPort(r.RemoteAddr)),
					response: WSResponse{
						data: recvChan,
						ctx:  ctx,
					},
				}:
				case <-ctx.Done():
					return
				}
			}
		}()

		// Write loop.
		go func() {
			defer wg.Done()
			for {
				select {
				case msg := <-recvChan:
					_, err := netConn.Write(msg)
					if err != nil {
						cancel()
						// DEBUG: log.Print(err)
						return
					}
				case <-ctx.Done():
					return
				}

			}
		}()

		wg.Wait()
	}
}
