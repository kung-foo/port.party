package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"time"

	"rsc.io/letsencrypt"

	rice "github.com/GeertJohan/go.rice"
	"github.com/Sirupsen/logrus"
	docopt "github.com/docopt/docopt-go"
	"github.com/gorilla/mux"
	"github.com/kung-foo/freki"
	"github.com/phyber/negroni-gzip/gzip"
	"github.com/rs/cors"
	"github.com/soheilhy/cmux"
	"github.com/urfave/negroni"
)

const port = 5000

var (
	// VERSION is set by the makefile
	VERSION = "0.0.0"
	devMode = false
	logger  *logrus.Logger
	eicar   = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
)

var frekiRules = fmt.Sprintf(`
rules:
    - match: tcp dst port 10022
      type: rewrite
      target: 22
    - match: tcp
      type: rewrite
      target: %d
`, port)

var usage = `
Usage:
    port-party [options] [-v ...] -i <interface>
    port-party -h | --help | --version
Options:
    -i --interface=<iface>  Bind to this interface.
    -d --development        Enable dev mode.
    -h --help               Show this screen.
    --version               Show version.
    -v                      Enable verbose logging (-vv for very verbose)
`

func main() {
	mainEx(os.Args[1:])
}

func onErrorExit(err error) {
	if err != nil {
		logger.Fatalf("[prt.prty] %+v", err)
	}
}

func onInterruptSignal(fn func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	go func() {
		<-sig
		fn()
	}()
}

type prefixWriter struct {
	io.Writer
	prefix string
}

func (pw *prefixWriter) Write(p []byte) (int, error) {
	prefixed := append([]byte(pw.prefix), p...)
	return pw.Writer.Write(prefixed)
}

func mainEx(argv []string) {
	args, err := docopt.Parse(usage, argv, true, VERSION, true)
	onErrorExit(err)

	logger = logrus.New()

	if args["-v"].(int) > 0 {
		logger.Level = logrus.DebugLevel
		logger.Formatter = &logrus.TextFormatter{
			FullTimestamp: true,
		}
	}

	devMode = args["--development"].(bool)

	if devMode {
		logger.Warn("[prt.prty] development enabled!")

		go func() {
			ticker := time.NewTicker(time.Second * 5)
			grc := runtime.NumGoroutine()

			for range ticker.C {
				n := runtime.NumGoroutine()

				if n != grc {
					logger.Debugf("[stats   ] NumGoroutine:%d", n)
					grc = n
				}
			}
		}()
	}

	rules, err := freki.ParseRuleSpec([]byte(frekiRules))
	onErrorExit(err)

	processor, err := freki.New(args["--interface"].(string), rules, logger)
	onErrorExit(err)

	err = processor.Init()
	onErrorExit(err)

	var srv *http.Server

	exitMtx := sync.RWMutex{}
	exit := func() {
		exitMtx.Lock()
		println() // make it look nice after the ^C
		logger.Debugf("[prt.prty] shutting down...")

		if srv != nil {
			logger.Debugf("[prt.prty] stopping web server...")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			srv.Shutdown(ctx)
		}

		onErrorExit(processor.Shutdown())
	}

	defer exit()
	onInterruptSignal(func() {
		exit()
		os.Exit(0)
	})

	go func() {
		err = processor.Start()
		if err != nil {
			logger.Errorf("[prt.prty] %+v", err)
		}
	}()

	tbox := rice.MustFindBox("templates")
	hbox := rice.MustFindBox("public_html")

	templates, err := parseTemplates(tbox)

	//templates := template.Must(template.ParseGlob("./templates/*.html"))

	router := mux.NewRouter()

	/*
		router.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
			fmt.Fprint(rw, "HELLO MR CURL")
		}).Headers("Accept")

		router.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
			fmt.Fprint(rw, "HELLO MR CURL")
		}).HeadersRegexp("User-Agent", "curl/.*")
	*/

	router.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		/*
			if devMode {
				templates = template.Must(template.ParseGlob("./templates/*.html"))
			}
		*/

		targetPort := r.Context().Value("targetPort").(string)
		p := &parameters{
			RemoteAddr: r.RemoteAddr,
			Port:       targetPort,
			UserAgent:  r.UserAgent(),
		}
		err := templates.ExecuteTemplate(rw, "index.html", p)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	router.HandleFunc("/cors.json", func(rw http.ResponseWriter, r *http.Request) {
		targetPort, err := strconv.Atoi(r.Context().Value("targetPort").(string))
		if err != nil {
			targetPort = -1
		}
		json.NewEncoder(rw).Encode(struct{ Port int }{targetPort})
	})

	router.HandleFunc("/eicar", func(rw http.ResponseWriter, r *http.Request) {
		fmt.Fprint(rw, eicar)
	})

	router.PathPrefix("/").HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		fmt.Fprint(rw, "OK")
	})

	mw := negroni.New()

	mw.UseFunc(func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		host, port, _ := net.SplitHostPort(r.RemoteAddr)
		ck := freki.NewConnKeyByString(host, port)
		md := processor.Connections.GetByFlow(ck)

		var tport string

		if md == nil {
			tport = "unknown"
		} else {
			tport = strconv.Itoa(int(md.TargetPort))
		}

		ctx := context.WithValue(r.Context(), "targetPort", tport)
		r = r.WithContext(ctx)

		next(rw, r)
	})

	mw.Use(cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
	}))

	mw.Use(&loggingHandler{log: logger})
	mw.Use(negroni.NewStatic(hbox.HTTPBox()))
	mw.Use(gzip.Gzip(gzip.DefaultCompression))

	mw.UseHandler(router)

	tcpListener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	onErrorExit(err)

	cm := cmux.New(tcpListener)
	httpl := cm.Match(cmux.HTTP2(), cmux.HTTP1Fast())
	tlsl := cm.Match(cmux.Any())

	srv = &http.Server{
		Handler:        mw,
		MaxHeaderBytes: 2048,
		WriteTimeout:   5 * time.Second,
		ReadTimeout:    5 * time.Second,
	}

	go srv.Serve(httpl)

	config := &tls.Config{}

	if !devMode {
		var m letsencrypt.Manager
		if err = m.CacheFile("letsencrypt.cache"); err != nil {
			onErrorExit(err)
		}
		m.SetHosts([]string{"port.party"})

		if !m.Registered() {
			onErrorExit(m.Register("me@jonathan.camp", nil))
		}

		config.GetCertificate = m.GetCertificate
	} else {
		SetSelfSignedCert(config)
	}

	srv.ErrorLog = log.New(logger.Out, "[internal] ", log.LstdFlags)

	go srv.Serve(tls.NewListener(tlsl, config))

	err = cm.Serve()
	if err != nil && err != http.ErrServerClosed {
		onErrorExit(err)
	}
}

type parameters struct {
	Port       string
	RemoteAddr string
	UserAgent  string
}

type loggingHandler struct {
	log *logrus.Logger
}

func (h *loggingHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	next(rw, r)

	targetPort := r.Context().Value("targetPort")

	res := rw.(negroni.ResponseWriter)

	host, _, err := net.SplitHostPort(r.RemoteAddr)

	if err != nil {
		host = r.RemoteAddr
	}

	// TODO: something like: https://github.com/gorilla/handlers/blob/master/handlers.go#L174
	h.log.Infof("[prt.prty] request: %s - - [%s] \"%s %s %s\" %d %d \"%s\" \"%s\" %s",
		host,
		time.Now().Format(time.RFC3339),
		r.Method,
		r.RequestURI,
		r.Proto,
		res.Status(),
		res.Size(),
		r.Referer(),
		r.UserAgent(),
		targetPort,
	)
}

func parseTemplates(box *rice.Box) (t *template.Template, err error) {
	box.Walk("/", func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		path = path[1:]

		if t == nil {
			t = template.New(path)
		} else {
			t = t.New(path)
		}

		t, err = t.Parse(box.MustString(path))

		return err
	})
	return
}
