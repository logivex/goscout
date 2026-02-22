package portscan

import (
	"net"
	"time"

	"github.com/logivex/goscout/pkg/rawsock"
)

type Scanner struct {
	cfg Config
}

func New(cfg Config) *Scanner {
	return &Scanner{cfg: cfg}
}

func (s *Scanner) Scan(target net.IP, ports []int) ([]Result, error) {
	sock, err := rawsock.Open()
	if err != nil {
		return nil, err
	}

	tracker := NewTracker()
	sender := NewSender(sock, target, s.cfg.SrcPort, s.cfg.Rate)
	receiver := NewReceiver(sock, target, s.cfg.SrcPort, tracker)

	tracker.Run()
	receiver.Run()

	sem := make(chan struct{}, s.cfg.Concurrency)

	for _, port := range ports {
		sem <- struct{}{}
		go func(p int) {
			defer func() { <-sem }()
			for i := 0; i <= s.cfg.Retries; i++ {
				sender.Send(p)
			}
			sender.Delay()
		}(port)
	}

	for i := 0; i < cap(sem); i++ {
		sem <- struct{}{}
	}

	time.Sleep(s.cfg.Timeout)
	receiver.Stop()
	sock.Close()
	results := tracker.Close(ports)
	time.Sleep(100 * time.Millisecond)
	return results, nil
}
