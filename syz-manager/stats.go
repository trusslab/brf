// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
//	"fmt"
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Stat uint64

type Stats struct {
	crashes             Stat
	crashTypes          Stat
	crashSuppressed     Stat
	vmRestarts          Stat
	newInputs           Stat
	rotatedInputs       Stat
	execTotal           Stat
	hubSendProgAdd      Stat
	hubSendProgDel      Stat
	hubSendRepro        Stat
	hubRecvProg         Stat
	hubRecvProgDrop     Stat
	hubRecvRepro        Stat
	hubRecvReproDrop    Stat
	corpusCover         Stat
	corpusCoverFiltered Stat
	corpusSignal        Stat
	maxSignal           Stat

	mu         sync.Mutex
	namedStats map[string]uint64
	brfStats   map[string]uint64
	haveHub    bool
}

func (mgr *Manager) initStats() {
	// Prometheus Instrumentation https://prometheus.io/docs/guides/go-application .
	prometheus.Register(promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "syz_exec_total",
		Help: "Total executions during current execution of syz-manager",
	},
		func() float64 { return float64(mgr.stats.execTotal.get()) },
	))
	prometheus.Register(promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "syz_corpus_cover",
		Help: "Corpus coverage during current execution of syz-manager",
	},
		func() float64 { return float64(mgr.stats.corpusCover.get()) },
	))
	prometheus.Register(promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "syz_crash_total",
		Help: "Count of crashes during current execution of syz-manager",
	},
		func() float64 { return float64(mgr.stats.crashes.get()) },
	))
}

func (stats *Stats) all() map[string]uint64 {
	m := map[string]uint64{
		"crashes":           stats.crashes.get(),
		"crash types":       stats.crashTypes.get(),
		"suppressed":        stats.crashSuppressed.get(),
		"vm restarts":       stats.vmRestarts.get(),
		"new inputs":        stats.newInputs.get(),
		"rotated inputs":    stats.rotatedInputs.get(),
		"exec total":        stats.execTotal.get(),
		"coverage":          stats.corpusCover.get(),
		"filtered coverage": stats.corpusCoverFiltered.get(),
		"signal":            stats.corpusSignal.get(),
		"max signal":        stats.maxSignal.get(),
	}
	if stats.haveHub {
		m["hub: send prog add"] = stats.hubSendProgAdd.get()
		m["hub: send prog del"] = stats.hubSendProgDel.get()
		m["hub: send repro"] = stats.hubSendRepro.get()
		m["hub: recv prog"] = stats.hubRecvProg.get()
		m["hub: recv prog drop"] = stats.hubRecvProgDrop.get()
		m["hub: recv repro"] = stats.hubRecvRepro.get()
		m["hub: recv repro drop"] = stats.hubRecvReproDrop.get()
	}
	stats.mu.Lock()
	defer stats.mu.Unlock()
	for k, v := range stats.namedStats {
		m[k] = v
	}
	return m
}

func (stats *Stats) brf() (map[string]*[4]uint64, map[string]*[4]uint64, map[string]*[4]uint64, map[string]*[4]uint64) {
	generals := make(map[string]*[4]uint64)
	progs := make(map[string]*[4]uint64)
	helpers := make(map[string]*[4]uint64)
	maps := make(map[string]*[4]uint64)
	for k, v := range stats.brfStats {
		key := k[0:len(k)-2]

		typ := 0
		i := k[len(k)-1:]
		if i == "0" {
			typ = 0
		} else if i == "1" {
			typ = 1
		} else if i == "2" {
			typ = 2
		} else if i == "3" {
			typ = 3
		}

		if k[0:7] == "BPF_BRF" {
			if _, ok := generals[key]; !ok {
				generals[key] = new([4]uint64)
			}
			(*generals[key])[typ] = v
		} else if k[0:8] == "BPF_PROG" {
			if _, ok := progs[key]; !ok {
				progs[key] = new([4]uint64)
			}
			(*progs[key])[typ] = v
		} else if k[0:8] == "BPF_FUNC" {
			if _, ok := helpers[key]; !ok {
				helpers[key] = new([4]uint64)
			}
			(*helpers[key])[typ] = v
		} else if k[0:7] == "BPF_MAP" {
			if _, ok := maps[key]; !ok {
				maps[key] = new([4]uint64)
			}
			(*maps[key])[typ] = v
		}
	}
	return generals, progs, helpers, maps
}

func (stats *Stats) mergeNamed(named map[string]uint64) {
	stats.mu.Lock()
	defer stats.mu.Unlock()
	if stats.namedStats == nil {
		stats.namedStats = make(map[string]uint64)
	}
	if stats.brfStats == nil {
		stats.brfStats = make(map[string]uint64)
	}
	for k, v := range named {
		switch k {
		case "exec total":
			stats.execTotal.add(int(v))
		default:
			if k[0:3] == "BPF" {
				if k[0:7] == "BPF_BRF" && k[len(k)-1:] == "1" {
					if stats.brfStats[k] < v {
						stats.brfStats[k] = v
					}
				} else {
					stats.brfStats[k] += v
				}
			} else {
				stats.namedStats[k] += v
			}
		}
	}
}

func (s *Stat) get() uint64 {
	return atomic.LoadUint64((*uint64)(s))
}

func (s *Stat) inc() {
	s.add(1)
}

func (s *Stat) add(v int) {
	atomic.AddUint64((*uint64)(s), uint64(v))
}

func (s *Stat) set(v int) {
	atomic.StoreUint64((*uint64)(s), uint64(v))
}
