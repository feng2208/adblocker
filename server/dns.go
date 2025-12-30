package server

import (
	"fmt"
	"log"
	"net/netip"

	"adblocker/config"
	"adblocker/engine"

	"time"

	"github.com/miekg/dns"
)

// Server handles incoming DNS queries.
type Server struct {
	Engine         *engine.Engine
	Upstream       string
	Server         *dns.Server
	MacResolver    *MacResolver
	UserGroupCache *TTLCache
	UpstreamCache  *TTLCache
}

// NewServer creates a new DNS server instance.
func NewServer(addr string, upstream string, engine *engine.Engine) *Server {
	srv := &Server{
		Engine:         engine,
		Upstream:       upstream,
		MacResolver:    NewMacResolver(5 * time.Minute), // Cache for 5 minutes
		UserGroupCache: NewTTLCache(),
		UpstreamCache:  NewTTLCache(),
	}

	srv.Server = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: dns.HandlerFunc(srv.handleRequest),
	}

	return srv
}

func (s *Server) Start() error {
	log.Printf("DNS Server listening on %s (Upstream: %s)", s.Server.Addr, s.Upstream)
	return s.Server.ListenAndServe()
}

func (s *Server) Stop() error {
	s.UserGroupCache.Stop()
	s.UpstreamCache.Stop()
	return s.Server.Shutdown()
}

func (s *Server) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true
	m.Authoritative = true // We are authoritative for blocks

	// 1. Get Client Info
	rAddr := w.RemoteAddr()
	clientIP, _ := netip.ParseAddrPort(rAddr.String())
	clientMAC := s.MacResolver.GetMAC(clientIP.Addr())

	// 2. Determine User Group (for Caching)
	user := s.Engine.GetUser(clientIP.Addr(), clientMAC)
	userGroupName := s.getUserGroupName(user)

	for _, q := range r.Question {
		// 3. Check UserGroup Cache (Internal blocks/rewrites)
		// Key: Group:Type:Name
		ugKey := fmt.Sprintf("%s:%d:%s", userGroupName, q.Qtype, q.Name)
		if cached := s.UserGroupCache.Get(ugKey); cached != nil {
			cached.Id = r.Id // Restore ID
			w.WriteMsg(cached)
			log.Printf("[CACHE:GROUP] Hit for %s (%s)", q.Name, userGroupName)
			return
		}

		// 4. Query Engine (Rule Check)
		res := s.Engine.Resolve(q.Name, q.Qtype, clientIP.Addr(), clientMAC)

		if res.Blocked {
			// Construct Block/Rewrite Response
			m.RecursionAvailable = true

			if res.DNSRewrite != "" {
				log.Printf("[REWRITE] Domain: %s -> %s, Client: %s, Rule: %s", q.Name, res.DNSRewrite, clientIP.Addr(), res.Rule.Pattern)
				rewriteDest := res.DNSRewrite
				rrHeader := fmt.Sprintf("%s 20 IN", q.Name)

				if destIP, err := netip.ParseAddr(rewriteDest); err == nil {
					if q.Qtype == dns.TypeA && destIP.Is4() {
						rr, _ := dns.NewRR(fmt.Sprintf("%s A %s", rrHeader, destIP.String()))
						m.Answer = append(m.Answer, rr)
					} else if q.Qtype == dns.TypeAAAA && destIP.Is6() {
						rr, _ := dns.NewRR(fmt.Sprintf("%s AAAA %s", rrHeader, destIP.String()))
						m.Answer = append(m.Answer, rr)
					}
				} else {
					if q.Qtype == dns.TypeCNAME || q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
						rr, _ := dns.NewRR(fmt.Sprintf("%s CNAME %s.", rrHeader, rewriteDest))
						m.Answer = append(m.Answer, rr)
					}
				}
			} else {
				log.Printf("[BLOCK] Domain: %s, Client: %s (MAC: %s), Rule: %s, Group: %s", q.Name, clientIP.Addr(), clientMAC, res.Rule.Pattern, userGroupName)
				switch q.Qtype {
				case dns.TypeA:
					rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN A 0.0.0.0", q.Name))
					m.Answer = append(m.Answer, rr)
				case dns.TypeAAAA:
					rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN AAAA ::", q.Name))
					m.Answer = append(m.Answer, rr)
				}
			}

			// Cache UserGroup Result (20s)
			s.UserGroupCache.Set(ugKey, m, 20*time.Second)
			w.WriteMsg(m)
			return

		} else {
			// 5. Allowed -> Check Upstream Cache
			log.Printf("[ALLOW] Domain: %s, Client: %s (MAC: %s)", q.Name, clientIP.Addr(), clientMAC)

			// Key: Type:Name (Global)
			upstreamKey := fmt.Sprintf("%d:%s", q.Qtype, q.Name)
			if cached := s.UpstreamCache.Get(upstreamKey); cached != nil {
				cached.Id = r.Id
				w.WriteMsg(cached)
				log.Printf("[CACHE:UPSTREAM] Hit for %s", q.Name)
				return
			}

			// 6. Query Upstream
			resp, err := dns.Exchange(r, s.Upstream)
			if err != nil {
				log.Printf("Upstream error: %v", err)
				dns.HandleFailed(w, r)
				return
			}

			// 7. Calculate TTL & Cache
			minTTL := uint32(20)      // 20s
			maxTTL := uint32(30 * 60) // 30m

			// Find smallest TTL in response
			recordTTL := maxTTL // Default start high
			foundRecord := false

			// Helper to check RR sections
			checkSection := func(section []dns.RR) {
				for _, rr := range section {
					ttl := rr.Header().Ttl
					if ttl < recordTTL {
						recordTTL = ttl
					}
					foundRecord = true
				}
			}
			checkSection(resp.Answer)
			checkSection(resp.Ns)
			checkSection(resp.Extra)

			if !foundRecord {
				recordTTL = minTTL // Default if no records (e.g. NXDOMAIN usually has SOA, but be safe)
			}

			// Clamp
			finalTTL := recordTTL
			if finalTTL < minTTL {
				finalTTL = minTTL
			}
			if finalTTL > maxTTL {
				finalTTL = maxTTL
			}

			// Cache Upstream Result
			s.UpstreamCache.Set(upstreamKey, resp, time.Duration(finalTTL)*time.Second)

			w.WriteMsg(resp)
			return
		}
	}

	// Should allow empty queries? Usually r.Question has 1 item.
	// If loops finishes without return (empty question), existing m is sent (empty).
	w.WriteMsg(m)
}

func (s *Server) getUserGroupName(u *config.User) string {
	if u != nil {
		return fmt.Sprintf("%s (%s)", u.Name, u.UserGroup)
	}
	return "Default"
}
