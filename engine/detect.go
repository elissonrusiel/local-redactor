package main

import (
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Finding is one detected span. Start/End are UTF-16 code-unit offsets so the
// JavaScript side can slice strings directly.
type Finding struct {
	Start    int    `json:"start"`
	End      int    `json:"end"`
	Kind     string `json:"kind"`
	Text     string `json:"text"`
	Severity string `json:"severity"`
	Source   string `json:"source"` // engine | dictionary | term
	Rule     string `json:"rule"`
	bs, be   int    // byte offsets (internal)
}

var sevRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

type rule struct {
	name, kind, sev string
	re              *regexp.Regexp
	group           int                     // capture group holding the value (0 = whole match)
	valid           func(s string) bool     // optional validator
}

var (
	reEmail   = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,24}`)
	reCard    = regexp.MustCompile(`\b\d(?:[ \-]?\d){12,18}\b`)
	reIBAN    = regexp.MustCompile(`\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b`)
	reSSN     = regexp.MustCompile(`\b(\d{3})-(\d{2})-(\d{4})\b`)
	reIPv4    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reIPv6    = regexp.MustCompile(`(?i)(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}`)
	reMAC     = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b`)
	rePhone   = regexp.MustCompile(`(?:\+\d{1,3}[\s.\-]?)?(?:\(\d{1,4}\)[\s.\-]?)?\d{2,4}(?:[\s.\-]\d{2,6}){1,4}(?:\s?(?:x|ext\.?)\s?\d{1,5})?`)
	rePhoneLb = regexp.MustCompile(`(?i)\b(?:phone|tel|telephone|mobile|cell|fax|whatsapp)\b\.?\s*(?:no\.?|number|#)?\s*[:=]?\s*$`)
	reDOB     = regexp.MustCompile(`(?i)\b(?:dob|d\.o\.b\.?|date of birth|birth ?date|born(?: on)?)\b(?:\s+(?:is|was|of))?\s*[:=]?\s*((?:\d{1,2}[./\-]\d{1,2}[./\-]\d{2,4})|(?:\d{4}-\d{2}-\d{2})|(?:\d{1,2}\s+[A-Z][a-z]{2,8}\.?\s+\d{4})|(?:[A-Z][a-z]{2,8}\.?\s+\d{1,2},?\s+\d{4}))`)
	reTitle   = regexp.MustCompile(`\b(?:Mr|Mrs|Ms|Mx|Dr|Prof)\.?\s+([A-Z][a-zA-Z'\-]+(?:\s+[A-Z][a-zA-Z'\-]+){0,2})`)
	reNameLb  = regexp.MustCompile(`(?i:\b(?:name|full name|first name|last name|surname|patient|customer|client|employee|contact|signed|attn)\b)\s*[:=]\s*([A-Z][a-zA-Z'\-]+(?:[ \t]+[A-Z][a-zA-Z'\-]+){0,2})`)
	reAddr    = regexp.MustCompile(`\b\d{1,5}[A-Za-z]?\s+(?:[A-Z][a-z]+\s+){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Close|Square|Sq)\b\.?(?:,?\s+(?:Apt|Suite|Unit|Flat)\.?\s*#?\w+)?`)
	rePostUK  = regexp.MustCompile(`\b(?:[A-Z]{1,2}\d[A-Z\d]?|GIR) ?\d[A-Z]{2}\b`)
	reSecretL = regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|passcode|pin|secret|api[_\- ]?key|apikey|access[_\- ]?key|auth[_\- ]?token|token|client[_\- ]?secret)\b\s*[:=]\s*["']?([^\s"',;]{4,})`)
	reIDLb    = regexp.MustCompile(`(?i)\b(?:passport|driver'?s? licen[cs]e|licen[cs]e no|national id|id number|id no|account (?:no|number)|acct|member id|policy (?:no|number)|tax id|vat (?:no|number)|nhs number|medical record|mrn)\b\.?\s*(?:no\.?|number|#)?\s*[:=#]?\s*([A-Z0-9][A-Z0-9\-]{4,19})`)
)

var reDateLike = regexp.MustCompile(`^\d{4}[\-./]\d{2}[\-./]\d{2}$|^\d{2}[\-./]\d{2}[\-./]\d{4}$`)

var secretRules = []rule{
	{name: "aws-access-key", re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{name: "github-token", re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`)},
	{name: "github-pat", re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{60,}\b`)},
	{name: "slack-token", re: regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9\-]{10,}\b`)},
	{name: "google-api-key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
	{name: "stripe-key", re: regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b`)},
	{name: "anthropic-key", re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}`)},
	{name: "openai-key", re: regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}`)},
	{name: "jwt", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`)},
	{name: "private-key", re: regexp.MustCompile(`-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z]+ )?PRIVATE KEY-----|$)`)},
}

func digits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func luhn(d string) bool {
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

func validCard(s string) bool {
	d := digits(s)
	if len(d) < 13 || len(d) > 19 || !luhn(d) {
		return false
	}
	if strings.Trim(d, "0") == "" {
		return false
	}
	switch d[0] {
	case '2', '3', '4', '5', '6':
		return true
	}
	return false
}

func validIBAN(s string) bool {
	c := strings.ReplaceAll(s, " ", "")
	if len(c) < 15 || len(c) > 34 {
		return false
	}
	r := c[4:] + c[:4]
	rem := 0
	for _, ch := range r {
		var v int
		switch {
		case ch >= '0' && ch <= '9':
			v = int(ch - '0')
		case ch >= 'A' && ch <= 'Z':
			v = int(ch-'A') + 10
		default:
			return false
		}
		if v >= 10 {
			rem = (rem*100 + v) % 97
		} else {
			rem = (rem*10 + v) % 97
		}
	}
	return rem == 1
}

func validSSN(m []string) bool {
	a, g, s := m[1], m[2], m[3]
	if a == "000" || a == "666" || a[0] == '9' || g == "00" || s == "0000" {
		return false
	}
	return true
}

func validIPv4(s string) bool {
	for _, p := range strings.Split(s, ".") {
		if len(p) > 1 && p[0] == '0' {
			return false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n > 255 {
			return false
		}
	}
	return s != "0.0.0.0"
}

func validIPv6(s string) bool {
	if strings.Count(s, ":") < 2 || len(s) < 6 {
		return false
	}
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is6() {
		return false
	}
	// require at least two hex groups with letters or 3+ chars, to skip things like times
	groups := 0
	for _, g := range strings.Split(s, ":") {
		if len(g) >= 3 {
			groups++
		}
	}
	return groups >= 2
}

func validPhone(s string, before string) bool {
	d := digits(strings.SplitN(strings.ToLower(s), "x", 2)[0])
	if len(d) < 8 || len(d) > 15 {
		return false
	}
	labelled := rePhoneLb.MatchString(before)
	intl := strings.HasPrefix(s, "+")
	paren := strings.Contains(s, "(")
	if !(labelled || intl || paren) {
		// Bare numbers need typical grouping: 3-3-4 or similar with consistent separators.
		seps := 0
		for _, r := range s {
			if r == ' ' || r == '-' || r == '.' {
				seps++
			}
		}
		if seps < 2 || len(d) < 10 {
			return false
		}
		if strings.Contains(s, ".") && strings.Count(s, ".") >= 2 && len(d) <= 8 {
			return false
		}
	}
	// Reject date-like groupings (2024-01-31, 31.12.2024)
	if reDateLike.MatchString(strings.TrimSpace(s)) {
		return false
	}
	return true
}

// firstNames is a compact dictionary used to spot "Firstname Lastname" pairs.
var firstNames = map[string]bool{}

func init() {
	for _, n := range strings.Fields(`
James John Robert Michael William David Richard Joseph Thomas Charles Christopher Daniel Matthew Anthony Mark Donald Steven Paul Andrew Joshua Kenneth Kevin Brian George Timothy Ronald Edward Jason Jeffrey Ryan Jacob Gary Nicholas Eric Jonathan Stephen Larry Justin Scott Brandon Benjamin Samuel Gregory Alexander Frank Patrick Raymond Jack Dennis Jerry Tyler Aaron Jose Adam Nathan Henry Douglas Zachary Peter Kyle Noah Ethan Jeremy Walter Christian Keith Roger Terry Austin Sean Gerald Carl Harold Dylan Arthur Lawrence Jordan Jesse Bryan Billy Bruce Gabriel Joe Logan Alan Juan Albert Willie Elijah Wayne Randy Vincent Liam Oliver Lucas Leo Hugo Mateo Luis Carlos Miguel Diego Pablo Javier Alejandro Marco Luca Giovanni Pierre Louis Jean Hans Lars Sven Ivan Dmitri Sergei Ahmed Mohammed Muhammad Ali Omar Hassan Yusuf Ibrahim Raj Arjun Rahul Amit Vikram Wei Jun Hiroshi Kenji Takeshi Min Jin Kwame Kofi Chinedu Tunde Yosef Avi Noam Eitan
Mary Patricia Jennifer Linda Elizabeth Barbara Susan Jessica Sarah Karen Lisa Nancy Betty Margaret Sandra Ashley Kimberly Emily Donna Michelle Carol Amanda Dorothy Melissa Deborah Stephanie Rebecca Sharon Laura Cynthia Kathleen Amy Angela Shirley Anna Brenda Pamela Emma Nicole Helen Samantha Katherine Christine Debra Rachel Carolyn Janet Catherine Maria Heather Diane Ruth Julie Olivia Joyce Virginia Victoria Kelly Lauren Christina Joan Evelyn Judith Megan Andrea Cheryl Hannah Jacqueline Martha Gloria Teresa Ann Sara Madison Frances Kathryn Janice Jean Abigail Alice Judy Sophia Grace Denise Amber Doris Marilyn Danielle Beverly Isabella Theresa Diana Natalie Brittany Charlotte Marie Kayla Alexis Lori Ava Mia Chloe Zoe Lucia Sofia Valentina Camila Isabel Elena Carmen Ana Paula Giulia Chiara Claire Camille Ingrid Astrid Olga Natalia Tatiana Fatima Aisha Leila Yasmin Priya Ananya Deepa Mei Yuki Sakura Aiko Hana Ji-woo Amara Ngozi Chiamaka Noa Tamar Maya Shira Yael`) {
		firstNames[n] = true
	}
}

var reCapPair = regexp.MustCompile(`\b([A-Z][a-z]+)\s+((?:[A-Z]\.\s+)?[A-Z][a-zA-Z'\-]{1,})\b`)

func isStop(w string) bool {
	switch w {
	case "Street", "Road", "Avenue", "Lane", "Drive", "Inc", "Ltd", "Corp", "Bank", "University", "Hospital", "Hotel", "Airport", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday", "The", "And":
		return true
	}
	return false
}

func add(out *[]Finding, bs, be int, text, kind, sev, src, rname string) {
	*out = append(*out, Finding{bs: bs, be: be, Text: text[bs:be], Kind: kind, Severity: sev, Source: src, Rule: rname})
}

// Detect runs every rule over text and returns non-overlapping findings.
func Detect(text string, terms []string) []Finding {
	var c []Finding

	for _, m := range reEmail.FindAllStringIndex(text, -1) {
		s, e := m[0], m[1]
		for e > s && text[e-1] == '.' {
			e--
		}
		add(&c, s, e, text, "EMAIL", "high", "engine", "email")
	}
	for _, m := range reCard.FindAllStringIndex(text, -1) {
		if validCard(text[m[0]:m[1]]) {
			add(&c, m[0], m[1], text, "CREDIT_CARD", "critical", "engine", "card-luhn")
		}
	}
	for _, m := range reIBAN.FindAllStringIndex(text, -1) {
		if validIBAN(text[m[0]:m[1]]) {
			add(&c, m[0], m[1], text, "IBAN", "critical", "engine", "iban-mod97")
		}
	}
	for _, m := range reSSN.FindAllStringSubmatchIndex(text, -1) {
		sub := []string{text[m[0]:m[1]], text[m[2]:m[3]], text[m[4]:m[5]], text[m[6]:m[7]]}
		if validSSN(sub) {
			add(&c, m[0], m[1], text, "SSN", "critical", "engine", "us-ssn")
		}
	}
	for _, m := range reIPv4.FindAllStringIndex(text, -1) {
		// skip version strings like v1.2.3.4 and dotted runs longer than 4 parts
		if m[0] > 0 && (text[m[0]-1] == 'v' || text[m[0]-1] == '.') {
			continue
		}
		if m[1] < len(text)-1 && text[m[1]] == '.' && text[m[1]+1] >= '0' && text[m[1]+1] <= '9' {
			continue
		}
		if validIPv4(text[m[0]:m[1]]) {
			add(&c, m[0], m[1], text, "IP_ADDRESS", "medium", "engine", "ipv4")
		}
	}
	for _, m := range reIPv6.FindAllStringIndex(text, -1) {
		if validIPv6(text[m[0]:m[1]]) {
			add(&c, m[0], m[1], text, "IP_ADDRESS", "medium", "engine", "ipv6")
		}
	}
	for _, m := range reMAC.FindAllStringIndex(text, -1) {
		add(&c, m[0], m[1], text, "MAC_ADDRESS", "medium", "engine", "mac")
	}
	for _, m := range rePhone.FindAllStringIndex(text, -1) {
		s, e := m[0], m[1]
		// don't start in the middle of a longer number/word
		if s > 0 {
			p := text[s-1]
			if (p >= '0' && p <= '9') || (p >= 'A' && p <= 'Z') || (p >= 'a' && p <= 'z') || p == '/' {
				continue
			}
		}
		if e < len(text) {
			n := text[e]
			if (n >= '0' && n <= '9') || (n >= 'A' && n <= 'Z') || (n >= 'a' && n <= 'z') {
				continue
			}
		}
		lb := s - 40
		if lb < 0 {
			lb = 0
		}
		if validPhone(text[s:e], text[lb:s]) {
			add(&c, s, e, text, "PHONE", "medium", "engine", "phone")
		}
	}
	for _, r := range secretRules {
		for _, m := range r.re.FindAllStringIndex(text, -1) {
			add(&c, m[0], m[1], text, "SECRET", "critical", "engine", r.name)
		}
	}
	for _, m := range reSecretL.FindAllStringSubmatchIndex(text, -1) {
		e := m[3]
		for e > m[2] && strings.ContainsRune(".:)]}", rune(text[e-1])) {
			e--
		}
		add(&c, m[2], e, text, "SECRET", "critical", "engine", "labelled-secret")
	}
	for _, m := range reDOB.FindAllStringSubmatchIndex(text, -1) {
		add(&c, m[2], m[3], text, "DATE_OF_BIRTH", "high", "engine", "dob-label")
	}
	for _, m := range reIDLb.FindAllStringSubmatchIndex(text, -1) {
		v := text[m[2]:m[3]]
		if strings.ContainsAny(v, "0123456789") {
			add(&c, m[2], m[3], text, "ID_NUMBER", "high", "engine", "labelled-id")
		}
	}
	for _, m := range reAddr.FindAllStringIndex(text, -1) {
		add(&c, m[0], m[1], text, "ADDRESS", "high", "engine", "street-address")
	}
	for _, m := range rePostUK.FindAllStringIndex(text, -1) {
		add(&c, m[0], m[1], text, "ADDRESS", "medium", "engine", "uk-postcode")
	}
	for _, m := range reTitle.FindAllStringSubmatchIndex(text, -1) {
		add(&c, m[2], m[3], text, "PERSON", "medium", "engine", "title-name")
	}
	for _, m := range reNameLb.FindAllStringSubmatchIndex(text, -1) {
		add(&c, m[2], m[3], text, "PERSON", "medium", "engine", "labelled-name")
	}
	for pos := 0; pos < len(text); {
		loc := reCapPair.FindStringSubmatchIndex(text[pos:])
		if loc == nil {
			break
		}
		m := make([]int, len(loc))
		for i := range loc {
			m[i] = loc[i] + pos
		}
		first := text[m[2]:m[3]]
		last := text[m[4]:m[5]]
		lastWord := last
		if i := strings.LastIndex(last, " "); i >= 0 {
			lastWord = last[i+1:]
		}
		if firstNames[first] && !isStop(lastWord) {
			add(&c, m[0], m[1], text, "PERSON", "medium", "dictionary", "first-name-dictionary")
			pos = m[1]
		} else {
			pos = m[4] // retry starting at the second word
		}
	}

	// user terms: case-insensitive literal matches (ASCII case folding keeps offsets stable)
	lower := strings.ToLower(text)
	for _, t := range terms {
		t = strings.TrimSpace(t)
		if len(t) < 2 {
			continue
		}
		lt := strings.ToLower(t)
		if len(lt) != len(t) {
			continue
		}
		for i := 0; ; {
			j := strings.Index(lower[i:], lt)
			if j < 0 {
				break
			}
			s := i + j
			add(&c, s, s+len(lt), text, "CUSTOM", "high", "term", "your-term")
			i = s + len(lt)
		}
	}

	return resolve(c, text)
}

// resolve drops overlapping candidates, keeping higher severity, then longer, then earlier.
func resolve(c []Finding, text string) []Finding {
	sort.SliceStable(c, func(i, j int) bool {
		a, b := c[i], c[j]
		if sevRank[a.Severity] != sevRank[b.Severity] {
			return sevRank[a.Severity] > sevRank[b.Severity]
		}
		if a.Source == "term" && b.Source != "term" {
			return true
		}
		if (a.be - a.bs) != (b.be - b.bs) {
			return (a.be - a.bs) > (b.be - b.bs)
		}
		return a.bs < b.bs
	})
	var kept []Finding
	for _, f := range c {
		if f.be <= f.bs {
			continue
		}
		ok := true
		for _, k := range kept {
			if f.bs < k.be && k.bs < f.be {
				ok = false
				break
			}
		}
		if ok {
			kept = append(kept, f)
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].bs < kept[j].bs })
	// convert byte offsets to UTF-16 offsets
	idx := utf16Index(text)
	for i := range kept {
		kept[i].Start = idx[kept[i].bs]
		kept[i].End = idx[kept[i].be]
	}
	return kept
}

// utf16Index maps every byte offset to its UTF-16 code-unit offset.
func utf16Index(s string) []int {
	out := make([]int, len(s)+1)
	u := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		for k := 0; k < size; k++ {
			out[i+k] = u
		}
		if r >= 0x10000 {
			u += 2
		} else {
			u++
		}
		i += size
	}
	out[len(s)] = u
	return out
}
