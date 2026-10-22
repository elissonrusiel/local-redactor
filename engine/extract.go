package main

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
)

func readZipFile(z *zip.Reader, name string) ([]byte, bool) {
	for _, f := range z.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				return nil, false
			}
			defer rc.Close()
			b, err := io.ReadAll(io.LimitReader(rc, 200<<20))
			return b, err == nil
		}
	}
	return nil, false
}

// Extract returns plain text for .docx and .xlsx files.
func Extract(name string, data []byte) (string, error) {
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("not a valid Office file")
	}
	switch strings.ToLower(path.Ext(name)) {
	case ".docx":
		return docxText(z)
	case ".xlsx":
		return xlsxText(z)
	}
	return "", fmt.Errorf("unsupported file type")
}

func docxText(z *zip.Reader) (string, error) {
	var parts []string
	var names []string
	for _, f := range z.File {
		n := f.Name
		if n == "word/document.xml" || (strings.HasPrefix(n, "word/header") || strings.HasPrefix(n, "word/footer")) && strings.HasSuffix(n, ".xml") {
			names = append(names, n)
		}
	}
	sort.SliceStable(names, func(i, j int) bool { return names[i] == "word/document.xml" })
	for _, n := range names {
		b, ok := readZipFile(z, n)
		if !ok {
			continue
		}
		t := wordXML(b)
		if strings.TrimSpace(t) != "" {
			parts = append(parts, strings.TrimRight(t, "\n"))
		}
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("no text found in document")
	}
	return strings.Join(parts, "\n\n"), nil
}

func wordXML(b []byte) string {
	d := xml.NewDecoder(bytes.NewReader(b))
	var sb strings.Builder
	inT := false
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "t":
				inT = true
			case "tab":
				sb.WriteByte('\t')
			case "br", "cr":
				sb.WriteByte('\n')
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "t":
				inT = false
			case "p":
				sb.WriteByte('\n')
			case "tc":
				sb.WriteByte('\t')
			}
		case xml.CharData:
			if inT {
				sb.Write(t)
			}
		}
	}
	return sb.String()
}

func xlsxText(z *zip.Reader) (string, error) {
	var shared []string
	if b, ok := readZipFile(z, "xl/sharedStrings.xml"); ok {
		d := xml.NewDecoder(bytes.NewReader(b))
		var cur strings.Builder
		inSI, inT := false, false
		for {
			tok, err := d.Token()
			if err != nil {
				break
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if t.Name.Local == "si" {
					inSI = true
					cur.Reset()
				} else if t.Name.Local == "t" && inSI {
					inT = true
				}
			case xml.EndElement:
				if t.Name.Local == "si" {
					inSI = false
					shared = append(shared, cur.String())
				} else if t.Name.Local == "t" {
					inT = false
				}
			case xml.CharData:
				if inT {
					cur.Write(t)
				}
			}
		}
	}
	var sheets []string
	for _, f := range z.File {
		if strings.HasPrefix(f.Name, "xl/worksheets/sheet") && strings.HasSuffix(f.Name, ".xml") {
			sheets = append(sheets, f.Name)
		}
	}
	sort.Slice(sheets, func(i, j int) bool {
		ni, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(sheets[i], "xl/worksheets/sheet"), ".xml"))
		nj, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(sheets[j], "xl/worksheets/sheet"), ".xml"))
		return ni < nj
	})
	var out strings.Builder
	for si, n := range sheets {
		b, ok := readZipFile(z, n)
		if !ok {
			continue
		}
		if si > 0 {
			out.WriteString("\n")
		}
		fmt.Fprintf(&out, "Sheet %d\n", si+1)
		d := xml.NewDecoder(bytes.NewReader(b))
		var row []string
		var cellType string
		var val strings.Builder
		inV, inCell := false, false
		for {
			tok, err := d.Token()
			if err != nil {
				break
			}
			switch t := tok.(type) {
			case xml.StartElement:
				switch t.Name.Local {
				case "row":
					row = row[:0]
				case "c":
					inCell = true
					cellType = ""
					val.Reset()
					for _, a := range t.Attr {
						if a.Name.Local == "t" {
							cellType = a.Value
						}
					}
				case "v", "t":
					if inCell {
						inV = true
					}
				}
			case xml.EndElement:
				switch t.Name.Local {
				case "v", "t":
					inV = false
				case "c":
					inCell = false
					v := val.String()
					if cellType == "s" {
						if i, err := strconv.Atoi(v); err == nil && i >= 0 && i < len(shared) {
							v = shared[i]
						}
					}
					row = append(row, v)
				case "row":
					out.WriteString(strings.Join(row, "\t"))
					out.WriteByte('\n')
				}
			case xml.CharData:
				if inV {
					val.Write(t)
				}
			}
		}
	}
	if out.Len() == 0 {
		return "", fmt.Errorf("no cells found in workbook")
	}
	return out.String(), nil
}
