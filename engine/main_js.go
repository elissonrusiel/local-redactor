//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"
)

func main() {
	api := js.Global().Get("Object").New()
	// detect(text: string, terms: string[]) -> JSON string of findings
	api.Set("detect", js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return "[]"
		}
		var terms []string
		if len(args) > 1 && args[1].Type() == js.TypeObject {
			for i := 0; i < args[1].Length(); i++ {
				terms = append(terms, args[1].Index(i).String())
			}
		}
		out := Detect(args[0].String(), terms)
		if out == nil {
			out = []Finding{}
		}
		b, _ := json.Marshal(out)
		return string(b)
	}))
	// extract(name: string, bytes: Uint8Array) -> {text} | {error}
	api.Set("extract", js.FuncOf(func(this js.Value, args []js.Value) any {
		res := js.Global().Get("Object").New()
		if len(args) < 2 {
			res.Set("error", "missing arguments")
			return res
		}
		buf := make([]byte, args[1].Get("length").Int())
		js.CopyBytesToGo(buf, args[1])
		text, err := Extract(args[0].String(), buf)
		if err != nil {
			res.Set("error", err.Error())
		} else {
			res.Set("text", text)
		}
		return res
	}))
	api.Set("version", "rules-1.0")
	js.Global().Set("piiweb", api)
	if cb := js.Global().Get("piiwebReady"); cb.Type() == js.TypeFunction {
		cb.Invoke()
	}
	select {}
}
