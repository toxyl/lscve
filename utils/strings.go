package utils

import (
	"fmt"
	"strings"

	"github.com/toxyl/glog"
)

func WordWrap(str string, maxLineLength int, linePad string) string {
	words := strings.Split(str, " ")
	res := ""
	lineLen := 0
	for _, w := range words {
		l := len(glog.StripANSI(w))
		lineLen += l
		if lineLen > maxLineLength {
			lineLen = l
			res += "\n" + linePad
		}
		res += w + " "
		lineLen++
	}
	return res
}

func GetSeverity(cvss float64) string {
	if cvss >= 9.0 {
		return glog.WrapRed("CRITICAL")
	}
	if cvss >= 7.0 {
		return glog.WrapOrange("high")
	}
	if cvss >= 4.0 {
		return glog.WrapYellow("medium")
	}
	if cvss >= 0.1 {
		return glog.WrapGreen("low")
	}
	return "none"
}

func ColorSeverity(cvss float64) string {
	v := fmt.Sprintf("%.1f", cvss)
	if cvss >= 9.0 {
		return glog.WrapRed(v)
	}
	if cvss >= 7.0 {
		return glog.WrapOrange(v)
	}
	if cvss >= 4.0 {
		return glog.WrapYellow(v)
	}
	if cvss >= 0.1 {
		return glog.WrapGreen(v)
	}
	return v
}

func ColorEPSS(cvss float64) string {
	v := fmt.Sprintf("%.2f", cvss)
	if cvss >= 0.90 {
		return glog.WrapRed(v)
	}
	if cvss >= 0.70 {
		return glog.WrapOrange(v)
	}
	if cvss >= 0.40 {
		return glog.WrapYellow(v)
	}
	if cvss >= 0.01 {
		return glog.WrapGreen(v)
	}
	return v
}

func AutoColorList(str, sep string) string {
	parts := strings.Split(str, sep)
	for i, p := range parts {
		parts[i] = glog.Auto(p)
	}
	return strings.Join(parts, sep)
}
