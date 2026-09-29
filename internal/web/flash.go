package web

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// Feedback after a POST takes the detour through a one-shot cookie instead of the query
// string. Two reasons: the address bar stays clean (a bookmarked or shared URL does not
// carry "Weiterleitung ist aktiv." with it forever), and above all the message survives
// exactly one render - reloading the page to see fresh numbers must not repeat an
// announcement that has long stopped being news. The redirect after POST stays, it is
// what keeps a reload from re-submitting the form.
const (
	flashCookieName = "sgw_flash"
	// Long enough to survive the redirect even on a slow link, short enough that a
	// message can never reappear next to an unrelated later visit.
	flashMaxAge = 30
	// Error texts come from validation and are short; the cap only keeps a broken
	// caller from producing a cookie the browser would silently drop.
	flashMaxLen = 512
)

// setFlash stores one message for the next rendering of the page. errMsg wins over msg -
// a caller that has both had something fail.
func setFlash(w http.ResponseWriter, msg, errMsg string) {
	kind, text := "ok", msg
	if errMsg != "" {
		kind, text = "err", errMsg
	}
	text = sanitizeFlash(text)
	if text == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:  flashCookieName,
		Value: kind + "." + base64.RawURLEncoding.EncodeToString([]byte(text)),
		Path:  "/",
		// No Secure flag: the gateway is reached over plain HTTP in the LAN, and a
		// cookie the browser refuses to send would swallow every message.
		MaxAge:   flashMaxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// takeFlash reads the message and clears it in the same response, so it is gone whatever
// the user does next.
func takeFlash(w http.ResponseWriter, r *http.Request) (msg, errMsg string) {
	c, err := r.Cookie(flashCookieName)
	if err != nil || c.Value == "" {
		return "", ""
	}
	clearFlash(w)
	kind, enc, ok := strings.Cut(c.Value, ".")
	if !ok {
		return "", ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return "", ""
	}
	// The cookie is ours, but the browser hands back whatever it was given; treat the
	// content as input. html/template escapes it, sanitizeFlash keeps control characters
	// out of the layout.
	text := sanitizeFlash(string(raw))
	if text == "" {
		return "", ""
	}
	if kind == "err" {
		return "", text
	}
	return text, ""
}

func clearFlash(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func sanitizeFlash(s string) string {
	if len(s) > flashMaxLen {
		s = s[:flashMaxLen]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.TrimSpace(s))
}
