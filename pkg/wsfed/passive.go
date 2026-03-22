package wsfed

import (
	"fmt"
	"net/url"
	"time"
)

type PassiveRequest struct {
	WAAction  string
	WTREALM   string
	WREPLY    string
	WCTX      string
	WFRESH    string
	WHR       string
}

func ParsePassiveRequest(params url.Values) *PassiveRequest {
	return &PassiveRequest{
		WAAction: params.Get("wa"),
		WTREALM:  params.Get("wtrealm"),
		WREPLY:   params.Get("wreply"),
		WCTX:     params.Get("wctx"),
		WFRESH:   params.Get("wfresh"),
		WHR:      params.Get("whr"),
	}
}

func BuildPassiveSignInResponse(tokenXML, wctx, wreply string, created, expires time.Time) string {
	createdStr := created.UTC().Format("2006-01-02T15:04:05Z")
	expiresStr := expires.UTC().Format("2006-01-02T15:04:05Z")

	wresult := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">
  <t:Lifetime>
    <wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%s</wsu:Created>
    <wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%s</wsu:Expires>
  </t:Lifetime>
  <t:RequestedSecurityToken>
    %s
  </t:RequestedSecurityToken>
  <t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType>
  <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
</t:RequestSecurityTokenResponse>`,
		createdStr, expiresStr, tokenXML,
	)

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Working...</title></head>
<body>
<form method="POST" action="%s" id="hiddenform">
  <input type="hidden" name="wa" value="wsignin1.0"/>
  <input type="hidden" name="wresult" value="%s"/>
  <input type="hidden" name="wctx" value="%s"/>
  <noscript>
    <p>Script is disabled. Click Submit to continue.</p>
    <input type="submit" value="Submit"/>
  </noscript>
</form>
<script language="javascript">window.setTimeout('document.forms[0].submit()', 0);</script>
</body>
</html>`,
		wreply,
		htmlEscape(wresult),
		htmlEscape(wctx),
	)
}

func htmlEscape(s string) string {
	result := ""
	for _, c := range s {
		switch c {
		case '&':
			result += "&amp;"
		case '<':
			result += "&lt;"
		case '>':
			result += "&gt;"
		case '"':
			result += "&quot;"
		case '\'':
			result += "&#39;"
		default:
			result += string(c)
		}
	}
	return result
}
