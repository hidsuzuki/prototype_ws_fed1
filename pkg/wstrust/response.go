package wstrust

import (
	"fmt"
	"time"
)

const soapEnvelopeNS = `xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"`

func BuildWSTrust13Response(tokenXML, tokenType, appliesTo string, created, expires time.Time, trustNS string) string {
	createdStr := created.UTC().Format("2006-01-02T15:04:05Z")
	expiresStr := expires.UTC().Format("2006-01-02T15:04:05Z")

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope %s>
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue</a:Action>
    <a:RelatesTo>urn:uuid:00000000-0000-0000-0000-000000000000</a:RelatesTo>
  </s:Header>
  <s:Body>
    <trust:RequestSecurityTokenResponseCollection xmlns:trust="%s">
      <trust:RequestSecurityTokenResponse>
        <trust:Lifetime>
          <u:Created>%s</u:Created>
          <u:Expires>%s</u:Expires>
        </trust:Lifetime>
        <trust:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
          <a:EndpointReference>
            <a:Address>%s</a:Address>
          </a:EndpointReference>
        </trust:AppliesTo>
        <trust:RequestedSecurityToken>
          %s
        </trust:RequestedSecurityToken>
        <trust:TokenType>%s</trust:TokenType>
        <trust:RequestType>%s/Issue</trust:RequestType>
      </trust:RequestSecurityTokenResponse>
    </trust:RequestSecurityTokenResponseCollection>
  </s:Body>
</s:Envelope>`,
		soapEnvelopeNS,
		trustNS,
		createdStr,
		expiresStr,
		appliesTo,
		tokenXML,
		tokenType,
		trustNS,
	)
}

func BuildFaultResponse(code, reason string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope %s>
  <s:Body>
    <s:Fault>
      <s:Code>
        <s:Value>s:Sender</s:Value>
        <s:Subcode>
          <s:Value>%s</s:Value>
        </s:Subcode>
      </s:Code>
      <s:Reason>
        <s:Text xml:lang="en">%s</s:Text>
      </s:Reason>
    </s:Fault>
  </s:Body>
</s:Envelope>`,
		soapEnvelopeNS,
		code,
		reason,
	)
}
