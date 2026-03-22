package wstrust

import (
	"encoding/xml"
	"io"
)

type SOAPEnvelope struct {
	XMLName xml.Name   `xml:"Envelope"`
	Header  SOAPHeader `xml:"Header"`
	Body    SOAPBody   `xml:"Body"`
}

type SOAPHeader struct {
	XMLName  xml.Name        `xml:"Header"`
	Action   string          `xml:"Action"`
	Security *WSSecurity     `xml:"Security"`
}

type WSSecurity struct {
	XMLName       xml.Name      `xml:"Security"`
	UsernameToken UsernameToken `xml:"UsernameToken"`
}

type UsernameToken struct {
	XMLName  xml.Name `xml:"UsernameToken"`
	Username string   `xml:"Username"`
	Password string   `xml:"Password"`
}

type SOAPBody struct {
	XMLName xml.Name           `xml:"Body"`
	RST     *RequestSecurityToken `xml:"RequestSecurityToken"`
}

type RequestSecurityToken struct {
	XMLName     xml.Name    `xml:"RequestSecurityToken"`
	TokenType   string      `xml:"TokenType"`
	RequestType string      `xml:"RequestType"`
	AppliesTo   *AppliesTo  `xml:"AppliesTo"`
}

type AppliesTo struct {
	XMLName              xml.Name             `xml:"AppliesTo"`
	EndpointReference    EndpointReference    `xml:"EndpointReference"`
}

type EndpointReference struct {
	XMLName xml.Name `xml:"EndpointReference"`
	Address string   `xml:"Address"`
}

type ParsedRequest struct {
	Username    string
	Password    string
	TokenType   string
	RequestType string
	AppliesTo   string
	Action      string
}

func ParseSOAPRequest(body io.Reader) (*ParsedRequest, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}

	var envelope SOAPEnvelope
	if err := xml.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}

	req := &ParsedRequest{
		Action: envelope.Header.Action,
	}

	if envelope.Header.Security != nil {
		req.Username = envelope.Header.Security.UsernameToken.Username
		req.Password = envelope.Header.Security.UsernameToken.Password
	}

	if envelope.Body.RST != nil {
		req.TokenType = envelope.Body.RST.TokenType
		req.RequestType = envelope.Body.RST.RequestType
		if envelope.Body.RST.AppliesTo != nil {
			req.AppliesTo = envelope.Body.RST.AppliesTo.EndpointReference.Address
		}
	}

	if req.TokenType == "" {
		req.TokenType = "urn:oasis:names:tc:SAML:1.0:assertion"
	}
	if req.AppliesTo == "" {
		req.AppliesTo = "urn:federation:MicrosoftOnline"
	}

	return req, nil
}
