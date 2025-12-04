use worker::*;
use crate::config::Config;

pub async fn doh(req_wireformat: &[u8]) -> Result<Vec<u8>> {
    let mut headers = Headers::new();
    headers.set("Accept", "application/dns-message")?;
    headers.set("Content-Type", "application/dns-message")?;

    let mut request = Request::new_with_init(
        "https://1.1.1.1/dns-query",
        &RequestInit {
            method: Method::Post,
            headers,
            body: Some(wasm_bindgen::JsValue::from(js_sys::Uint8Array::from(req_wireformat))),
            ..Default::default()
        },
    )?;

    let mut response = Fetch::Request(request).send().await?;

    Ok(response.bytes().await?)
}

pub async fn handle_dns_request(mut req: Request, ctx: RouteContext<Config>) -> Result<Response> {
    let body = req.bytes().await?;
    
    // Parse domain from DNS query
    if let Some((domain, qname_len)) = parse_domain_name(&body) {
        // Check KV for blocked domain
        if let Ok(kv) = ctx.kv("DNS_CUSTOM") {
            if let Ok(Some(_)) = kv.get(&domain).text().await {
                // Domain is blocked. Return NXDOMAIN (Name Error).
                // This is a standard way to say "domain does not exist".
                
                // Construct NXDOMAIN response
                // Header (12 bytes)
                // ID: Copy from request
                // Flags: 0x8183 (QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=3=NXDOMAIN)
                // QDCOUNT: 1
                // ANCOUNT: 0
                // NSCOUNT: 0
                // ARCOUNT: 0
                
                let mut response = Vec::with_capacity(12 + qname_len + 4);
                
                // ID
                response.extend_from_slice(&body[0..2]);
                // Flags (Standard Response, Recursion Desired, Recursion Available, NXDOMAIN)
                response.extend_from_slice(&[0x81, 0x83]);
                // QDCOUNT (1)
                response.extend_from_slice(&[0x00, 0x01]);
                // ANCOUNT (0)
                response.extend_from_slice(&[0x00, 0x00]);
                // NSCOUNT (0)
                response.extend_from_slice(&[0x00, 0x00]);
                // ARCOUNT (0)
                response.extend_from_slice(&[0x00, 0x00]);
                
                // Question Section (Copy from request)
                // QNAME + QTYPE + QCLASS
                let question_end = 12 + qname_len + 4;
                if question_end <= body.len() {
                    response.extend_from_slice(&body[12..question_end]);
                }
                
                let headers = Headers::new();
                headers.set("Content-Type", "application/dns-message")?;
                return Ok(Response::from_bytes(response)?.with_headers(headers));
            }
        }
    }

    let response_bytes = doh(&body).await?;
    
    let headers = Headers::new();
    headers.set("Content-Type", "application/dns-message")?;
    
    Ok(Response::from_bytes(response_bytes)?.with_headers(headers))
}

fn parse_domain_name(data: &[u8]) -> Option<(String, usize)> {
    if data.len() < 12 { return None; }
    let mut pos = 12;
    let mut domain = String::new();
    let start_pos = pos;
    
    loop {
        if pos >= data.len() { return None; }
        let len = data[pos] as usize;
        if len == 0 { 
            pos += 1; 
            break; 
        } 
        if len & 0xC0 == 0xC0 { return None; } // Compression not supported
        
        pos += 1;
        if pos + len > data.len() { return None; }
        
        if !domain.is_empty() {
            domain.push('.');
        }
        
        let label = std::str::from_utf8(&data[pos..pos+len]).ok()?;
        domain.push_str(label);
        pos += len;
    }
    
    Some((domain, pos - start_pos))
}
